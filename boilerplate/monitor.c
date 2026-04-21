/*
 * monitor.c - Multi-Container Memory Monitor (Linux Kernel Module)
 *
 * Implements TODOs 1-6:
 *   1. monitored_entry struct  (linked list node)
 *   2. global list + mutex
 *   3. timer callback          (periodic RSS check)
 *   4. ioctl REGISTER          (add entry)
 *   5. ioctl UNREGISTER        (remove entry)
 *   6. module_exit cleanup     (free all entries)
 *
 * Lock choice: mutex (not spinlock).
 * Rationale: the timer callback calls get_rss_bytes() which takes
 * rcu_read_lock() and get_task_mm() — both are sleepable contexts.
 * A spinlock cannot be held across sleepable calls; mutex is correct.
 * The ioctl path also runs in process context (not hard IRQ), so
 * mutex is safe there too.
 */

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "monitor_ioctl.h"

#define DEVICE_NAME        "container_monitor"
#define CHECK_INTERVAL_SEC 1

/* ==============================================================
 * TODO 1: linked-list node struct
 *
 * Fields:
 *   list           – kernel list_head for embedding in a list
 *   pid            – host PID of the container's init process
 *   container_id   – human-readable name (from ioctl request)
 *   soft_limit     – RSS threshold for a warning log (bytes)
 *   hard_limit     – RSS threshold for SIGKILL (bytes)
 *   soft_warned    – flag: 1 after the first soft-limit warning
 *                    so we don't spam dmesg on every tick
 * ============================================================== */
struct monitored_entry {
    struct list_head list;
    pid_t            pid;
    char             container_id[MONITOR_NAME_LEN];
    unsigned long    soft_limit;
    unsigned long    hard_limit;
    int              soft_warned;
};

/* ==============================================================
 * TODO 2: global monitored list and protecting mutex
 *
 * monitored_list  – doubly-linked list head (always valid)
 * monitor_mutex   – serialises insert / remove / iteration
 *
 * Why mutex over spinlock:
 *   The timer callback calls get_rss_bytes() which internally
 *   calls get_task_mm() → mmget() which may sleep.  A spinlock
 *   cannot be held across a sleep; mutex is the right primitive.
 *   Both ioctl and timer run in process/softirq context where
 *   sleeping is allowed, so mutex is correct on all paths.
 * ============================================================== */
static LIST_HEAD(monitored_list);
static DEFINE_MUTEX(monitor_mutex);

/* --- Provided: internal device / timer state --- */
static struct timer_list monitor_timer;
static dev_t              dev_num;
static struct cdev        c_dev;
static struct class      *cl;

/* ---------------------------------------------------------------
 * Provided: RSS helper
 * Returns RSS in bytes, or -1 if the task no longer exists.
 * --------------------------------------------------------------- */
static long get_rss_bytes(pid_t pid)
{
    struct task_struct *task;
    struct mm_struct   *mm;
    struct pid         *pid_struct;
    long rss_pages = 0;

    rcu_read_lock();
    /*
     * find_get_pid() looks up by the global (init namespace) PID number,
     * which is what the supervisor passes us as host_pid.
     * find_vpid() would look up relative to the current namespace and
     * would fail to find container processes from inside the module.
     */
    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        rcu_read_unlock();
        return -1;
    }
    task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        put_pid(pid_struct);
        rcu_read_unlock();
        return -1;
    }
    get_task_struct(task);
    put_pid(pid_struct);
    rcu_read_unlock();

    mm = get_task_mm(task);
    if (mm) {
        rss_pages = get_mm_rss(mm);
        mmput(mm);
    }
    put_task_struct(task);

    return rss_pages * PAGE_SIZE;
}

/* ---------------------------------------------------------------
 * Provided: soft-limit warning helper
 * --------------------------------------------------------------- */
static void log_soft_limit_event(const char *container_id,
                                  pid_t pid,
                                  unsigned long limit_bytes,
                                  long rss_bytes)
{
    printk(KERN_WARNING
           "[container_monitor] SOFT LIMIT container=%s pid=%d"
           " rss=%ld limit=%lu\n",
           container_id, pid, rss_bytes, limit_bytes);
}

/* ---------------------------------------------------------------
 * Provided: hard-limit kill helper
 * --------------------------------------------------------------- */
static void kill_process(const char *container_id,
                          pid_t pid,
                          unsigned long limit_bytes,
                          long rss_bytes)
{
    struct task_struct *task;

    rcu_read_lock();
    {
        struct pid *pid_struct = find_get_pid(pid);
        if (pid_struct) {
            task = pid_task(pid_struct, PIDTYPE_PID);
            if (task)
                send_sig(SIGKILL, task, 1);
            put_pid(pid_struct);
        }
    }
    rcu_read_unlock();

    printk(KERN_WARNING
           "[container_monitor] HARD LIMIT container=%s pid=%d"
           " rss=%ld limit=%lu — sent SIGKILL\n",
           container_id, pid, rss_bytes, limit_bytes);
}

/* ---------------------------------------------------------------
 * TODO 3: timer_callback — fires every CHECK_INTERVAL_SEC seconds
 *
 * Algorithm:
 *   For each entry in monitored_list:
 *     a) Call get_rss_bytes(pid).
 *        If -1 the process is gone → remove and free the entry.
 *     b) If RSS ≥ hard_limit → kill, remove, free.
 *     c) If RSS ≥ soft_limit AND not yet warned → warn, set flag.
 *
 * Use list_for_each_entry_safe so we can delete inside the loop
 * without corrupting the iterator (safe variant saves next pointer
 * before the body runs).
 * --------------------------------------------------------------- */
static void timer_callback(struct timer_list *t)
{
    struct monitored_entry *entry, *tmp;
    long rss;

    (void)t;

    mutex_lock(&monitor_mutex);

    list_for_each_entry_safe(entry, tmp, &monitored_list, list) {

        rss = get_rss_bytes(entry->pid);

        /* (a) process no longer exists – clean up stale entry */
        if (rss < 0) {
            printk(KERN_INFO
                   "[container_monitor] container=%s pid=%d exited,"
                   " removing from list\n",
                   entry->container_id, entry->pid);
            list_del(&entry->list);
            kfree(entry);
            continue;
        }

        /* (b) hard limit exceeded → SIGKILL + remove */
        if ((unsigned long)rss >= entry->hard_limit) {
            kill_process(entry->container_id, entry->pid,
                         entry->hard_limit, rss);
            list_del(&entry->list);
            kfree(entry);
            continue;
        }

        /* (c) soft limit exceeded → warn once */
        if ((unsigned long)rss >= entry->soft_limit &&
            !entry->soft_warned) {
            log_soft_limit_event(entry->container_id, entry->pid,
                                 entry->soft_limit, rss);
            entry->soft_warned = 1;
        }
    }

    mutex_unlock(&monitor_mutex);

    /* re-arm the timer */
    mod_timer(&monitor_timer, jiffies + CHECK_INTERVAL_SEC * HZ);
}

/* ---------------------------------------------------------------
 * IOCTL handler
 * --------------------------------------------------------------- */
static long monitor_ioctl(struct file *f, unsigned int cmd,
                           unsigned long arg)
{
    struct monitor_request req;

    (void)f;

    if (cmd != MONITOR_REGISTER && cmd != MONITOR_UNREGISTER)
        return -EINVAL;

    if (copy_from_user(&req,
                       (struct monitor_request __user *)arg,
                       sizeof(req)))
        return -EFAULT;

    /* ----------------------------------------------------------------
     * TODO 4: MONITOR_REGISTER – allocate and insert a new entry
     *
     * Steps:
     *   1. Validate: soft_limit must be ≤ hard_limit.
     *   2. kmalloc a new monitored_entry (GFP_KERNEL).
     *   3. Populate all fields from req; zero soft_warned.
     *   4. Lock → list_add_tail → unlock.
     * ---------------------------------------------------------------- */
    if (cmd == MONITOR_REGISTER) {
        struct monitored_entry *entry;

        printk(KERN_INFO
               "[container_monitor] Registering container=%s pid=%d"
               " soft=%lu hard=%lu\n",
               req.container_id, req.pid,
               req.soft_limit_bytes, req.hard_limit_bytes);

        /* 1 – sanity check limits */
        if (req.soft_limit_bytes > req.hard_limit_bytes) {
            printk(KERN_WARNING
                   "[container_monitor] Register rejected: soft > hard"
                   " for container=%s\n", req.container_id);
            return -EINVAL;
        }

        /* 2 – allocate node */
        entry = kmalloc(sizeof(*entry), GFP_KERNEL);
        if (!entry)
            return -ENOMEM;

        /* 3 – populate */
        INIT_LIST_HEAD(&entry->list);
        entry->pid         = req.pid;
        entry->soft_limit  = req.soft_limit_bytes;
        entry->hard_limit  = req.hard_limit_bytes;
        entry->soft_warned = 0;
        strncpy(entry->container_id, req.container_id,
                MONITOR_NAME_LEN - 1);
        entry->container_id[MONITOR_NAME_LEN - 1] = '\0';

        /* 4 – insert under lock */
        mutex_lock(&monitor_mutex);
        list_add_tail(&entry->list, &monitored_list);
        mutex_unlock(&monitor_mutex);

        return 0;
    }

    /* ----------------------------------------------------------------
     * TODO 5: MONITOR_UNREGISTER – find and remove a matching entry
     *
     * Match on pid (and optionally container_id for extra safety).
     * Use list_for_each_entry_safe so deletion is safe mid-iteration.
     * Return -ENOENT if no matching entry was found.
     * ---------------------------------------------------------------- */
    printk(KERN_INFO
           "[container_monitor] Unregister request container=%s pid=%d\n",
           req.container_id, req.pid);

    {
        struct monitored_entry *entry, *tmp;
        int found = 0;

        mutex_lock(&monitor_mutex);
        list_for_each_entry_safe(entry, tmp, &monitored_list, list) {
            if (entry->pid == req.pid) {
                list_del(&entry->list);
                kfree(entry);
                found = 1;
                break;   /* PIDs are unique in our list */
            }
        }
        mutex_unlock(&monitor_mutex);

        if (!found) {
            printk(KERN_INFO
                   "[container_monitor] Unregister: pid=%d not found\n",
                   req.pid);
            return -ENOENT;
        }

        printk(KERN_INFO
               "[container_monitor] Unregistered container=%s pid=%d\n",
               req.container_id, req.pid);
        return 0;
    }
}

/* --- Provided: file operations --- */
static struct file_operations fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = monitor_ioctl,
};

/* --- Provided: Module Init --- */
static int __init monitor_init(void)
{
    if (alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME) < 0)
        return -1;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    cl = class_create(DEVICE_NAME);
#else
    cl = class_create(THIS_MODULE, DEVICE_NAME);
#endif
    if (IS_ERR(cl)) {
        unregister_chrdev_region(dev_num, 1);
        return PTR_ERR(cl);
    }

    if (IS_ERR(device_create(cl, NULL, dev_num, NULL, DEVICE_NAME))) {
        class_destroy(cl);
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    cdev_init(&c_dev, &fops);
    if (cdev_add(&c_dev, dev_num, 1) < 0) {
        device_destroy(cl, dev_num);
        class_destroy(cl);
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    /* initialise list (macro already did this, but be explicit) */
    INIT_LIST_HEAD(&monitored_list);

    timer_setup(&monitor_timer, timer_callback, 0);
    mod_timer(&monitor_timer, jiffies + CHECK_INTERVAL_SEC * HZ);

    printk(KERN_INFO
           "[container_monitor] Module loaded. Device: /dev/%s\n",
           DEVICE_NAME);
    return 0;
}

/* --- Provided: Module Exit --- */
static void __exit monitor_exit(void)
{
    struct monitored_entry *entry, *tmp;

    /* stop timer before touching the list */
    del_timer_sync(&monitor_timer);

    /* ----------------------------------------------------------------
     * TODO 6: Free all remaining monitored entries on module unload.
     *
     * We hold the mutex while draining the list so any in-flight
     * timer callback (which del_timer_sync already waited for)
     * doesn't race with us.  list_for_each_entry_safe lets us
     * kfree() each node safely during iteration.
     * ---------------------------------------------------------------- */
    mutex_lock(&monitor_mutex);
    list_for_each_entry_safe(entry, tmp, &monitored_list, list) {
        printk(KERN_INFO
               "[container_monitor] cleanup: freeing container=%s pid=%d\n",
               entry->container_id, entry->pid);
        list_del(&entry->list);
        kfree(entry);
    }
    mutex_unlock(&monitor_mutex);

    cdev_del(&c_dev);
    device_destroy(cl, dev_num);
    class_destroy(cl);
    unregister_chrdev_region(dev_num, 1);

    printk(KERN_INFO "[container_monitor] Module unloaded.\n");
}

module_init(monitor_init);
module_exit(monitor_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Supervised multi-container memory monitor");

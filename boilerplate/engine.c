/*
 * engine.c – Supervised Multi-Container Runtime (User Space)
 *
 * Task 1  : Multi-container supervisor with namespace isolation  [DONE]
 * Task 2  : CLI + UNIX-socket control plane                      [DONE]
 * Task 3  : Bounded-buffer logging pipeline                      [DONE]
 * Task 4  : Kernel monitor integration (ioctl)                   [DONE]
 * Task 5  : Scheduling experiments                               [supported]
 * Task 6  : Resource cleanup                                     [DONE]
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -o engine engine.c -lpthread
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "monitor_ioctl.h"

/* ================================================================
 * Constants
 * ================================================================ */
#define STACK_SIZE          (1024 * 1024)
#define CONTAINER_ID_LEN    32
#define CONTROL_PATH        "/tmp/mini_runtime.sock"
#define LOG_DIR             "logs"
#define CONTROL_MESSAGE_LEN 512
#define CHILD_COMMAND_LEN   256
#define LOG_CHUNK_SIZE      4096
#define LOG_BUFFER_CAPACITY 64
#define DEFAULT_SOFT_LIMIT  (40UL << 20)
#define DEFAULT_HARD_LIMIT  (64UL << 20)
#define MONITOR_DEV         "/dev/container_monitor"

/* ================================================================
 * Enumerations
 * ================================================================ */
typedef enum {
    CMD_SUPERVISOR = 0,
    CMD_START,
    CMD_RUN,
    CMD_PS,
    CMD_LOGS,
    CMD_STOP
} command_kind_t;

typedef enum {
    CONTAINER_STARTING = 0,
    CONTAINER_RUNNING,
    CONTAINER_STOPPED,
    CONTAINER_KILLED,
    CONTAINER_EXITED
} container_state_t;

typedef enum {
    EXIT_REASON_UNKNOWN = 0,
    EXIT_REASON_NORMAL,
    EXIT_REASON_STOPPED,
    EXIT_REASON_HARD_LIMIT_KILLED
} exit_reason_t;

/* ================================================================
 * Data structures
 * ================================================================ */

typedef struct container_record {
    char               id[CONTAINER_ID_LEN];
    pid_t              host_pid;
    time_t             started_at;
    container_state_t  state;
    unsigned long      soft_limit_bytes;
    unsigned long      hard_limit_bytes;
    int                exit_code;
    int                exit_signal;
    int                stop_requested;
    exit_reason_t      exit_reason;
    char               log_path[PATH_MAX];
    int                pipe_read_fd;
    pthread_t          producer_thread;
    int                producer_running;
    struct container_record *next;
} container_record_t;

typedef struct {
    char   container_id[CONTAINER_ID_LEN];
    size_t length;
    char   data[LOG_CHUNK_SIZE];
} log_item_t;

typedef struct {
    log_item_t      items[LOG_BUFFER_CAPACITY];
    size_t          head;
    size_t          tail;
    size_t          count;
    int             shutting_down;
    pthread_mutex_t mutex;
    pthread_cond_t  not_empty;
    pthread_cond_t  not_full;
} bounded_buffer_t;

typedef struct {
    command_kind_t kind;
    char           container_id[CONTAINER_ID_LEN];
    char           rootfs[PATH_MAX];
    char           command[CHILD_COMMAND_LEN];
    unsigned long  soft_limit_bytes;
    unsigned long  hard_limit_bytes;
    int            nice_value;
} control_request_t;

typedef struct {
    int  status;
    int  exit_code;
    char message[CONTROL_MESSAGE_LEN];
} control_response_t;

typedef struct {
    char  id[CONTAINER_ID_LEN];
    char  rootfs[PATH_MAX];
    char  command[CHILD_COMMAND_LEN];
    int   nice_value;
    int   pipe_write_fd;
} child_config_t;

typedef struct {
    bounded_buffer_t   *buffer;
    container_record_t *record;
    pthread_mutex_t    *metadata_lock;
} producer_arg_t;

typedef struct {
    int               server_fd;
    int               monitor_fd;
    volatile int      should_stop;
    pthread_t         consumer_thread;
    bounded_buffer_t  log_buffer;
    pthread_mutex_t   metadata_lock;
    container_record_t *containers;
} supervisor_ctx_t;

/* ================================================================
 * Global supervisor pointer (needed by signal handlers)
 * ================================================================ */
static supervisor_ctx_t *g_ctx = NULL;

/* ================================================================
 * String helpers
 * ================================================================ */
static const char *state_to_string(container_state_t s)
{
    switch (s) {
    case CONTAINER_STARTING: return "starting";
    case CONTAINER_RUNNING:  return "running";
    case CONTAINER_STOPPED:  return "stopped";
    case CONTAINER_KILLED:   return "killed";
    case CONTAINER_EXITED:   return "exited";
    default:                 return "unknown";
    }
}

static const char *exit_reason_to_string(exit_reason_t r)
{
    switch (r) {
    case EXIT_REASON_NORMAL:            return "normal";
    case EXIT_REASON_STOPPED:           return "stopped";
    case EXIT_REASON_HARD_LIMIT_KILLED: return "hard_limit_killed";
    default:                            return "unknown";
    }
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s supervisor <base-rootfs>\n"
            "  %s start <id> <container-rootfs> <command>"
                " [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s run   <id> <container-rootfs> <command>"
                " [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s ps\n"
            "  %s logs <id>\n"
            "  %s stop <id>\n",
            prog, prog, prog, prog, prog, prog);
}

/* ================================================================
 * Flag parsing
 * ================================================================ */
static int parse_mib_flag(const char *flag, const char *value,
                           unsigned long *target)
{
    char *end = NULL;
    unsigned long mib;
    errno = 0;
    mib = strtoul(value, &end, 10);
    if (errno || end == value || *end != '\0') {
        fprintf(stderr, "Invalid value for %s: %s\n", flag, value);
        return -1;
    }
    if (mib > ULONG_MAX / (1UL << 20)) {
        fprintf(stderr, "Value for %s too large\n", flag);
        return -1;
    }
    *target = mib * (1UL << 20);
    return 0;
}

static int parse_optional_flags(control_request_t *req,
                                  int argc, char *argv[], int start)
{
    int i;
    for (i = start; i < argc; i += 2) {
        char *end = NULL; long nv;
        if (i + 1 >= argc) {
            fprintf(stderr, "Missing value for %s\n", argv[i]); return -1;
        }
        if (strcmp(argv[i], "--soft-mib") == 0) {
            if (parse_mib_flag("--soft-mib", argv[i+1],
                               &req->soft_limit_bytes)) return -1;
            continue;
        }
        if (strcmp(argv[i], "--hard-mib") == 0) {
            if (parse_mib_flag("--hard-mib", argv[i+1],
                               &req->hard_limit_bytes)) return -1;
            continue;
        }
        if (strcmp(argv[i], "--nice") == 0) {
            errno = 0;
            nv = strtol(argv[i+1], &end, 10);
            if (errno || end == argv[i+1] || *end || nv < -20 || nv > 19) {
                fprintf(stderr, "Invalid --nice value: %s\n", argv[i+1]);
                return -1;
            }
            req->nice_value = (int)nv;
            continue;
        }
        fprintf(stderr, "Unknown option: %s\n", argv[i]);
        return -1;
    }
    if (req->soft_limit_bytes > req->hard_limit_bytes) {
        fprintf(stderr, "soft limit cannot exceed hard limit\n"); return -1;
    }
    return 0;
}

/* ================================================================
 * Bounded buffer (Task 3)
 *
 * Design:
 *   Circular ring-buffer, capacity LOG_BUFFER_CAPACITY.
 *   mutex   – protects head/tail/count/shutting_down
 *   not_full  – producers wait here when buffer is full
 *   not_empty – consumer waits here when buffer is empty
 *
 * Race conditions without synchronisation:
 *   - Two producers could write to the same tail slot.
 *   - Consumer could read a partially written item.
 *   - count could be read/written non-atomically.
 *
 * Deadlock avoidance:
 *   shutting_down is broadcast to both CVs so all waiters
 *   wake up and exit rather than blocking forever.
 * ================================================================ */
static int bounded_buffer_init(bounded_buffer_t *b)
{
    int rc;
    memset(b, 0, sizeof(*b));
    if ((rc = pthread_mutex_init(&b->mutex, NULL))) return rc;
    if ((rc = pthread_cond_init(&b->not_empty, NULL))) {
        pthread_mutex_destroy(&b->mutex); return rc;
    }
    if ((rc = pthread_cond_init(&b->not_full, NULL))) {
        pthread_cond_destroy(&b->not_empty);
        pthread_mutex_destroy(&b->mutex); return rc;
    }
    return 0;
}

static void bounded_buffer_destroy(bounded_buffer_t *b)
{
    pthread_cond_destroy(&b->not_full);
    pthread_cond_destroy(&b->not_empty);
    pthread_mutex_destroy(&b->mutex);
}

static void bounded_buffer_begin_shutdown(bounded_buffer_t *b)
{
    pthread_mutex_lock(&b->mutex);
    b->shutting_down = 1;
    pthread_cond_broadcast(&b->not_empty);
    pthread_cond_broadcast(&b->not_full);
    pthread_mutex_unlock(&b->mutex);
}

int bounded_buffer_push(bounded_buffer_t *b, const log_item_t *item)
{
    pthread_mutex_lock(&b->mutex);
    while (b->count == LOG_BUFFER_CAPACITY && !b->shutting_down)
        pthread_cond_wait(&b->not_full, &b->mutex);
    if (b->shutting_down) {
        pthread_mutex_unlock(&b->mutex);
        return -1;
    }
    b->items[b->tail] = *item;
    b->tail = (b->tail + 1) % LOG_BUFFER_CAPACITY;
    b->count++;
    pthread_cond_signal(&b->not_empty);
    pthread_mutex_unlock(&b->mutex);
    return 0;
}

int bounded_buffer_pop(bounded_buffer_t *b, log_item_t *item)
{
    pthread_mutex_lock(&b->mutex);
    while (b->count == 0 && !b->shutting_down)
        pthread_cond_wait(&b->not_empty, &b->mutex);
    if (b->count == 0) {          /* shutting down AND empty – we're done */
        pthread_mutex_unlock(&b->mutex);
        return -1;
    }
    *item = b->items[b->head];
    b->head = (b->head + 1) % LOG_BUFFER_CAPACITY;
    b->count--;
    pthread_cond_signal(&b->not_full);
    pthread_mutex_unlock(&b->mutex);
    return 0;
}

/* ================================================================
 * Logging consumer thread (Task 3)
 * Drains buffer → per-container log files.
 * Exits only after shutdown is signalled AND buffer is empty.
 * ================================================================ */
void *logging_thread(void *arg)
{
    supervisor_ctx_t *ctx = (supervisor_ctx_t *)arg;
    log_item_t item;

    while (bounded_buffer_pop(&ctx->log_buffer, &item) == 0) {
        container_record_t *rec;
        int log_fd;

        pthread_mutex_lock(&ctx->metadata_lock);
        for (rec = ctx->containers; rec; rec = rec->next)
            if (strcmp(rec->id, item.container_id) == 0) break;
        if (rec) {
            char path[PATH_MAX];
            strncpy(path, rec->log_path, PATH_MAX - 1);
            pthread_mutex_unlock(&ctx->metadata_lock);
            log_fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (log_fd >= 0) {
                ssize_t w = write(log_fd, item.data, item.length);
                (void)w;
                close(log_fd);
            }
        } else {
            pthread_mutex_unlock(&ctx->metadata_lock);
        }
    }
    return NULL;
}

/* ================================================================
 * Producer thread – reads container pipe, pushes to buffer (Task 3)
 * ================================================================ */
static void *producer_thread_fn(void *arg)
{
    producer_arg_t     *parg   = (producer_arg_t *)arg;
    bounded_buffer_t   *buf    = parg->buffer;
    container_record_t *rec    = parg->record;
    pthread_mutex_t    *lock   = parg->metadata_lock;
    int                 rfd    = rec->pipe_read_fd;
    log_item_t          item;
    ssize_t             n;

    memset(&item, 0, sizeof(item));
    strncpy(item.container_id, rec->id, CONTAINER_ID_LEN - 1);

    while ((n = read(rfd, item.data, LOG_CHUNK_SIZE)) > 0) {
        item.length = (size_t)n;
        bounded_buffer_push(buf, &item);
        memset(item.data, 0, (size_t)n);
    }

    close(rfd);

    pthread_mutex_lock(lock);
    rec->pipe_read_fd     = -1;
    rec->producer_running = 0;
    pthread_mutex_unlock(lock);

    free(parg);
    return NULL;
}

/* ================================================================
 * Task 1: child_fn
 *
 * Runs inside the cloned child process.
 *  1. Redirect stdout/stderr to supervisor pipe
 *  2. Set UTS hostname = container id
 *  3. chroot into container rootfs
 *  4. Mount /proc (new PID namespace needs its own)
 *  5. Apply nice value
 *  6. exec the command
 * ================================================================ */
static int child_fn(void *arg)
{
    child_config_t *cfg = (child_config_t *)arg;

    /* 1 – stdout/stderr → supervisor pipe */
    if (dup2(cfg->pipe_write_fd, STDOUT_FILENO) < 0 ||
        dup2(cfg->pipe_write_fd, STDERR_FILENO) < 0) {
        perror("child: dup2");
        _exit(1);
    }
    close(cfg->pipe_write_fd);

    /* 2 – hostname in new UTS namespace */
    if (sethostname(cfg->id, strlen(cfg->id)) < 0)
        perror("child: sethostname");   /* non-fatal */

    /* 3 – chroot into container rootfs */
    if (chroot(cfg->rootfs) < 0) {
        perror("child: chroot");
        _exit(1);
    }
    if (chdir("/") < 0) {
        perror("child: chdir /");
        _exit(1);
    }

    /* 4 – mount /proc so ps/top work inside container */
    if (mount("proc", "/proc", "proc",
              MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) < 0)
        perror("child: mount /proc");   /* non-fatal */

    /* 5 – nice value for scheduling experiments (Task 5) */
    if (cfg->nice_value != 0) {
        errno = 0;
        (void)nice(cfg->nice_value);
        if (errno) perror("child: nice");
    }

    /* 6 – tokenise command string and exec */
    char  cmd_copy[CHILD_COMMAND_LEN];
    strncpy(cmd_copy, cfg->command, CHILD_COMMAND_LEN - 1);

    char *argv_exec[64];
    int   argc_exec = 0;
    char *tok = strtok(cmd_copy, " ");
    while (tok && argc_exec < 63) {
        argv_exec[argc_exec++] = tok;
        tok = strtok(NULL, " ");
    }
    argv_exec[argc_exec] = NULL;

    free(cfg);

    if (argc_exec == 0) { fprintf(stderr, "child: empty command\n"); _exit(1); }

    execv(argv_exec[0], argv_exec);
    perror("child: execv");
    _exit(1);
}

/* ================================================================
 * Task 1: launch_container
 * Creates namespace-isolated child, pipe, metadata record, producer.
 * ================================================================ */
static int launch_container(supervisor_ctx_t *ctx,
                              const control_request_t *req)
{
    int                pipefd[2];
    pid_t              child_pid;
    char              *stack, *stack_top;
    child_config_t    *cfg;
    container_record_t *rec;
    producer_arg_t    *parg;
    char               log_path[PATH_MAX];

    /* Reject duplicate IDs */
    pthread_mutex_lock(&ctx->metadata_lock);
    for (rec = ctx->containers; rec; rec = rec->next) {
        if (strcmp(rec->id, req->container_id) == 0) {
            pthread_mutex_unlock(&ctx->metadata_lock);
            fprintf(stderr, "supervisor: container '%s' already exists\n",
                    req->container_id);
            return -1;
        }
    }
    pthread_mutex_unlock(&ctx->metadata_lock);

    /* pipe: child writes, supervisor reads */
    if (pipe(pipefd) < 0) { perror("pipe"); return -1; }

    /* child config (heap – child frees it) */
    cfg = calloc(1, sizeof(*cfg));
    if (!cfg) { close(pipefd[0]); close(pipefd[1]); return -1; }
    strncpy(cfg->id,      req->container_id, CONTAINER_ID_LEN - 1);
    strncpy(cfg->rootfs,  req->rootfs,        PATH_MAX - 1);
    strncpy(cfg->command, req->command,        CHILD_COMMAND_LEN - 1);
    cfg->nice_value    = req->nice_value;
    cfg->pipe_write_fd = pipefd[1];

    /* clone stack */
    stack = malloc(STACK_SIZE);
    if (!stack) { free(cfg); close(pipefd[0]); close(pipefd[1]); return -1; }
    stack_top = stack + STACK_SIZE;

    /* log path */
    mkdir(LOG_DIR, 0755);
    snprintf(log_path, PATH_MAX, "%s/%s.log", LOG_DIR, req->container_id);

    /* metadata record */
    rec = calloc(1, sizeof(*rec));
    if (!rec) {
        free(stack); free(cfg);
        close(pipefd[0]); close(pipefd[1]); return -1;
    }
    strncpy(rec->id,       req->container_id, CONTAINER_ID_LEN - 1);
    strncpy(rec->log_path, log_path,           PATH_MAX - 1);
    rec->state            = CONTAINER_STARTING;
    rec->soft_limit_bytes = req->soft_limit_bytes;
    rec->hard_limit_bytes = req->hard_limit_bytes;
    rec->started_at       = time(NULL);
    rec->pipe_read_fd     = pipefd[0];
    rec->producer_running = 0;
    rec->stop_requested   = 0;
    rec->exit_reason      = EXIT_REASON_UNKNOWN;

    /* clone: new PID + UTS + mount namespaces */
    child_pid = clone(child_fn, stack_top,
                      CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | SIGCHLD,
                      cfg);
    free(stack);   /* supervisor doesn't need this after clone */

    if (child_pid < 0) {
        perror("clone");
        free(rec); free(cfg);
        close(pipefd[0]); close(pipefd[1]); return -1;
    }

    close(pipefd[1]);   /* supervisor only reads */

    rec->host_pid = child_pid;
    rec->state    = CONTAINER_RUNNING;

    /* insert into metadata list */
    pthread_mutex_lock(&ctx->metadata_lock);
    rec->next       = ctx->containers;
    ctx->containers = rec;
    pthread_mutex_unlock(&ctx->metadata_lock);

    fprintf(stdout,
            "supervisor: started '%s' host_pid=%d log=%s\n",
            rec->id, rec->host_pid, rec->log_path);
    fflush(stdout);

    /* register with kernel monitor (Task 4) */
    if (ctx->monitor_fd >= 0) {
        struct monitor_request mreq;
        memset(&mreq, 0, sizeof(mreq));
        mreq.pid              = child_pid;
        mreq.soft_limit_bytes = req->soft_limit_bytes;
        mreq.hard_limit_bytes = req->hard_limit_bytes;
        strncpy(mreq.container_id, req->container_id,
                sizeof(mreq.container_id) - 1);
        if (ioctl(ctx->monitor_fd, MONITOR_REGISTER, &mreq) < 0)
            perror("ioctl MONITOR_REGISTER");
    }

    /* start producer thread */
    parg = calloc(1, sizeof(*parg));
    if (parg) {
        parg->buffer        = &ctx->log_buffer;
        parg->record        = rec;
        parg->metadata_lock = &ctx->metadata_lock;
        pthread_mutex_lock(&ctx->metadata_lock);
        rec->producer_running = 1;
        if (pthread_create(&rec->producer_thread, NULL,
                           producer_thread_fn, parg) != 0) {
            perror("pthread_create producer");
            rec->producer_running = 0;
            free(parg);
        }
        pthread_mutex_unlock(&ctx->metadata_lock);
    }

    return 0;
}

/* ================================================================
 * Task 1 + 2: SIGCHLD handler
 * Reaps all available children, updates metadata state.
 * ================================================================ */
static void sigchld_handler(int sig)
{
    (void)sig;
    int status; pid_t pid;

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (!g_ctx) continue;

        container_record_t *rec;
        pthread_mutex_lock(&g_ctx->metadata_lock);
        for (rec = g_ctx->containers; rec; rec = rec->next)
            if (rec->host_pid == pid) break;

        if (rec) {
            if (WIFEXITED(status)) {
                rec->exit_code   = WEXITSTATUS(status);
                rec->exit_signal = 0;
                rec->state       = CONTAINER_EXITED;
                rec->exit_reason = rec->stop_requested
                                   ? EXIT_REASON_STOPPED
                                   : EXIT_REASON_NORMAL;
            } else if (WIFSIGNALED(status)) {
                rec->exit_code   = 0;
                rec->exit_signal = WTERMSIG(status);
                if (rec->stop_requested) {
                    rec->state       = CONTAINER_STOPPED;
                    rec->exit_reason = EXIT_REASON_STOPPED;
                } else if (rec->exit_signal == SIGKILL) {
                    rec->state       = CONTAINER_KILLED;
                    rec->exit_reason = EXIT_REASON_HARD_LIMIT_KILLED;
                } else {
                    rec->state       = CONTAINER_KILLED;
                    rec->exit_reason = EXIT_REASON_UNKNOWN;
                }
            }

            /* unregister from kernel monitor */
            if (g_ctx->monitor_fd >= 0) {
                struct monitor_request mreq;
                memset(&mreq, 0, sizeof(mreq));
                mreq.pid = pid;
                strncpy(mreq.container_id, rec->id,
                        sizeof(mreq.container_id) - 1);
                ioctl(g_ctx->monitor_fd, MONITOR_UNREGISTER, &mreq);
            }
        }
        pthread_mutex_unlock(&g_ctx->metadata_lock);
    }
}

static void sigterm_handler(int sig)
{
    (void)sig;
    if (g_ctx) g_ctx->should_stop = 1;
}

/* ================================================================
 * Task 2: handle one accepted control connection
 * ================================================================ */
static void handle_control_connection(supervisor_ctx_t *ctx, int conn_fd)
{
    control_request_t  req;
    control_response_t resp;

    memset(&resp, 0, sizeof(resp));
    if (recv(conn_fd, &req, sizeof(req), MSG_WAITALL) != (ssize_t)sizeof(req)) {
        resp.status = -1;
        snprintf(resp.message, CONTROL_MESSAGE_LEN, "bad request");
        send(conn_fd, &resp, sizeof(resp), 0);
        return;
    }

    switch (req.kind) {

    case CMD_START:
    case CMD_RUN: {
        int rc = launch_container(ctx, &req);
        if (rc != 0) {
            resp.status = -1;
            snprintf(resp.message, CONTROL_MESSAGE_LEN,
                     "failed to launch '%s'", req.container_id);
            send(conn_fd, &resp, sizeof(resp), 0);
            return;
        }
        resp.status = 0;
        snprintf(resp.message, CONTROL_MESSAGE_LEN,
                 "started '%s'", req.container_id);

        if (req.kind == CMD_RUN) {
            /* ack to unblock the client */
            send(conn_fd, &resp, sizeof(resp), 0);

            /* wait for container to exit */
            pid_t wpid = -1;
            pthread_mutex_lock(&ctx->metadata_lock);
            container_record_t *r;
            for (r = ctx->containers; r; r = r->next)
                if (strcmp(r->id, req.container_id) == 0)
                    { wpid = r->host_pid; break; }
            pthread_mutex_unlock(&ctx->metadata_lock);

            if (wpid > 0) { int ws; waitpid(wpid, &ws, 0); }

            /* send final status */
            memset(&resp, 0, sizeof(resp));
            pthread_mutex_lock(&ctx->metadata_lock);
            for (r = ctx->containers; r; r = r->next)
                if (strcmp(r->id, req.container_id) == 0) break;
            if (r) {
                resp.status    = 0;
                resp.exit_code = r->exit_code;
                snprintf(resp.message, CONTROL_MESSAGE_LEN,
                         "container '%s' exited code=%d reason=%s",
                         r->id, r->exit_code,
                         exit_reason_to_string(r->exit_reason));
            } else {
                resp.status = -1;
                snprintf(resp.message, CONTROL_MESSAGE_LEN, "not found");
            }
            pthread_mutex_unlock(&ctx->metadata_lock);
            send(conn_fd, &resp, sizeof(resp), 0);
            return;
        }
        break;
    }

    case CMD_PS: {
        char buf[CONTROL_MESSAGE_LEN]; int pos = 0;
        pos += snprintf(buf+pos, sizeof(buf)-(size_t)pos,
                        "%-16s %-8s %-12s %-10s %-10s %s\n",
                        "ID","PID","STATE","SOFT(MiB)","HARD(MiB)","REASON");
        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *r;
        for (r = ctx->containers; r; r = r->next)
            pos += snprintf(buf+pos, sizeof(buf)-(size_t)pos,
                            "%-16s %-8d %-12s %-10lu %-10lu %s\n",
                            r->id, r->host_pid,
                            state_to_string(r->state),
                            r->soft_limit_bytes >> 20,
                            r->hard_limit_bytes >> 20,
                            exit_reason_to_string(r->exit_reason));
        pthread_mutex_unlock(&ctx->metadata_lock);
        resp.status = 0;
        snprintf(resp.message, CONTROL_MESSAGE_LEN, "%s", buf);
        break;
    }

    case CMD_LOGS: {
        char lpath[PATH_MAX] = {0};
        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *r;
        for (r = ctx->containers; r; r = r->next)
            if (strcmp(r->id, req.container_id) == 0)
                { strncpy(lpath, r->log_path, PATH_MAX-1); break; }
        pthread_mutex_unlock(&ctx->metadata_lock);
        if (!lpath[0]) {
            resp.status = -1;
            snprintf(resp.message, CONTROL_MESSAGE_LEN,
                     "no container '%s'", req.container_id);
        } else {
            FILE *f = fopen(lpath, "r");
            if (!f) {
                resp.status = -1;
                snprintf(resp.message, CONTROL_MESSAGE_LEN,
                         "cannot open %s", lpath);
            } else {
                size_t nr = fread(resp.message, 1,
                                  CONTROL_MESSAGE_LEN-1, f);
                resp.message[nr] = '\0';
                resp.status = 0;
                fclose(f);
            }
        }
        break;
    }

    case CMD_STOP: {
        pid_t kpid = -1;
        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *r;
        for (r = ctx->containers; r; r = r->next) {
            if (strcmp(r->id, req.container_id) == 0) {
                kpid = r->host_pid;
                r->stop_requested = 1;
                break;
            }
        }
        pthread_mutex_unlock(&ctx->metadata_lock);
        if (kpid < 0) {
            resp.status = -1;
            snprintf(resp.message, CONTROL_MESSAGE_LEN,
                     "no container '%s'", req.container_id);
        } else {
            kill(kpid, SIGTERM);
            usleep(200000);
            kill(kpid, SIGKILL);
            resp.status = 0;
            snprintf(resp.message, CONTROL_MESSAGE_LEN,
                     "stopped '%s' pid=%d", req.container_id, kpid);
        }
        break;
    }

    default:
        resp.status = -1;
        snprintf(resp.message, CONTROL_MESSAGE_LEN, "unknown command");
    }

    send(conn_fd, &resp, sizeof(resp), 0);
}

/* ================================================================
 * run_supervisor
 * ================================================================ */
static int run_supervisor(const char *rootfs)
{
    supervisor_ctx_t   ctx;
    struct sockaddr_un addr;
    struct sigaction   sa;
    int rc;

    memset(&ctx, 0, sizeof(ctx));
    ctx.server_fd = ctx.monitor_fd = -1;
    g_ctx = &ctx;

    if ((rc = pthread_mutex_init(&ctx.metadata_lock, NULL))) {
        errno = rc; perror("pthread_mutex_init"); return 1;
    }
    if ((rc = bounded_buffer_init(&ctx.log_buffer))) {
        errno = rc; perror("bounded_buffer_init");
        pthread_mutex_destroy(&ctx.metadata_lock); return 1;
    }

    /* open kernel monitor device */
    ctx.monitor_fd = open(MONITOR_DEV, O_RDWR);
    if (ctx.monitor_fd < 0)
        fprintf(stderr,
                "supervisor: %s unavailable (module not loaded?)\n",
                MONITOR_DEV);

    /* UNIX domain socket */
    ctx.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctx.server_fd < 0) { perror("socket"); return 1; }
    unlink(CONTROL_PATH);
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path)-1);
    if (bind(ctx.server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(ctx.server_fd); return 1;
    }
    if (listen(ctx.server_fd, 8) < 0) {
        perror("listen"); close(ctx.server_fd); return 1;
    }
    chmod(CONTROL_PATH, 0666);

    /* signal handlers */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
    sa.sa_handler = sigterm_handler;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* consumer thread */
    if ((rc = pthread_create(&ctx.consumer_thread, NULL,
                             logging_thread, &ctx))) {
        errno = rc; perror("pthread_create consumer");
        close(ctx.server_fd); return 1;
    }

    fprintf(stdout,
            "supervisor: ready  rootfs=%s  socket=%s\n",
            rootfs, CONTROL_PATH);
    fflush(stdout);

    /* event loop */
    while (!ctx.should_stop) {
        fd_set rfds;
        struct timeval tv = {1, 0};
        FD_ZERO(&rfds);
        FD_SET(ctx.server_fd, &rfds);
        rc = select(ctx.server_fd + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0) { if (errno == EINTR) continue; perror("select"); break; }
        if (rc == 0) continue;
        int cfd = accept(ctx.server_fd, NULL, NULL);
        if (cfd < 0) { if (errno == EINTR) continue; perror("accept"); continue; }
        handle_control_connection(&ctx, cfd);
        close(cfd);
    }

    /* ---- orderly shutdown (Task 6) ---------------------------- */
    fprintf(stdout, "supervisor: shutting down...\n");

    /* kill all running containers */
    pthread_mutex_lock(&ctx.metadata_lock);
    container_record_t *rec;
    for (rec = ctx.containers; rec; rec = rec->next)
        if (rec->state == CONTAINER_RUNNING ||
            rec->state == CONTAINER_STARTING) {
            rec->stop_requested = 1;
            kill(rec->host_pid, SIGKILL);
        }
    pthread_mutex_unlock(&ctx.metadata_lock);

    /* reap */
    while (waitpid(-1, NULL, WNOHANG) > 0) {}

    /* join producer threads */
    pthread_mutex_lock(&ctx.metadata_lock);
    for (rec = ctx.containers; rec; rec = rec->next)
        if (rec->producer_running) {
            pthread_mutex_unlock(&ctx.metadata_lock);
            pthread_join(rec->producer_thread, NULL);
            pthread_mutex_lock(&ctx.metadata_lock);
        }
    pthread_mutex_unlock(&ctx.metadata_lock);

    /* drain log buffer and join consumer */
    bounded_buffer_begin_shutdown(&ctx.log_buffer);
    pthread_join(ctx.consumer_thread, NULL);

    /* free metadata */
    pthread_mutex_lock(&ctx.metadata_lock);
    rec = ctx.containers;
    while (rec) {
        container_record_t *nxt = rec->next;
        if (rec->pipe_read_fd >= 0) close(rec->pipe_read_fd);
        free(rec);
        rec = nxt;
    }
    ctx.containers = NULL;
    pthread_mutex_unlock(&ctx.metadata_lock);

    bounded_buffer_destroy(&ctx.log_buffer);
    pthread_mutex_destroy(&ctx.metadata_lock);
    close(ctx.server_fd);
    unlink(CONTROL_PATH);
    if (ctx.monitor_fd >= 0) close(ctx.monitor_fd);

    fprintf(stdout, "supervisor: clean exit\n");
    return 0;
}

/* ================================================================
 * CLI: send_control_request
 * ================================================================ */
static int send_control_request(const control_request_t *req)
{
    int sock_fd;
    struct sockaddr_un addr;
    control_response_t resp;

    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) { perror("socket"); return 1; }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path)-1);

    if (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr,
                "engine: cannot connect to supervisor (%s)\n"
                "        Is 'engine supervisor' running?\n",
                CONTROL_PATH);
        close(sock_fd); return 1;
    }

    if (send(sock_fd, req, sizeof(*req), 0) != (ssize_t)sizeof(*req)) {
        perror("send"); close(sock_fd); return 1;
    }

    int responses = (req->kind == CMD_RUN) ? 2 : 1;
    int ret = 0;
    for (int i = 0; i < responses; i++) {
        if (recv(sock_fd, &resp, sizeof(resp), MSG_WAITALL)
                != (ssize_t)sizeof(resp)) {
            fprintf(stderr, "engine: incomplete response\n");
            close(sock_fd); return 1;
        }
        if (resp.message[0]) printf("%s\n", resp.message);
        if (resp.status != 0) ret = 1;
        if (req->kind == CMD_RUN && i == 1) ret = resp.exit_code;
    }

    close(sock_fd);
    return ret;
}

/* ================================================================
 * CLI command functions
 * ================================================================ */
static int cmd_start(int argc, char *argv[])
{
    if (argc < 5) {
        fprintf(stderr,
            "Usage: %s start <id> <rootfs> <cmd> "
            "[--soft-mib N] [--hard-mib N] [--nice N]\n", argv[0]);
        return 1;
    }
    control_request_t req;
    memset(&req, 0, sizeof(req));
    req.kind             = CMD_START;
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;
    strncpy(req.container_id, argv[2], CONTAINER_ID_LEN-1);
    strncpy(req.rootfs,        argv[3], PATH_MAX-1);
    strncpy(req.command,       argv[4], CHILD_COMMAND_LEN-1);
    if (parse_optional_flags(&req, argc, argv, 5)) return 1;
    return send_control_request(&req);
}

static int cmd_run(int argc, char *argv[])
{
    if (argc < 5) {
        fprintf(stderr,
            "Usage: %s run <id> <rootfs> <cmd> "
            "[--soft-mib N] [--hard-mib N] [--nice N]\n", argv[0]);
        return 1;
    }
    control_request_t req;
    memset(&req, 0, sizeof(req));
    req.kind             = CMD_RUN;
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;
    strncpy(req.container_id, argv[2], CONTAINER_ID_LEN-1);
    strncpy(req.rootfs,        argv[3], PATH_MAX-1);
    strncpy(req.command,       argv[4], CHILD_COMMAND_LEN-1);
    if (parse_optional_flags(&req, argc, argv, 5)) return 1;
    return send_control_request(&req);
}

static int cmd_ps(void)
{
    control_request_t req;
    memset(&req, 0, sizeof(req));
    req.kind = CMD_PS;
    return send_control_request(&req);
}

static int cmd_logs(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s logs <id>\n", argv[0]); return 1;
    }
    control_request_t req;
    memset(&req, 0, sizeof(req));
    req.kind = CMD_LOGS;
    strncpy(req.container_id, argv[2], CONTAINER_ID_LEN-1);
    return send_control_request(&req);
}

static int cmd_stop(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s stop <id>\n", argv[0]); return 1;
    }
    control_request_t req;
    memset(&req, 0, sizeof(req));
    req.kind = CMD_STOP;
    strncpy(req.container_id, argv[2], CONTAINER_ID_LEN-1);
    return send_control_request(&req);
}

/* ================================================================
 * main
 * ================================================================ */
int main(int argc, char *argv[])
{
    if (argc < 2) { usage(argv[0]); return 1; }

    if (strcmp(argv[1], "supervisor") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s supervisor <base-rootfs>\n", argv[0]);
            return 1;
        }
        return run_supervisor(argv[2]);
    }
    if (strcmp(argv[1], "start") == 0) return cmd_start(argc, argv);
    if (strcmp(argv[1], "run")   == 0) return cmd_run(argc, argv);
    if (strcmp(argv[1], "ps")    == 0) return cmd_ps();
    if (strcmp(argv[1], "logs")  == 0) return cmd_logs(argc, argv);
    if (strcmp(argv[1], "stop")  == 0) return cmd_stop(argc, argv);

    usage(argv[0]);
    return 1;
}

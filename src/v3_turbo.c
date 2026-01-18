

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <liburing.h>
#include <getopt.h>

#include "v3_cpu_dispatch.h"

#define V3_PORT             51820
#define QUEUE_DEPTH         2048
#define BUF_SIZE            1500
#define MAX_CONNS           4096

typedef struct {
    uint64_t    target_bps;
    bool        brutal_enabled;
    uint8_t     xor_group_size;
} turbo_config_t;

static turbo_config_t g_config = {
    .target_bps = 100 * 1000 * 1000,
    .brutal_enabled = true,
    .xor_group_size = 4,
};

static struct io_uring g_ring;
static volatile sig_atomic_t g_running = 1;

typedef struct {
    uint8_t     data[4][BUF_SIZE];
    size_t      lens[4];
    int         count;
    uint32_t    group_id;
} xor_fec_group_t;

static void xor_fec_add(xor_fec_group_t *g, const uint8_t *data, size_t len) {
    if (g->count < 4) {
        memcpy(g->data[g->count], data, len);
        g->lens[g->count] = len;
        g->count++;
    }
}

static size_t xor_fec_generate_parity(xor_fec_group_t *g, uint8_t *parity) {
    if (g->count == 0) return 0;
    
    size_t max_len = 0;
    for (int i = 0; i < g->count; i++) {
        if (g->lens[i] > max_len) max_len = g->lens[i];
    }
    
    memset(parity, 0, max_len);
    
    for (int i = 0; i < g->count; i++) {
        for (size_t j = 0; j < g->lens[i]; j++) {
            parity[j] ^= g->data[i][j];
        }
    }
    
    return max_len;
}

typedef struct {
    uint64_t    target_bps;
    uint64_t    tokens;
    double      tokens_per_ns;
    uint64_t    last_refill_ns;
} brutal_pacer_t;

static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void brutal_init(brutal_pacer_t *p, uint64_t target_bps) {
    p->target_bps = target_bps;
    p->tokens = target_bps / 8;
    p->tokens_per_ns = (double)target_bps / 8.0 / 1e9;
    p->last_refill_ns = get_time_ns();
}

static uint64_t brutal_acquire(brutal_pacer_t *p, size_t bytes) {
    uint64_t now = get_time_ns();
    uint64_t elapsed = now - p->last_refill_ns;
    
    p->tokens += elapsed * p->tokens_per_ns;
    
    uint64_t max_burst = p->target_bps / 8 / 10;
    if (p->tokens > max_burst) p->tokens = max_burst;
    
    p->last_refill_ns = now;
    
    if (p->tokens >= bytes) {
        p->tokens -= bytes;
        return 0;
    }
    
    double deficit = bytes - p->tokens;
    return (uint64_t)(deficit / p->tokens_per_ns);
}

typedef struct {
    int fd;
    struct sockaddr_in addr;
    struct iovec iov;
    struct msghdr msg;
    uint8_t buf[BUF_SIZE];
    enum { OP_READ, OP_WRITE } op;
} io_ctx_t;

static io_ctx_t g_io_pool[MAX_CONNS];
static brutal_pacer_t g_pacer;
static xor_fec_group_t g_fec_group;

static void submit_recv(io_ctx_t *ctx) {
    ctx->op = OP_READ;
    ctx->iov.iov_base = ctx->buf;
    ctx->iov.iov_len = BUF_SIZE;
    ctx->msg.msg_name = &ctx->addr;
    ctx->msg.msg_namelen = sizeof(ctx->addr);
    ctx->msg.msg_iov = &ctx->iov;
    ctx->msg.msg_iovlen = 1;
    
    struct io_uring_sqe *sqe = io_uring_get_sqe(&g_ring);
    io_uring_prep_recvmsg(sqe, ctx->fd, &ctx->msg, 0);
    io_uring_sqe_set_data(sqe, ctx);
}

static void handle_packet(io_ctx_t *ctx, int len) {
    if (len < 8) {
        submit_recv(ctx);
        return;
    }
    
    xor_fec_add(&g_fec_group, ctx->buf, len);
    
    if (g_fec_group.count >= g_config.xor_group_size) {
        uint8_t parity[BUF_SIZE];
        xor_fec_generate_parity(&g_fec_group, parity);
        
        g_fec_group.count = 0;
        g_fec_group.group_id++;
    }
    
    if (g_config.brutal_enabled) {
        uint64_t wait = brutal_acquire(&g_pacer, len);
        if (wait > 0) {
            struct timespec ts = {0, wait};
            nanosleep(&ts, NULL);
        }
    }
    
    submit_recv(ctx);
}

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static void usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("v8 Turbo - Brutal Mode Server\n\n");
    printf("Options:\n");
    printf("  --port=PORT       Listen port (default: 51820)\n");
    printf("  --rate=MBPS       Target rate in Mbps (default: 100)\n");
    printf("  --fec-group=N     XOR FEC group size (default: 4)\n");
    printf("  --no-brutal       Disable Brutal mode\n");
    printf("  --help            Show this help\n");
}

int main(int argc, char **argv) {
    int port = V3_PORT;
    
    static struct option long_opts[] = {
        {"port",      required_argument, 0, 'p'},
        {"rate",      required_argument, 0, 'r'},
        {"fec-group", required_argument, 0, 'g'},
        {"no-brutal", no_argument,       0, 'B'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "p:r:g:Bh", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'p': port = atoi(optarg); break;
            case 'r': g_config.target_bps = atoll(optarg) * 1000000ULL; break;
            case 'g': g_config.xor_group_size = atoi(optarg); break;
            case 'B': g_config.brutal_enabled = false; break;
            case 'h': usage(argv[0]); return 0;
        }
    }
    
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                    v3 Turbo (v8)                              ║\n");
    printf("║              Brutal Mode + XOR FEC                            ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n\n");
    
    cpu_detect();
    cpu_print_info();
    
    printf("[Config] Target Rate: %lu Mbps\n", g_config.target_bps / 1000000);
    printf("[Config] Brutal Mode: %s\n", g_config.brutal_enabled ? "ON" : "OFF");
    printf("[Config] FEC Group: %d\n", g_config.xor_group_size);
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    brutal_init(&g_pacer, g_config.target_bps);
    memset(&g_fec_group, 0, sizeof(g_fec_group));
    
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int val = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
    
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = INADDR_ANY
    };
    bind(fd, (struct sockaddr*)&addr, sizeof(addr));
    
    struct io_uring_params params = {0};
    if (geteuid() == 0) {
        params.flags |= IORING_SETUP_SQPOLL;
        params.sq_thread_idle = 2000;
    }
    io_uring_queue_init_params(QUEUE_DEPTH, &g_ring, &params);
    
    printf("[INFO] Listening on port %d\n\n", port);
    
    for (int i = 0; i < MAX_CONNS; i++) {
        g_io_pool[i].fd = fd;
        submit_recv(&g_io_pool[i]);
    }
    io_uring_submit(&g_ring);
    
    struct io_uring_cqe *cqe;
    while (g_running) {
        int ret = io_uring_wait_cqe(&g_ring, &cqe);
        if (ret < 0) {
            if (ret == -EINTR) continue;
            break;
        }
        
        io_ctx_t *ctx = io_uring_cqe_get_data(cqe);
        if (cqe->res > 0 && ctx->op == OP_READ) {
            handle_packet(ctx, cqe->res);
        } else {
            submit_recv(ctx);
        }
        io_uring_cqe_seen(&g_ring, cqe);
    }
    
    io_uring_queue_exit(&g_ring);
    close(fd);
    
    printf("[INFO] Shutdown complete.\n");
    return 0;
}




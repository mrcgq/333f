
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>

#define V3_PORT         51820
#define BUF_SIZE        1500
#define MAX_EVENTS      64

static struct {
    uint64_t    target_bps;
    bool        brutal_enabled;
    uint8_t     xor_group_size;
    int         port;
} g_config = {
    .target_bps = 100 * 1000 * 1000,
    .brutal_enabled = true,
    .xor_group_size = 4,
    .port = V3_PORT,
};

static volatile sig_atomic_t g_running = 1;

static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

typedef struct {
    uint64_t    target_bps;
    double      tokens;
    double      tokens_per_ns;
    uint64_t    last_refill_ns;
} brutal_pacer_t;

static brutal_pacer_t g_pacer;

static void brutal_init(brutal_pacer_t *p, uint64_t bps) {
    p->target_bps = bps;
    p->tokens = bps / 8;
    p->tokens_per_ns = (double)bps / 8.0 / 1e9;
    p->last_refill_ns = get_time_ns();
}

static uint64_t brutal_acquire(brutal_pacer_t *p, size_t bytes) {
    uint64_t now = get_time_ns();
    uint64_t elapsed = now - p->last_refill_ns;
    
    p->tokens += elapsed * p->tokens_per_ns;
    
    double max_burst = p->target_bps / 8.0 / 10.0;
    if (p->tokens > max_burst) p->tokens = max_burst;
    
    p->last_refill_ns = now;
    
    if (p->tokens >= bytes) {
        p->tokens -= bytes;
        return 0;
    }
    
    return (uint64_t)((bytes - p->tokens) / p->tokens_per_ns);
}

typedef struct {
    uint8_t data[4][BUF_SIZE];
    size_t  lens[4];
    int     count;
} xor_group_t;

static xor_group_t g_fec;

static void xor_add(xor_group_t *g, const uint8_t *d, size_t len) {
    if (g->count < 4) {
        memcpy(g->data[g->count], d, len);
        g->lens[g->count] = len;
        g->count++;
    }
}

static size_t xor_parity(xor_group_t *g, uint8_t *out) {
    if (g->count == 0) return 0;
    
    size_t max = 0;
    for (int i = 0; i < g->count; i++)
        if (g->lens[i] > max) max = g->lens[i];
    
    memset(out, 0, max);
    for (int i = 0; i < g->count; i++)
        for (size_t j = 0; j < g->lens[i]; j++)
            out[j] ^= g->data[i][j];
    
    return max;
}

static void sig_handler(int sig) {
    (void)sig;
    g_running = 0;
}

int main(int argc, char **argv) {
    static struct option opts[] = {
        {"port", required_argument, 0, 'p'},
        {"rate", required_argument, 0, 'r'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "p:r:h", opts, NULL)) != -1) {
        switch (opt) {
            case 'p': g_config.port = atoi(optarg); break;
            case 'r': g_config.target_bps = atoll(optarg) * 1000000ULL; break;
            case 'h':
                printf("v9 Turbo-Portable - Static Brutal Server\n");
                printf("  --port=PORT   Listen port\n");
                printf("  --rate=MBPS   Target rate\n");
                return 0;
        }
    }
    
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║               v3 Turbo-Portable (v9)                          ║\n");
    printf("║            Static + Brutal + XOR FEC                          ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n\n");
    
    printf("[Config] Rate: %lu Mbps, Port: %d\n\n", 
           g_config.target_bps / 1000000, g_config.port);
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    brutal_init(&g_pacer, g_config.target_bps);
    
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fd < 0) { perror("socket"); return 1; }
    
    int val = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
    
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(g_config.port),
        .sin_addr.s_addr = INADDR_ANY
    };
    
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    
    int epfd = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN | EPOLLET, .data.fd = fd };
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
    
    printf("[INFO] Listening on port %d (epoll mode)\n\n", g_config.port);
    
    struct epoll_event events[MAX_EVENTS];
    uint8_t buf[BUF_SIZE];
    
    while (g_running) {
        int n = epoll_wait(epfd, events, MAX_EVENTS, 1000);
        
        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == fd) {
                struct sockaddr_in client;
                socklen_t clen = sizeof(client);
                
                while (1) {
                    int len = recvfrom(fd, buf, BUF_SIZE, 0,
                                      (struct sockaddr*)&client, &clen);
                    if (len < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        perror("recvfrom");
                        break;
                    }
                    
                    xor_add(&g_fec, buf, len);
                    if (g_fec.count >= g_config.xor_group_size) {
                        uint8_t parity[BUF_SIZE];
                        xor_parity(&g_fec, parity);
                        g_fec.count = 0;
                    }
                    
                    if (g_config.brutal_enabled) {
                        uint64_t wait = brutal_acquire(&g_pacer, len);
                        if (wait > 0) {
                            struct timespec ts = {0, wait};
                            nanosleep(&ts, NULL);
                        }
                    }
                }
            }
        }
    }
    
    close(fd);
    close(epfd);
    
    printf("[INFO] Shutdown complete.\n");
    return 0;
}




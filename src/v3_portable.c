
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <getopt.h>

#define V3_PORT             51820
#define MAX_CONNS           1024
#define BUF_SIZE            2048
#define MAX_EVENTS          64
#define MAX_INTENTS         16

static int crypto_verify16(const uint8_t *x, const uint8_t *y) {
    uint32_t d = 0;
    for (int i = 0; i < 16; i++) d |= x[i] ^ y[i];
    return (1 & ((d - 1) >> 8)) - 1;
}

static void random_bytes(uint8_t *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        if (read(fd, buf, len) != (ssize_t)len) {
            for(size_t i=0;i<len;i++) buf[i] = rand();
        }
        close(fd);
    }
}

#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a, b, c, d) a += b; d ^= a; d = ROTL(d,16); c += d; b ^= c; b = ROTL(b,12); a += b; d ^= a; d = ROTL(d, 8); c += d; b ^= c; b = ROTL(b, 7);

static void chacha20_block(uint32_t out[16], uint32_t const in[16]) {
    int i; uint32_t x[16];
    for (i = 0; i < 16; ++i) x[i] = in[i];
    for (i = 0; i < 10; ++i) {
        QR(x[0], x[4], x[8], x[12]); QR(x[1], x[5], x[9], x[13]);
        QR(x[2], x[6], x[10], x[14]); QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]); QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8], x[13]); QR(x[3], x[4], x[9], x[14]);
    }
    for (i = 0; i < 16; ++i) out[i] = x[i] + in[i];
}

static void chacha20_xor(uint8_t *out, const uint8_t *in, size_t len, 
                         const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
    uint32_t state[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    memcpy(&state[4], key, 32); 
    state[12] = counter; 
    memcpy(&state[13], nonce, 12);

    uint32_t block[16]; 
    uint8_t *kstream = (uint8_t *)block; 
    size_t offset = 0;

    while (offset < len) {
        chacha20_block(block, state); 
        state[12]++;
        size_t chunk = (len - offset > 64) ? 64 : (len - offset);
        for (size_t i = 0; i < chunk; i++) {
            if (in) out[offset + i] = in[offset + i] ^ kstream[i];
            else    out[offset + i] = kstream[i];
        }
        offset += chunk;
    }
}

typedef struct {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    size_t leftover;
    uint8_t buffer[16];
    uint8_t final;
} poly1305_state;

static void poly1305_init(poly1305_state *st, const uint8_t key[32]) {
    st->r[0] = (*(uint32_t*)&key[0])  & 0x3ffffff;
    st->r[1] = (*(uint32_t*)&key[3]  >> 2) & 0x3ffff03;
    st->r[2] = (*(uint32_t*)&key[6]  >> 4) & 0x3ffc0ff;
    st->r[3] = (*(uint32_t*)&key[9]  >> 6) & 0x3f03fff;
    st->r[4] = (*(uint32_t*)&key[12] >> 8) & 0x00fffff;
    
    st->h[0] = 0; st->h[1] = 0; st->h[2] = 0; st->h[3] = 0; st->h[4] = 0;
    
    st->pad[0] = *(uint32_t*)&key[16];
    st->pad[1] = *(uint32_t*)&key[20];
    st->pad[2] = *(uint32_t*)&key[24];
    st->pad[3] = *(uint32_t*)&key[28];
    
    st->leftover = 0;
    st->final = 0;
}

static void poly1305_blocks(poly1305_state *st, const uint8_t *m, size_t bytes) {
    const uint32_t hibit = st->final ? 0 : (1 << 24);
    uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3], r4 = st->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
    
    while (bytes >= 16) {
        h0 += (*(uint32_t*)&m[0])  & 0x3ffffff;
        h1 += (*(uint32_t*)&m[3]  >> 2) & 0x3ffffff;
        h2 += (*(uint32_t*)&m[6]  >> 4) & 0x3ffffff;
        h3 += (*(uint32_t*)&m[9]  >> 6) & 0x3ffffff;
        h4 += (*(uint32_t*)&m[12] >> 8) | hibit;
        
        uint64_t d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
        uint64_t d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
        uint64_t d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
        uint64_t d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
        uint64_t d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;
        
        uint32_t c;
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff; d1 += c;
        c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff; d2 += c;
        c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff; d3 += c;
        c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff; d4 += c;
        c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff; h0 += c * 5;
        c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
        
        m += 16; bytes -= 16;
    }
    st->h[0] = h0; st->h[1] = h1; st->h[2] = h2; st->h[3] = h3; st->h[4] = h4;
}

static void poly1305_update(poly1305_state *st, const uint8_t *m, size_t bytes) {
    if (st->leftover) {
        size_t want = 16 - st->leftover;
        if (want > bytes) want = bytes;
        memcpy(st->buffer + st->leftover, m, want);
        bytes -= want; m += want; st->leftover += want;
        if (st->leftover < 16) return;
        poly1305_blocks(st, st->buffer, 16);
        st->leftover = 0;
    }
    if (bytes >= 16) {
        size_t want = bytes & ~15;
        poly1305_blocks(st, m, want);
        m += want; bytes -= want;
    }
    if (bytes) {
        memcpy(st->buffer, m, bytes);
        st->leftover = bytes;
    }
}

static void poly1305_finish(poly1305_state *st, uint8_t mac[16]) {
    if (st->leftover) {
        st->buffer[st->leftover++] = 1;
        while (st->leftover < 16) st->buffer[st->leftover++] = 0;
        st->final = 1;
        poly1305_blocks(st, st->buffer, 16);
    }
    
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
    uint32_t c;
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    
    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1 << 26);
    
    uint32_t mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2; h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;
    
    uint64_t f;
    f = (uint64_t)h0 + st->pad[0];                h0 = (uint32_t)f;
    f = (uint64_t)h1 + st->pad[1] + (f >> 32);    h1 = (uint32_t)f;
    f = (uint64_t)h2 + st->pad[2] + (f >> 32);    h2 = (uint32_t)f;
    f = (uint64_t)h3 + st->pad[3] + (f >> 32);    h3 = (uint32_t)f;
    
    *(uint32_t*)&mac[0]  = h0 | (h1 << 26);
    *(uint32_t*)&mac[4]  = (h1 >> 6) | (h2 << 20);
    *(uint32_t*)&mac[8]  = (h2 >> 12) | (h3 << 14);
    *(uint32_t*)&mac[12] = (h3 >> 18) | (h4 << 8);
}

static void poly1305_pad16(poly1305_state *st, size_t len) {
    if (len % 16 != 0) {
        uint8_t zero[16] = {0};
        poly1305_update(st, zero, 16 - (len % 16));
    }
}

static int aead_encrypt(uint8_t *ct, uint8_t tag[16], 
                        const uint8_t *pt, size_t pt_len, 
                        const uint8_t *aad, size_t aad_len, 
                        const uint8_t nonce[12], const uint8_t key[32]) {
    
    uint8_t poly_key[64] = {0};
    chacha20_xor(poly_key, poly_key, 64, key, nonce, 0); 
    
    chacha20_xor(ct, pt, pt_len, key, nonce, 1);
    
    poly1305_state st;
    poly1305_init(&st, poly_key);
    
    poly1305_update(&st, aad, aad_len);
    poly1305_pad16(&st, aad_len);
    
    poly1305_update(&st, ct, pt_len);
    poly1305_pad16(&st, pt_len);
    
    uint8_t lens[16];
    *(uint64_t*)&lens[0] = (uint64_t)aad_len;
    *(uint64_t*)&lens[8] = (uint64_t)pt_len;
    poly1305_update(&st, lens, 16);
    
    poly1305_finish(&st, tag);
    return 0;
}

static int aead_decrypt(uint8_t *pt, 
                        const uint8_t *ct, size_t ct_len, 
                        const uint8_t tag[16], 
                        const uint8_t *aad, size_t aad_len, 
                        const uint8_t nonce[12], const uint8_t key[32]) {
    
    uint8_t poly_key[64] = {0};
    chacha20_xor(poly_key, poly_key, 64, key, nonce, 0);
    
    uint8_t computed_tag[16];
    poly1305_state st;
    poly1305_init(&st, poly_key);
    
    poly1305_update(&st, aad, aad_len);
    poly1305_pad16(&st, aad_len);
    
    poly1305_update(&st, ct, ct_len);
    poly1305_pad16(&st, ct_len);
    
    uint8_t lens[16];
    *(uint64_t*)&lens[0] = (uint64_t)aad_len;
    *(uint64_t*)&lens[8] = (uint64_t)ct_len;
    poly1305_update(&st, lens, 16);
    
    poly1305_finish(&st, computed_tag);
    
    if (crypto_verify16(tag, computed_tag) != 0) {
        return -1;
    }
    
    chacha20_xor(pt, ct, ct_len, key, nonce, 1);
    return 0;
}

static void simple_hash(uint8_t out[32], const uint8_t *in, size_t inlen) {
    uint8_t state[32] = {0}; 
    uint8_t nonce[12] = {0};
    
    uint8_t block[64];
    size_t offset = 0;
    while(offset < inlen) {
        size_t chunk = (inlen - offset > 32) ? 32 : (inlen - offset);
        for(size_t i=0; i<chunk; i++) state[i] ^= in[offset+i];
        
        chacha20_xor(block, block, 64, state, nonce, 0);
        memcpy(state, block, 32);
        
        offset += chunk;
    }
    memcpy(out, state, 32);
}

static uint8_t g_master_key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

typedef struct __attribute__((packed)) {
    uint32_t magic_derived; 
    uint8_t nonce[12]; 
    uint8_t enc_block[16];
    uint8_t tag[16];
    uint16_t early_len;
    uint16_t pad;
} v3_header_t;
#define V3_HEADER_SIZE sizeof(v3_header_t)

typedef struct {
    uint64_t session_token; 
	uint16_t intent_id; 
	uint16_t stream_id; 
	uint16_t flags;
	uint16_t early_len;
} v3_meta_t;

typedef struct { int active; uint32_t ip; uint16_t port; } route_t;

static route_t g_intents[MAX_INTENTS];
static int g_udp_fd, g_epoll_fd;
static volatile sig_atomic_t g_running = 1;

static uint32_t derive_magic(time_t window) {
    uint8_t input[40]; 
    memcpy(input, g_master_key, 32);
    uint64_t w = window / 60;
    memcpy(input + 32, &w, 8);
    
    uint8_t hash[32]; 
    simple_hash(hash, input, sizeof(input));
    
    uint32_t magic; 
    memcpy(&magic, hash, 4);
    return magic;
}

static int verify_magic(uint32_t received) {
    time_t now = time(NULL);
    if (received == derive_magic(now)) return 1;
    if (received == derive_magic(now - 60)) return 1;
    if (received == derive_magic(now + 60)) return 1;
    return 0;
}

static int decrypt_header(const uint8_t *buf, size_t len, v3_meta_t *out) {
    if (len < V3_HEADER_SIZE) return 0;
    const v3_header_t *hdr = (const v3_header_t *)buf;
    
    if (!verify_magic(hdr->magic_derived)) return 0;
    
    uint8_t aad_buf[8];
    memcpy(aad_buf, &hdr->early_len, 2);
    memcpy(aad_buf+2, &hdr->pad, 2);
    memcpy(aad_buf+4, &hdr->magic_derived, 4);

    uint8_t plaintext[16];
    if (aead_decrypt(plaintext, 
                     hdr->enc_block, 16, 
                     hdr->tag, 
                     aad_buf, 8, 
                     hdr->nonce, g_master_key) != 0) {
        return 0;
    }
    
    memcpy(&out->session_token, plaintext, 8);
    memcpy(&out->intent_id, plaintext + 8, 2);
    memcpy(&out->stream_id, plaintext + 10, 2);
    memcpy(&out->flags, plaintext + 12, 2);
    
    out->early_len = hdr->early_len;
    return 1;
}

static void handle_udp_packet(uint8_t *buf, int len, struct sockaddr_in *from) {
    v3_meta_t meta;
    if (!decrypt_header(buf, len, &meta)) {
        return;
    }
    
    if (meta.intent_id >= MAX_INTENTS || !g_intents[meta.intent_id].active) return;
    route_t *route = &g_intents[meta.intent_id];
    
    printf("[v3] Recv Packet. Token: %lx, Intent: %d, Payload: %d bytes\n", 
           meta.session_token, meta.intent_id, len - (int)V3_HEADER_SIZE);
}

static void sig_handler(int sig) {
    (void)sig;
    g_running = 0;
}

int main(int argc, char **argv) {
    signal(SIGINT, sig_handler);
    
    g_intents[0].active = 1; 
    inet_pton(AF_INET, "127.0.0.1", &g_intents[0].ip); 
    g_intents[0].port = 8080;

    g_udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (g_udp_fd < 0) { perror("socket"); return 1; }
    
    struct sockaddr_in addr = { 
        .sin_family = AF_INET, 
        .sin_addr.s_addr = 0, 
        .sin_port = htons(V3_PORT) 
    };
    if (bind(g_udp_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { 
        perror("bind"); return 1; 
    }
    
    g_epoll_fd = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN | EPOLLET, .data.fd = g_udp_fd };
    epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, g_udp_fd, &ev);
    
    printf("v3 Portable Server (ChaCha20-Poly1305 RFC7539) listening on %d\n", V3_PORT);
    
    struct epoll_event events[MAX_EVENTS];
    uint8_t buf[BUF_SIZE];
    
    while (g_running) {
        int n = epoll_wait(g_epoll_fd, events, MAX_EVENTS, 1000);
        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == g_udp_fd) {
                struct sockaddr_in client;
                socklen_t clen = sizeof(client);
                while (1) {
                    int len = recvfrom(g_udp_fd, buf, BUF_SIZE, 0, (struct sockaddr*)&client, &clen);
                    if (len < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        perror("recvfrom"); break;
                    }
                    handle_udp_packet(buf, len, &client);
                }
            }
        }
    }
    
    close(g_udp_fd);
    close(g_epoll_fd);
    return 0;
}




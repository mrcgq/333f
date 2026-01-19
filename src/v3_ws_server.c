

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define WS_PORT 443
#define V3_LOCAL_PORT 51820
#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// =========================================================
// 1. WebSocket 协议实现
// =========================================================
static int b64_encode(const unsigned char *in, int inlen, char *out) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, in, inlen);
    BIO_flush(b64);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);
    memcpy(out, bptr->data, bptr->length);
    out[bptr->length] = 0;
    BIO_free_all(b64);
    return bptr->length;
}

static void ws_make_accept_key(char *out, const char *key) {
    char combined[128];
    snprintf(combined, sizeof(combined), "%s%s", key, WS_GUID);
    uint8_t hash[SHA_DIGEST_LENGTH];
    SHA1((uint8_t *)combined, strlen(combined), hash);
    b64_encode(hash, SHA_DIGEST_LENGTH, out);
}

static int unwrap_ws_frame(uint8_t *buf, int len, uint8_t **payload, int *payload_len) {
    if (len < 2) return 0;
    int masked = (buf[1] >> 7) & 1;
    uint64_t p_len = buf[1] & 0x7F;
    int head_len = 2;
    if (p_len == 126) { if (len < 4) return 0; p_len = (buf[2] << 8) | buf[3]; head_len = 4; }
    if (masked) { if (len < head_len + 4) return 0; head_len += 4; }
    if (len < head_len + p_len) return 0;
    
    *payload = buf + head_len; *payload_len = p_len;
    
    if (masked) {
        uint8_t *mask = buf + head_len - 4;
        for (uint64_t i = 0; i < p_len; i++) (*payload)[i] ^= mask[i % 4];
    }
    return head_len + p_len;
}

static size_t wrap_ws_frame(uint8_t *out, const uint8_t *data, size_t len) {
    size_t head_len;
    out[0] = 0x82; // Binary
    if (len < 126) { out[1] = len; head_len = 2; }
    else { out[1] = 126; out[2] = (len >> 8) & 0xFF; out[3] = len & 0xFF; head_len = 4; }
    memcpy(out + head_len, data, len);
    return head_len + len;
}

// =========================================================
// 2. 客户端处理线程
// =========================================================
typedef struct { int client_fd; SSL_CTX *ssl_ctx; } thread_arg_t;

void* handle_client(void *arg) {
    thread_arg_t *targ = (thread_arg_t*)arg;
    int client_fd = targ->client_fd;
    SSL_CTX *ssl_ctx = targ->ssl_ctx;
    free(targ);
    
    pthread_detach(pthread_self());

    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, client_fd);
    
    if (SSL_accept(ssl) <= 0) goto cleanup;
    
    char buf[4096];
    int n = SSL_read(ssl, buf, sizeof(buf)-1);
    if (n <= 0) goto cleanup;
    buf[n] = 0;
    
    if (strstr(buf, "Upgrade: websocket")) {
        char *key_start = strstr(buf, "Sec-WebSocket-Key: ");
        if (!key_start) goto cleanup;
        key_start += 19;
        char *key_end = strstr(key_start, "\r\n");
        if (!key_end) goto cleanup;
        *key_end = 0;
        
        char accept_key[128];
        ws_make_accept_key(accept_key, key_start);
        
        char resp[512];
        sprintf(resp, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept_key);
        SSL_write(ssl, resp, strlen(resp));
        
        int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in v3_addr = {.sin_family=AF_INET, .sin_port=htons(V3_LOCAL_PORT), .sin_addr.s_addr=inet_addr("127.0.0.1")};
        
        while ((n = SSL_read(ssl, buf, sizeof(buf))) > 0) {
            uint8_t *v3_payload;
            int v3_len;
            int consumed = unwrap_ws_frame((uint8_t*)buf, n, &v3_payload, &v3_len);
            if (consumed > 0) {
                sendto(udp_fd, v3_payload, v3_len, 0, (struct sockaddr*)&v3_addr, sizeof(v3_addr));
            }
            // 简单的回显逻辑
            uint8_t resp_buf[2048];
            int resp_len = recv(udp_fd, resp_buf, sizeof(resp_buf), 0);
            if (resp_len > 0) {
                uint8_t ws_frame[2048+10];
                size_t ws_len = wrap_ws_frame(ws_frame, resp_buf, resp_len);
                SSL_write(ssl, ws_frame, ws_len);
            }
        }
        close(udp_fd);
    }

cleanup:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
    return NULL;
}

// =========================================================
// 3. 主程序
// =========================================================
int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <cert_file> <key_file>\n", argv[0]);
        return 1;
    }

    SSL_library_init();
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (SSL_CTX_use_certificate_file(ctx, argv[1], SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, argv[2], SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { .sin_family=AF_INET, .sin_port=htons(WS_PORT), .sin_addr.s_addr=0 };
    bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(listen_fd, 128);
    
    printf("v3 Rescue WSS listening on %d, forwarding to UDP %d\n", WS_PORT, V3_LOCAL_PORT);
    
    while(1) {
        int client = accept(listen_fd, NULL, NULL);
        if (client < 0) continue;
        
        thread_arg_t *arg = malloc(sizeof(thread_arg_t));
        arg->client_fd = client;
        arg->ssl_ctx = ctx;
        
        pthread_t tid;
        pthread_create(&tid, NULL, handle_client, arg);
    }
    
    SSL_CTX_free(ctx);
    close(listen_fd);
    return 0;
}

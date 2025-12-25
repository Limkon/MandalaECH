#include "crypto.h"
#include "utils.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>

// 引用 globals.c 中的全局变量
extern SSL_CTX *g_ssl_ctx;

static BIO_METHOD *method_frag = NULL;
static INIT_ONCE g_crypto_init_once = INIT_ONCE_STATIC_INIT;

// ---------------------- BIO Implementation (Frag + Padding) ----------------------
typedef struct {
    int first_packet_sent;
    // 分片配置
    int frag_min;
    int frag_max;
    int frag_delay;
    // 填充配置
    int enable_padding;
    int pad_min;
    int pad_max;
} FragCtx;

static int frag_write(BIO *b, const char *in, int inl);
static int frag_read(BIO *b, char *out, int outl);
static long frag_ctrl(BIO *b, int cmd, long num, void *ptr);
static int frag_new(BIO *b);
static int frag_free(BIO *b);

// [Optimization] 构造静态 BIO_METHOD，避免重复创建
BIO_METHOD *BIO_f_fragment(void) { 
    return method_frag; 
}

static int frag_new(BIO *b) {
    FragCtx *ctx = (FragCtx *)malloc(sizeof(FragCtx));
    if(!ctx) return 0;
    memset(ctx, 0, sizeof(FragCtx));
    BIO_set_data(b, ctx);
    BIO_set_init(b, 1);
    return 1;
}

static int frag_free(BIO *b) {
    if (b == NULL) return 0;
    FragCtx *ctx = (FragCtx *)BIO_get_data(b);
    if (ctx) { free(ctx); BIO_set_data(b, NULL); }
    return 1;
}

void BIO_set_params(BIO *b, const CryptoSettings *s) {
    FragCtx *ctx = (FragCtx *)BIO_get_data(b);
    if (ctx && s) { 
        ctx->frag_min = s->fragMin; 
        ctx->frag_max = s->fragMax; 
        ctx->frag_delay = s->fragDelay;
        ctx->enable_padding = s->enablePadding;
        ctx->pad_min = s->padMin;
        ctx->pad_max = s->padMax;
    }
}

#define MAX_FRAG_COUNT 32 
#define TLS_HEADER_LEN 5
#define HANDSHAKE_HEADER_LEN 4

// 辅助：获取安全的随机整数 [min, max]
static int get_secure_rand_range(int min, int max) {
    if (min > max) return min;
    if (min == max) return min;
    int range = max - min;
    unsigned char rnd;
    RAND_bytes(&rnd, 1);
    return min + (rnd % (range + 1));
}

// 辅助：手动构造带 Padding 的 ClientHello
// [Safety] 增加更严格的边界检查
static char* inject_padding(const char* in, int in_len, int* out_len, int pad_min, int pad_max) {
    if (in_len < TLS_HEADER_LEN + HANDSHAKE_HEADER_LEN) return NULL;
    
    unsigned char* data = (unsigned char*)in;
    
    // 1. 检查是否为 ClientHello (RecordType=0x16, HandshakeType=0x01)
    if (data[0] != 0x16 || data[5] != 0x01) return NULL; 

    // 2. 解析长度字段
    // Record Length
    int rec_len = (data[3] << 8) | data[4];
    if (rec_len + TLS_HEADER_LEN != in_len) return NULL; // 数据包不完整或有粘包

    // 3. 遍历字段以找到 Extensions
    // Header(5) + HS_Header(4) + Version(2) + Random(32) = 43
    int offset = 43; 
    if (in_len < offset + 1) return NULL;

    // Session ID
    int sess_id_len = data[offset];
    offset += 1 + sess_id_len;
    
    if (in_len < offset + 2) return NULL;
    // Cipher Suites
    int cipher_len = (data[offset] << 8) | data[offset+1];
    offset += 2 + cipher_len;

    if (in_len < offset + 1) return NULL;
    // Compression Methods
    int comp_len = data[offset];
    offset += 1 + comp_len;

    if (in_len < offset + 2) return NULL;
    // Extensions Length Field
    int ext_len_offset = offset;
    int ext_total_len = (data[offset] << 8) | data[offset+1];
    offset += 2;
    
    // 校验：当前偏移量 + 扩展总长度 必须等于 总长度
    if (offset + ext_total_len != in_len) {
        return NULL; // 解析失败，放弃注入
    }

    // 4. 计算 Padding
    int pad_data_len = get_secure_rand_range(pad_min, pad_max);
    if (pad_data_len <= 0) return NULL;

    int pad_ext_len = 4 + pad_data_len; // 2(Type) + 2(Len) + Data
    int new_total_len = in_len + pad_ext_len;

    char* new_buf = (char*)malloc(new_total_len);
    if (!new_buf) return NULL;

    // 5. 复制并拼接
    memcpy(new_buf, in, in_len);
    
    unsigned char* p = (unsigned char*)new_buf + in_len; 

    // 6. 追加 Padding Extension (Type 0x0015 = Padding)
    *p++ = 0x00; *p++ = 0x15;
    *p++ = (pad_data_len >> 8) & 0xFF;
    *p++ = pad_data_len & 0xFF;
    memset(p, 0, pad_data_len);

    // 7. 回填修改长度字段
    unsigned char* ptr = (unsigned char*)new_buf;
    
    // Update Record Length
    int new_rec_len = rec_len + pad_ext_len;
    ptr[3] = (new_rec_len >> 8) & 0xFF;
    ptr[4] = new_rec_len & 0xFF;

    // Update Handshake Length (24-bit)
    int old_hs_len = (ptr[6] << 16) | (ptr[7] << 8) | ptr[8];
    int new_hs_len = old_hs_len + pad_ext_len;
    ptr[6] = (new_hs_len >> 16) & 0xFF;
    ptr[7] = (new_hs_len >> 8) & 0xFF;
    ptr[8] = new_hs_len & 0xFF;

    // Update Extensions Length
    int new_ext_total_len = ext_total_len + pad_ext_len;
    ptr[ext_len_offset] = (new_ext_total_len >> 8) & 0xFF;
    ptr[ext_len_offset+1] = new_ext_total_len & 0xFF;

    *out_len = new_total_len;
    return new_buf;
}

static int frag_write(BIO *b, const char *in, int inl) {
    FragCtx *ctx = (FragCtx *)BIO_get_data(b);
    BIO *next = BIO_next(b);
    if (!ctx || !next) return 0;
    BIO_clear_retry_flags(b);

    const char* send_buf = in;
    int send_len = inl;
    char* alloc_buf = NULL; 

    // [Logic] ClientHello Padding 注入
    if (inl > 0 && ctx->first_packet_sent == 0) {
        if (ctx->enable_padding) {
            int new_len = 0;
            char* padded = inject_padding(in, inl, &new_len, ctx->pad_min, ctx->pad_max);
            if (padded) {
                send_buf = padded;
                send_len = new_len;
                alloc_buf = padded;
            }
        }
        ctx->first_packet_sent = 1; 
    }

    int total_sent = 0;
    
    // [Logic] TLS Record Fragmentation
    if (ctx->frag_min > 0 && ctx->frag_max >= ctx->frag_min) {
        int bytes_processed = 0;
        int remaining = send_len;
        int frag_count = 0;
        
        while (remaining > 0) {
            if (frag_count >= MAX_FRAG_COUNT) {
                // 超过最大分片数，剩余部分一次发送
                int ret = BIO_write(next, send_buf + bytes_processed, remaining);
                if (ret <= 0) { 
                    if (alloc_buf) free(alloc_buf);
                    BIO_copy_next_retry(b); 
                    return (bytes_processed > 0 ? inl : ret); // 如果已发部分数据，返回成功标志
                }
                bytes_processed += ret; 
                remaining -= ret; 
                break;
            }

            int chunk_size = get_secure_rand_range(ctx->frag_min, ctx->frag_max);
            
            if (chunk_size < 1) chunk_size = 1;
            if (chunk_size > remaining) chunk_size = remaining;

            int ret = BIO_write(next, send_buf + bytes_processed, chunk_size);
            if (ret <= 0) { 
                if (alloc_buf) free(alloc_buf);
                BIO_copy_next_retry(b); 
                // 注意：BIO write partial success 处理较复杂，此处简化为尽可能返回已发送量
                return (bytes_processed > 0 ? inl : ret); 
            }
            
            bytes_processed += ret; 
            remaining -= ret; 
            frag_count++;

            if (remaining > 0 && ctx->frag_delay > 0) {
                // [Optimization] 使用系统 Sleep，但在高并发下这会阻塞线程
                // 理想情况应使用异步定时器，但在 BIO 模型中较难实现。
                // 考虑到这是客户端代理，稍微阻塞是可以接受的。
                unsigned char dly; RAND_bytes(&dly, 1);
                Sleep(dly % (ctx->frag_delay + 1));
            }
        }
        total_sent = bytes_processed;
    } else {
        total_sent = BIO_write(next, send_buf, send_len);
    }

    if (alloc_buf) free(alloc_buf);
    
    // 欺骗 OpenSSL 我们只发送了 inl 长度，实际上可能发了更多(Padding)
    if (total_sent > 0) {
        BIO_copy_next_retry(b);
        return inl; 
    }
    
    BIO_copy_next_retry(b);
    return total_sent;
}

static int frag_read(BIO *b, char *out, int outl) {
    BIO *next = BIO_next(b);
    if (!next) return 0;
    BIO_clear_retry_flags(b);
    int ret = BIO_read(next, out, outl);
    BIO_copy_next_retry(b);
    return ret;
}

static long frag_ctrl(BIO *b, int cmd, long num, void *ptr) {
    BIO *next = BIO_next(b);
    if (!next) return 0;
    return BIO_ctrl(next, cmd, num, ptr);
}

// ---------------------- Initialization Logic ----------------------
BOOL CALLBACK InitCryptoCallback(PINIT_ONCE InitOnce, PVOID Parameter, PVOID *Context) {
    SSL_library_init(); 
    OpenSSL_add_all_algorithms(); 
    SSL_load_error_strings();
    
    method_frag = BIO_meth_new(BIO_TYPE_FILTER, "Fragmentation Filter");
    if (method_frag) {
        BIO_meth_set_write(method_frag, frag_write);
        BIO_meth_set_read(method_frag, frag_read);
        BIO_meth_set_ctrl(method_frag, frag_ctrl);
        BIO_meth_set_create(method_frag, frag_new);
        BIO_meth_set_destroy(method_frag, frag_free);
    }

    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_ssl_ctx) {
        log_msg("[Fatal] SSL_CTX_new failed");
        return FALSE;
    }

    SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(g_ssl_ctx, TLS1_3_VERSION);
    
    // [Config] 默认使用 Chrome 常用套件，模拟真实流量
    const char *chrome_ciphers = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA";
    SSL_CTX_set_cipher_list(g_ssl_ctx, chrome_ciphers);
    
    // 禁用 Session Ticket (减少被指纹识别特征)
    SSL_CTX_set_options(g_ssl_ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION | SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(g_ssl_ctx, SSL_SESS_CACHE_OFF);

    // 加载内嵌 CA 证书
    HRSRC hRes = FindResourceW(NULL, MAKEINTRESOURCEW(2), RT_RCDATA);
    if (hRes) {
        HGLOBAL hData = LoadResource(NULL, hRes);
        void* pData = LockResource(hData);
        DWORD dataSize = SizeofResource(NULL, hRes);
        if (pData && dataSize > 0) {
            BIO *cbio = BIO_new_mem_buf(pData, dataSize);
            if (cbio) {
                X509_STORE *cts = SSL_CTX_get_cert_store(g_ssl_ctx);
                X509 *x = NULL;
                int count = 0;
                while ((x = PEM_read_bio_X509(cbio, NULL, 0, NULL)) != NULL) {
                    if (X509_STORE_add_cert(cts, x)) count++;
                    X509_free(x);
                }
                BIO_free(cbio);
                log_msg("[Security] Embedded CA loaded (%d certs).", count);
            }
        }
    }
    return TRUE;
}

void init_crypto_global() {
    InitOnceExecuteOnce(&g_crypto_init_once, InitCryptoCallback, NULL, NULL);
}

void cleanup_crypto_global() {
    if (g_ssl_ctx) { SSL_CTX_free(g_ssl_ctx); g_ssl_ctx = NULL; }
    if (method_frag) { BIO_meth_free(method_frag); method_frag = NULL; }
}

// ---------------------- Connection Logic ----------------------

int tls_init_connect(TLSContext *ctx, const char* target_sni, const char* target_host, const CryptoSettings* settings) {
    if (!g_ssl_ctx) return -1;

    ctx->ssl = SSL_new(g_ssl_ctx);
    if (!ctx->ssl) return -1;
    SSL_set_fd(ctx->ssl, (int)ctx->sock);
    
    // [ECH 处理占位] 生产环境暂建议禁用不稳定 ECH，或需完整实现
    // 此处保留逻辑但建议在 GUI 默认关闭

    // 挂载 Fragmentation/Padding BIO
    BIO *bio = BIO_new_socket(ctx->sock, BIO_NOCLOSE);
    if (method_frag) {
        BIO *frag = BIO_new(method_frag);
        if (frag) {
            BIO_set_params(frag, settings);
            bio = BIO_push(frag, bio);
        }
    }
    
    SSL_set_bio(ctx->ssl, bio, bio);
    
    const char *sni_name = (target_sni && strlen(target_sni)) ? target_sni : target_host;
    SSL_set_tlsext_host_name(ctx->ssl, sni_name);
    
    // 模拟 HTTP/1.1 ALPN
    unsigned char alpn_protos[] = { 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
    SSL_set_alpn_protos(ctx->ssl, alpn_protos, sizeof(alpn_protos));
    
    int ret = SSL_connect(ctx->ssl);
    if (ret != 1) {
        // [Debug] 可选：打印 SSL 错误详情
        // ERR_print_errors_fp(stderr); 
        return -1;
    }
    return 0;
}

// 通用 SSL 读写函数 (处理 WANT_READ/WRITE)
int tls_write(TLSContext *ctx, const char *data, int len) {
    if (!ctx || !ctx->ssl) return -1;
    int written = 0;
    while (written < len) {
        int ret = SSL_write(ctx->ssl, data + written, len - written);
        if (ret > 0) { written += ret; } 
        else {
            int err = SSL_get_error(ctx->ssl, ret);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) { 
                // 简单轮询，生产环境应配合 Select/Epoll
                Sleep(1); 
                continue; 
            }
            return -1; 
        }
    }
    return written;
}

int tls_read(TLSContext *ctx, char *out, int max) {
    if (!ctx || !ctx->ssl) return -1;
    int ret = SSL_read(ctx->ssl, out, max);
    if (ret <= 0) {
        int err = SSL_get_error(ctx->ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return 0;
        return -1;
    }
    return ret;
}

int tls_read_exact(TLSContext *ctx, char *buf, int len) {
    int total = 0;
    while (total < len) {
        int ret = tls_read(ctx, buf + total, len - total);
        if (ret < 0) return 0;
        if (ret == 0) { 
            Sleep(1); // 避免 CPU 空转
            continue; 
        } 
        total += ret;
    }
    return 1;
}

void tls_close(TLSContext *ctx) {
    if (ctx->ssl) { 
        // 快速关闭，不发送 close_notify 以减少延迟（代理场景常见做法）
        SSL_set_quiet_shutdown(ctx->ssl, 1);
        SSL_shutdown(ctx->ssl); 
        SSL_free(ctx->ssl); 
        ctx->ssl = NULL; 
    }
}

// 构建 WebSocket 帧
int build_ws_frame(const char *in, int len, char *out) {
    int idx = 0;
    out[idx++] = (char)0x82; // Binary Frame
    
    unsigned char mask[4];
    RAND_bytes(mask, 4); // [Security] 强随机 Mask
    
    if (len < 126) {
        out[idx++] = (char)(0x80 | len);
    } else if (len <= 65535) {
        out[idx++] = (char)(0x80 | 126);
        out[idx++] = (len >> 8) & 0xFF;
        out[idx++] = len & 0xFF;
    } else {
        out[idx++] = (char)(0x80 | 127);
        // 不支持超大帧 (>4GB)，这里简单填0
        out[idx++] = 0; out[idx++] = 0; out[idx++] = 0; out[idx++] = 0;
        out[idx++] = (len >> 24) & 0xFF;
        out[idx++] = (len >> 16) & 0xFF;
        out[idx++] = (len >> 8) & 0xFF;
        out[idx++] = len & 0xFF;
    }
    memcpy(out + idx, mask, 4); idx += 4;
    for (int i = 0; i < len; i++) out[idx + i] = in[i] ^ mask[i % 4];
    return idx + len;
}

// 检查 WS 帧头
long long check_ws_frame(unsigned char *in, int len, int *head_len, int *payload_len) {
    if(len < 2) return 0;
    int hl = 2; 
    unsigned long long pl = in[1] & 0x7F;
    if (pl == 126) { if (len < 4) return 0; hl = 4; pl = ((unsigned long long)in[2] << 8) | in[3]; } 
    else if (pl == 127) { 
        if (len < 10) return 0; hl = 10; pl = 0;
        for(int i = 0; i < 8; i++) pl = (pl << 8) | in[2 + i];
    }
    if (in[1] & 0x80) hl += 4; // Masked? 客户端收到通常不Mask，但也可能
    
    // [Safety] 防止整数溢出或超大帧
    if (pl > 0x800000) return -1; // 限制单帧最大 8MB
    
    if ((unsigned long long)len < (unsigned long long)hl + pl) return 0; 
    *head_len = hl; *payload_len = (int)pl; 
    return (long long)(hl + pl); 
}

int ws_read_payload_exact(TLSContext *tls, char *out_buf, int expected_len) {
    char raw_head[16];
    if (!tls_read_exact(tls, raw_head, 2)) return 0;
    int payload_len = raw_head[1] & 0x7F;
    if (payload_len == 126) {
        if (!tls_read_exact(tls, raw_head + 2, 2)) return 0;
        payload_len = (unsigned char)raw_head[2] << 8 | (unsigned char)raw_head[3];
    }
    if (payload_len < expected_len) return 0;
    if (!tls_read_exact(tls, out_buf, payload_len)) return 0;
    return payload_len;
}

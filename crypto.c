#include "crypto.h"
#include "utils.h"
#include <openssl/rand.h>
#include <openssl/err.h>

// [Fix] g_ssl_ctx 已移动到 globals.c 定义，此处移除定义，仅保留使用
// 全局 BIO 方法 (用于分片)
static BIO_METHOD *method_frag = NULL;
// 仅初始化一次的标志
static INIT_ONCE g_crypto_init_once = INIT_ONCE_STATIC_INIT;

// ---------------------- BIO Fragmentation Implementation ----------------------

// 每个 BIO 实例的私有数据结构
typedef struct {
    int first_packet_sent;
    int frag_min;
    int frag_max;
    int frag_delay;
} FragCtx;

// 前向声明
static int frag_write(BIO *b, const char *in, int inl);
static int frag_read(BIO *b, char *out, int outl);
static long frag_ctrl(BIO *b, int cmd, long num, void *ptr);
static int frag_new(BIO *b);
static int frag_free(BIO *b);

// 获取全局的分片 BIO Method
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
    if (ctx) { 
        free(ctx); 
        BIO_set_data(b, NULL); 
    }
    return 1;
}

// 辅助函数：设置 BIO 实例的分片参数
void BIO_set_frag_params(BIO *b, int min, int max, int delay) {
    FragCtx *ctx = (FragCtx *)BIO_get_data(b);
    if (ctx) {
        ctx->frag_min = min;
        ctx->frag_max = max;
        ctx->frag_delay = delay;
    }
}

#define MAX_FRAG_COUNT 32 

static int frag_write(BIO *b, const char *in, int inl) {
    FragCtx *ctx = (FragCtx *)BIO_get_data(b);
    BIO *next = BIO_next(b);
    if (!ctx || !next) return 0;

    BIO_clear_retry_flags(b);

    // 仅针对第一个数据包进行分片 (TLS Client Hello)
    if (inl > 0 && ctx->first_packet_sent == 0) {
        ctx->first_packet_sent = 1; 
        int bytes_sent = 0;
        int remaining = inl;
        int frag_count = 0;

        while (remaining > 0) {
            // 安全限制：防止分片过多导致服务器拒绝
            if (frag_count >= MAX_FRAG_COUNT) {
                int ret = BIO_write(next, in + bytes_sent, remaining);
                if (ret <= 0) {
                    BIO_copy_next_retry(b);
                    if (bytes_sent > 0) {
                        BIO_clear_retry_flags(b);
                        return bytes_sent;
                    }
                    return ret;
                }
                bytes_sent += ret;
                remaining -= ret;
                break;
            }

            int chunk_size;
            int range = ctx->frag_max - ctx->frag_min;
            if (range < 0) range = 0;
            
            // 使用 OpenSSL 高强度随机数
            unsigned char rnd_byte;
            RAND_bytes(&rnd_byte, 1);
            chunk_size = ctx->frag_min + (range > 0 ? (rnd_byte % (range + 1)) : 0);
            
            if (chunk_size < 1) chunk_size = 1;
            if (chunk_size > remaining) chunk_size = remaining;

            int ret = BIO_write(next, in + bytes_sent, chunk_size);
            if (ret <= 0) {
                BIO_copy_next_retry(b);
                if (bytes_sent > 0) {
                    BIO_clear_retry_flags(b);
                    return bytes_sent;
                }
                return ret;
            }
            bytes_sent += ret;
            remaining -= ret;
            frag_count++;
            
            if (remaining > 0 && ctx->frag_delay > 0) {
                // 使用随机延迟增加指纹混淆
                unsigned char dly_rnd;
                RAND_bytes(&dly_rnd, 1);
                Sleep(dly_rnd % (ctx->frag_delay + 1));
            }
        }
        return bytes_sent;
    }
    
    // 后续数据直接透传
    int ret = BIO_write(next, in, inl);
    BIO_copy_next_retry(b);
    return ret;
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

// 系统回调初始化函数
BOOL CALLBACK InitCryptoCallback(PINIT_ONCE InitOnce, PVOID Parameter, PVOID *Context) {
    SSL_library_init(); 
    OpenSSL_add_all_algorithms(); 
    SSL_load_error_strings();
    
    // 1. 初始化 Fragment BIO Method
    method_frag = BIO_meth_new(BIO_TYPE_FILTER, "Fragmentation Filter");
    if (method_frag) {
        BIO_meth_set_write(method_frag, frag_write);
        BIO_meth_set_read(method_frag, frag_read);
        BIO_meth_set_ctrl(method_frag, frag_ctrl);
        BIO_meth_set_create(method_frag, frag_new);
        BIO_meth_set_destroy(method_frag, frag_free);
    }

    // 2. 初始化全局 SSL CTX
    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_ssl_ctx) {
        log_msg("[Fatal] SSL_CTX_new failed");
        return FALSE;
    }

    // 3. 设置基础 TLS 属性
    SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(g_ssl_ctx, TLS1_3_VERSION);
    
    // 默认 Chrome 120+ 常见加密套件
    const char *chrome_ciphers = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA";
    SSL_CTX_set_cipher_list(g_ssl_ctx, chrome_ciphers);
    SSL_CTX_set_options(g_ssl_ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
    SSL_CTX_set_session_cache_mode(g_ssl_ctx, SSL_SESS_CACHE_CLIENT);

    // 4. 从资源加载 CA 证书 (资源 ID: 2)
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
    
    // 1. 应用 Padding 配置
    if (settings && settings->enablePadding) {
        int range = settings->padMax - settings->padMin;
        if (range < 0) range = 0;
        unsigned char rnd; 
        RAND_bytes(&rnd, 1);
        int blockSize = settings->padMin + (range > 0 ? (rnd % (range + 1)) : 0);
        if (blockSize > 200) blockSize = 200; // 限制最大填充
        if (blockSize > 0) SSL_set_block_padding(ctx->ssl, blockSize);
    }

    BIO *bio = BIO_new_socket(ctx->sock, BIO_NOCLOSE);
    
    // 2. 应用 Fragment 配置
    if (settings && settings->enableFragment && method_frag) {
        BIO *frag = BIO_new(method_frag);
        if (frag) {
            BIO_set_frag_params(frag, settings->fragMin, settings->fragMax, settings->fragDelay);
            bio = BIO_push(frag, bio);
        }
    }
    
    SSL_set_bio(ctx->ssl, bio, bio);
    
    // 3. 设置 SNI
    const char *sni_name = (target_sni && strlen(target_sni)) ? target_sni : target_host;
    SSL_set_tlsext_host_name(ctx->ssl, sni_name);
    
    // 4. 设置 ALPN (模拟 http/1.1)
    unsigned char alpn_protos[] = { 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
    SSL_set_alpn_protos(ctx->ssl, alpn_protos, sizeof(alpn_protos));
    
    int ret = SSL_connect(ctx->ssl);
    if (ret != 1) {
        // 握手失败
        return -1;
    }
    return 0;
}

// [Optimization] 写入数据：使用 select 替代 Sleep，避免 CPU 空转
int tls_write(TLSContext *ctx, const char *data, int len) {
    if (!ctx || !ctx->ssl) return -1;
    int written = 0;
    
    while (written < len) {
        int ret = SSL_write(ctx->ssl, data + written, len - written);
        
        if (ret > 0) { 
            written += ret; 
        } 
        else {
            int err = SSL_get_error(ctx->ssl, ret);
            
            // 处理非阻塞 IO 需要等待的情况
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) { 
                int sock = SSL_get_fd(ctx->ssl);
                fd_set fds; 
                FD_ZERO(&fds); 
                FD_SET(sock, &fds);
                
                struct timeval tv = { 1, 0 }; // 1秒超时
                
                if (err == SSL_ERROR_WANT_WRITE) {
                    select(0, NULL, &fds, NULL, &tv);
                } else {
                    select(0, &fds, NULL, NULL, &tv);
                }
                continue; 
            }
            return -1; 
        }
    }
    return written;
}

// [Optimization] 读取数据：非阻塞模式
int tls_read(TLSContext *ctx, char *out, int max) {
    if (!ctx || !ctx->ssl) return -1;
    
    int ret = SSL_read(ctx->ssl, out, max);
    
    if (ret <= 0) {
        int err = SSL_get_error(ctx->ssl, ret);
        // 如果是暂时无数据或忙，返回 0 供上层循环处理，而非报错
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return 0;
        }
        return -1;
    }
    
    return ret;
}

// [Optimization] 精确读取指定长度 (阻塞直到读完或超时)
int tls_read_exact(TLSContext *ctx, char *buf, int len) {
    int total = 0;
    while (total < len) {
        int ret = tls_read(ctx, buf + total, len - total);
        
        if (ret < 0) return 0; // 错误
        
        if (ret == 0) { 
            // 暂时无数据，使用 select 等待
            int sock = SSL_get_fd(ctx->ssl);
            fd_set rfds, wfds; 
            FD_ZERO(&rfds); 
            FD_ZERO(&wfds);
            
            if (SSL_want_read(ctx->ssl)) FD_SET(sock, &rfds);
            if (SSL_want_write(ctx->ssl)) FD_SET(sock, &wfds);
            
            struct timeval tv = { 1, 0 };
            int n = select(0, &rfds, &wfds, NULL, &tv);
            
            if (n <= 0) return 0; // 超时或错误
            continue; 
        } 
        total += ret;
    }
    return 1;
}

void tls_close(TLSContext *ctx) {
    if (ctx->ssl) { 
        SSL_shutdown(ctx->ssl); 
        SSL_free(ctx->ssl); 
        ctx->ssl = NULL; 
    }
}

// ---------------------- WebSocket Helpers ----------------------

int build_ws_frame(const char *in, int len, char *out) {
    int idx = 0;
    out[idx++] = (char)0x82; // Binary Frame
    
    unsigned char mask[4];
    RAND_bytes(mask, 4); // 使用安全随机数作为掩码

    if (len < 126) {
        out[idx++] = (char)(0x80 | len);
    } else if (len <= 65535) {
        out[idx++] = (char)(0x80 | 126);
        out[idx++] = (len >> 8) & 0xFF;
        out[idx++] = len & 0xFF;
    } else {
        out[idx++] = (char)(0x80 | 127);
        out[idx++] = 0; out[idx++] = 0; out[idx++] = 0; out[idx++] = 0;
        out[idx++] = (len >> 24) & 0xFF;
        out[idx++] = (len >> 16) & 0xFF;
        out[idx++] = (len >> 8) & 0xFF;
        out[idx++] = len & 0xFF;
    }
    
    memcpy(out + idx, mask, 4);
    idx += 4;
    
    for (int i = 0; i < len; i++) {
        out[idx + i] = in[i] ^ mask[i % 4];
    }
    return idx + len;
}

long long check_ws_frame(unsigned char *in, int len, int *head_len, int *payload_len) {
    if(len < 2) return 0;
    
    int hl = 2; 
    unsigned long long pl = in[1] & 0x7F;
    
    if (pl == 126) { 
        if (len < 4) return 0; 
        hl = 4; 
        pl = ((unsigned long long)in[2] << 8) | in[3]; 
    } else if (pl == 127) { 
        if (len < 10) return 0; 
        hl = 10; 
        pl = 0;
        for(int i = 0; i < 8; i++) pl = (pl << 8) | in[2 + i];
    }
    
    if (in[1] & 0x80) hl += 4; // 有 Mask
    
    if (pl > MAX_WS_FRAME_SIZE) return -1; // 帧过大
    if ((unsigned long long)len < (unsigned long long)hl + pl) return 0; // 数据不完整
    
    *head_len = hl; 
    *payload_len = (int)pl; 
    return (long long)(hl + pl); 
}

int ws_read_payload_exact(TLSContext *tls, char *out_buf, int expected_len) {
    char raw_head[16];
    
    // 读取前2字节
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

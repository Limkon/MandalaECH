#include "crypto.h"
#include "common.h"
#include "utils.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

// 全局 SSL 上下文
SSL_CTX *g_ssl_ctx = NULL;

// --- 自定义 BIO：用于分片(Fragment)和填充(Padding) ---
static BIO_METHOD *g_bio_frag_pad_method = NULL;

// BIO 状态结构
typedef struct {
    int fragMin;
    int fragMax;
    int fragDelay; // ms
    int padMin;
    int padMax;
    BOOL enableFrag;
    BOOL enablePad;
} BioFragPadCtx;

// BIO Write 回调：执行分片逻辑
static int bio_frag_pad_write(BIO *b, const char *in, int inl) {
    BioFragPadCtx *ctx = (BioFragPadCtx *)BIO_get_data(b);
    int ret = 0;
    int total_written = 0;
    
    if (!ctx || !ctx->enableFrag || inl <= ctx->fragMax) {
        return BIO_next(b) ? BIO_write(BIO_next(b), in, inl) : 0;
    }

    // 分片发送
    while (total_written < inl) {
        int chunk_size = ctx->fragMin + rand() % (ctx->fragMax - ctx->fragMin + 1);
        if (chunk_size > inl - total_written) chunk_size = inl - total_written;
        
        int n = BIO_write(BIO_next(b), in + total_written, chunk_size);
        if (n <= 0) {
            BIO_clear_retry_flags(b);
            BIO_copy_next_retry(b);
            return (total_written > 0) ? total_written : n;
        }
        total_written += n;
        
        // 分片间延迟
        if (ctx->fragDelay > 0 && total_written < inl) {
            Sleep(ctx->fragDelay);
        }
    }
    return total_written;
}

static int bio_frag_pad_read(BIO *b, char *out, int outl) {
    if (!BIO_next(b)) return 0;
    int ret = BIO_read(BIO_next(b), out, outl);
    BIO_clear_retry_flags(b);
    BIO_copy_next_retry(b);
    return ret;
}

static long bio_frag_pad_ctrl(BIO *b, int cmd, long num, void *ptr) {
    if (!BIO_next(b)) return 0;
    return BIO_ctrl(BIO_next(b), cmd, num, ptr);
}

static int bio_frag_pad_create(BIO *b) {
    BioFragPadCtx *ctx = (BioFragPadCtx *)malloc(sizeof(BioFragPadCtx));
    if (!ctx) return 0;
    memset(ctx, 0, sizeof(BioFragPadCtx));
    BIO_set_data(b, ctx);
    BIO_set_init(b, 1);
    return 1;
}

static int bio_frag_pad_destroy(BIO *b) {
    BioFragPadCtx *ctx = (BioFragPadCtx *)BIO_get_data(b);
    if (ctx) free(ctx);
    BIO_set_data(b, NULL);
    BIO_set_init(b, 0);
    return 1;
}

void InitBioMethod() {
    if (g_bio_frag_pad_method) return;
    g_bio_frag_pad_method = BIO_meth_new(BIO_TYPE_FILTER, "FragPadFilter");
    BIO_meth_set_write(g_bio_frag_pad_method, bio_frag_pad_write);
    BIO_meth_set_read(g_bio_frag_pad_method, bio_frag_pad_read);
    BIO_meth_set_ctrl(g_bio_frag_pad_method, bio_frag_pad_ctrl);
    BIO_meth_set_create(g_bio_frag_pad_method, bio_frag_pad_create);
    BIO_meth_set_destroy(g_bio_frag_pad_method, bio_frag_pad_destroy);
}

// --- ECH 配置辅助 ---
int SetECHConfig(SSL *ssl, const char *ech_config_b64) {
    if (!ech_config_b64 || strlen(ech_config_b64) == 0) return 0;
    
    size_t ech_len = 0;
    unsigned char *ech_bin = Base64Decode(ech_config_b64, &ech_len);
    if (!ech_bin) return 0;

    // OpenSSL 3.0+ / BoringSSL ECH 设置
    // 注意：具体 API 取决于链接的 SSL 库版本，此处假设使用支持 SSL_set1_ech_config_list 的版本
    // 如果编译报错，可能需要检查 OpenSSL 版本或替换为对应的 ECH API
#ifdef SSL_set1_ech_config_list
    int ret = SSL_set1_ech_config_list(ssl, ech_bin, ech_len);
#else
    // 降级或未支持版本的处理
    int ret = 0; 
#endif
    
    free(ech_bin);
    return ret;
}

// --- 全局初始化与清理 ---

void init_crypto_global() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    
    InitBioMethod();

    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_ssl_ctx) {
        log_msg("[Fatal] Failed to create SSL Context");
        return;
    }

    // 设置最小 TLS 版本
    SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(g_ssl_ctx, TLS1_3_VERSION);

    // 加载 CA 证书
    if (SSL_CTX_load_verify_locations(g_ssl_ctx, "cacert.pem", NULL) != 1) {
        log_msg("[Warn] 'cacert.pem' not found. Verification might fail.");
    }
    
    // 默认禁用验证（根据需求，生产环境建议开启 verify）
    SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);
    
    // 优化 Session 复用
    SSL_CTX_set_session_cache_mode(g_ssl_ctx, SSL_SESS_CACHE_CLIENT);
}

void cleanup_crypto_global() {
    if (g_ssl_ctx) SSL_CTX_free(g_ssl_ctx);
    if (g_bio_frag_pad_method) BIO_meth_free(g_bio_frag_pad_method);
    EVP_cleanup();
}

// --- TLS 连接生命周期 ---

int tls_init_connect(TLSContext *ctx, const char *sni, const char *host, CryptoSettings *settings) {
    if (!g_ssl_ctx || !ctx || ctx->sock == INVALID_SOCKET) return -1;

    ctx->ssl = SSL_new(g_ssl_ctx);
    if (!ctx->ssl) return -1;

    // 绑定 Socket
    SSL_set_fd(ctx->ssl, (int)ctx->sock);

    // SNI 设置
    if (sni && strlen(sni) > 0) SSL_set_tlsext_host_name(ctx->ssl, sni);
    else if (host && strlen(host) > 0) SSL_set_tlsext_host_name(ctx->ssl, host);

    // Chrome 指纹模拟 (Cipher Suite 顺序)
    if (settings && settings->enableChromeCiphers) {
        const char *chrome_ciphers = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA";
        SSL_set_cipher_list(ctx->ssl, chrome_ciphers);
    }

    // ECH 设置
    if (g_enableECH && strlen(g_echConfigServer) > 0) {
        // 尝试从缓存或直接使用配置的 ECH Config
        // 这里简化为：如果配置了静态的 ECHConfig 字符串（base64），则应用
        // 实际生产中可能需要先通过 DoH 获取
        // SetECHConfig(ctx->ssl, g_echConfigB64); 
    }

    // 设置抗封锁 BIO 过滤器
    if (settings && (settings->enableFragment || settings->enablePadding)) {
        BIO *ssl_bio = BIO_new(BIO_f_ssl());
        BIO_set_ssl(ssl_bio, ctx->ssl, BIO_CLOSE);
        
        BIO *frag_bio = BIO_new(g_bio_frag_pad_method);
        BioFragPadCtx *bctx = (BioFragPadCtx *)BIO_get_data(frag_bio);
        if (bctx) {
            bctx->enableFrag = settings->enableFragment;
            bctx->fragMin = settings->fragMin;
            bctx->fragMax = settings->fragMax;
            bctx->fragDelay = settings->fragDelay;
            bctx->enablePad = settings->enablePadding;
            bctx->padMin = settings->padMin;
            bctx->padMax = settings->padMax;
        }
        
        // 链式结构: Application -> FragBIO -> SSL_BIO -> Socket
        // 注意：OpenSSL 的 SSL_set_fd 已经设置了底层 socket bio
        // 这里我们需要替换写出的 BIO
        BIO_push(frag_bio, SSL_get_wbio(ctx->ssl));
        SSL_set_wbio(ctx->ssl, frag_bio);
    }

    // 执行握手
    int ret = SSL_connect(ctx->ssl);
    if (ret != 1) {
        int err = SSL_get_error(ctx->ssl, ret);
        // log_msg("[Err] SSL Handshake failed: %d", err);
        return -1;
    }

    return 0;
}

int tls_write(TLSContext *ctx, const void *buf, int num) {
    if (!ctx || !ctx->ssl) return -1;
    return SSL_write(ctx->ssl, buf, num);
}

int tls_read(TLSContext *ctx, void *buf, int num) {
    if (!ctx || !ctx->ssl) return -1;
    int n = SSL_read(ctx->ssl, buf, num);
    if (n < 0) {
        int err = SSL_get_error(ctx->ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            WSASetLastError(WSAEWOULDBLOCK);
        }
    }
    return n;
}

void tls_close(TLSContext *ctx) {
    if (ctx->ssl) {
        // 尝试通过 BIO 发送 Padding (如果开启)
        // 可以在关闭前注入随机垃圾数据来混淆长度，此处略
        
        SSL_shutdown(ctx->ssl);
        SSL_free(ctx->ssl);
        ctx->ssl = NULL;
    }
}

// --- WebSocket 辅助函数 (协议层) ---

long long check_ws_frame(unsigned char *buffer, int len, int *header_len, int *payload_len) {
    if (len < 2) return 0;
    
    int h_len = 2;
    unsigned long long p_len = buffer[1] & 0x7F;
    
    if (p_len == 126) {
        if (len < 4) return 0;
        p_len = (buffer[2] << 8) | buffer[3];
        h_len = 4;
    } else if (p_len == 127) {
        if (len < 10) return 0;
        p_len = 0;
        for (int i = 0; i < 8; i++) p_len = (p_len << 8) | buffer[2 + i];
        h_len = 10;
    }

    // 服务端发回的数据通常没有 Mask，但如果有，需要跳过 Mask Key
    // 标准规定服务端不应 Mask，但为了兼容性检查 Mask 位
    if (buffer[1] & 0x80) h_len += 4; 

    if (p_len > MAX_WS_FRAME_SIZE) return -1; // 帧过大
    if ((long long)len < h_len + (long long)p_len) return 0; // 数据不全

    *header_len = h_len;
    *payload_len = (int)p_len;
    return h_len + (long long)p_len;
}

int build_ws_frame(const char *data, int len, char *out_buf) {
    int header_len = 0;
    unsigned char *p = (unsigned char *)out_buf;
    
    p[0] = 0x82; // Binary Frame, FIN=1
    
    // 客户端发送必须 Mask
    if (len < 126) {
        p[1] = 0x80 | len;
        header_len = 2;
    } else if (len < 65536) {
        p[1] = 0x80 | 126;
        p[2] = (len >> 8) & 0xFF;
        p[3] = len & 0xFF;
        header_len = 4;
    } else {
        p[1] = 0x80 | 127;
        // 仅处理低32位长度，对于超大包应分片，但在本代理场景一般够用
        p[2] = 0; p[3] = 0; p[4] = 0; p[5] = 0;
        p[6] = (len >> 24) & 0xFF;
        p[7] = (len >> 16) & 0xFF;
        p[8] = (len >> 8) & 0xFF;
        p[9] = len & 0xFF;
        header_len = 10;
    }

    // 生成 Mask Key
    unsigned char mask[4];
    *(int*)mask = rand();
    memcpy(p + header_len, mask, 4);
    header_len += 4;

    // Mask 数据并复制
    for (int i = 0; i < len; i++) {
        p[header_len + i] = data[i] ^ mask[i % 4];
    }

    return header_len + len;
}

int ws_read_payload_exact(TLSContext *ctx, char *buf, int len) {
    int total = 0;
    while(total < len) {
        int n = tls_read(ctx, buf + total, len - total);
        if (n <= 0) return total;
        total += n;
    }
    return total;
}

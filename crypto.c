#include "crypto.h"
#include "utils.h"

// ---------------------- BIO Fragmentation Implementation ----------------------
typedef struct {
    int first_packet_sent;
} FragCtx;

static int frag_write(BIO *b, const char *in, int inl);
static int frag_read(BIO *b, char *out, int outl);
static long frag_ctrl(BIO *b, int cmd, long num, void *ptr);
static int frag_new(BIO *b);
static int frag_free(BIO *b);

static BIO_METHOD *method_frag = NULL;

BIO_METHOD *BIO_f_fragment(void) {
    if (method_frag == NULL) {
        method_frag = BIO_meth_new(BIO_TYPE_FILTER, "Fragmentation Filter");
        BIO_meth_set_write(method_frag, frag_write);
        BIO_meth_set_read(method_frag, frag_read);
        BIO_meth_set_ctrl(method_frag, frag_ctrl);
        BIO_meth_set_create(method_frag, frag_new);
        BIO_meth_set_destroy(method_frag, frag_free);
    }
    return method_frag;
}

static int frag_new(BIO *b) {
    FragCtx *ctx = (FragCtx *)malloc(sizeof(FragCtx));
    if(!ctx) return 0;
    ctx->first_packet_sent = 0;
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

static int frag_write(BIO *b, const char *in, int inl) {
    FragCtx *ctx = (FragCtx *)BIO_get_data(b);
    BIO *next = BIO_next(b);
    if (!ctx || !next) return 0;

    // 随机分片逻辑：仅针对握手阶段 (TLS ClientHello)
    // 修复：增加最大分片数限制，防止分片过多导致握手超时
    if (inl > 0 && ctx->first_packet_sent == 0) {
        ctx->first_packet_sent = 1; 

        int bytes_sent = 0;
        int remaining = inl;
        int frag_count = 0;
        const int MAX_FRAGS = 50; // 安全限制：最多切分 50 个包，避免握手太慢

        while (remaining > 0) {
            int chunk_size;

            // 策略：如果已经切了太多包，或者剩余数据量很大，则停止切分直接发送剩余部分
            // 这样既能混淆 SNI (通常在前几百字节)，又能保证握手完成
            if (frag_count >= MAX_FRAGS) {
                chunk_size = remaining;
            } else {
                int range = g_fragSizeMax - g_fragSizeMin;
                if (range < 0) range = 0;
                chunk_size = g_fragSizeMin + (range > 0 ? (rand() % (range + 1)) : 0);
            }
            
            if (chunk_size < 1) chunk_size = 1;
            if (chunk_size > remaining) chunk_size = remaining;

            int ret = BIO_write(next, in + bytes_sent, chunk_size);
            
            // 错误处理：如果底层写入失败
            if (ret <= 0) {
                // 如果之前已经成功发送了一些数据，则返回已发送量，让 OpenSSL 稍后重试剩余部分
                if (bytes_sent > 0) return bytes_sent;
                return ret;
            }

            bytes_sent += ret;
            remaining -= ret;
            frag_count++;

            // 仅在还有剩余数据时延时
            if (remaining > 0 && g_fragDelayMs > 0) {
                 // 使用随机延时，增加混淆
                 Sleep(rand() % (g_fragDelayMs + 1));
            }
        }
        return bytes_sent;
    }
    
    // 非握手阶段或后续数据，直接透传
    return BIO_write(next, in, inl);
}

static int frag_read(BIO *b, char *out, int outl) {
    BIO *next = BIO_next(b);
    if (!next) return 0;
    return BIO_read(next, out, outl);
}

static long frag_ctrl(BIO *b, int cmd, long num, void *ptr) {
    BIO *next = BIO_next(b);
    if (!next) return 0;
    return BIO_ctrl(next, cmd, num, ptr);
}
// ---------------------- End BIO Implementation ----------------------

void FreeGlobalSSLContext() {
    if (g_ssl_ctx) {
        SSL_CTX_free(g_ssl_ctx);
        g_ssl_ctx = NULL;
    }
}

void init_openssl_global() {
    if (g_ssl_ctx) return;
    SSL_library_init(); 
    OpenSSL_add_all_algorithms(); 
    SSL_load_error_strings();
    
    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_ssl_ctx) return;

    SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(g_ssl_ctx, TLS1_3_VERSION);

    if (g_enableChromeCiphers) {
        const char *chrome_ciphers = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA";
        SSL_CTX_set_cipher_list(g_ssl_ctx, chrome_ciphers);
        SSL_CTX_set_options(g_ssl_ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
        SSL_CTX_set_session_cache_mode(g_ssl_ctx, SSL_SESS_CACHE_CLIENT);
        log_msg("[Security] Chrome Cipher Suites Enabled");
    } else {
        log_msg("[Security] Standard OpenSSL Cipher Suites");
    }

    // 从资源载入证书 (ID: 2, Type: RT_RCDATA)
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

                if (count > 0) {
                    SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_PEER, NULL);
                    log_msg("[Security] Embedded CA loaded (%d certs). Strict mode.", count);
                } else {
                    SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);
                    log_msg("[Warning] Embedded CA data invalid. Insecure mode.");
                }
            } else {
                SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);
                log_msg("[Warning] Failed to create BIO for CA. Insecure mode.");
            }
        } else {
            SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);
            log_msg("[Warning] Empty CA resource. Insecure mode.");
        }
    } else {
        SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);
        log_msg("[Warning] cacert.pem resource not found in exe. Insecure mode.");
    }
}

int tls_init_connect(TLSContext *ctx) {
    ctx->ssl = SSL_new(g_ssl_ctx);
    
    // Padding 设置
    if (g_enablePadding) {
        int range = g_padSizeMax - g_padSizeMin;
        if (range < 0) range = 0;
        int blockSize = g_padSizeMin + (range > 0 ? (rand() % (range + 1)) : 0);
        if (blockSize > 0) {
            SSL_set_block_padding(ctx->ssl, blockSize);
        }
    }

    BIO *bio = BIO_new_socket(ctx->sock, BIO_NOCLOSE);
    
    // 挂载分片 BIO
    if (g_enableFragment) {
        BIO *frag = BIO_new(BIO_f_fragment());
        bio = BIO_push(frag, bio);
    }
    
    SSL_set_bio(ctx->ssl, bio, bio);
    
    const char *sni_name = (strlen(g_proxyConfig.sni) ? g_proxyConfig.sni : g_proxyConfig.host);
    SSL_set_tlsext_host_name(ctx->ssl, sni_name);
    
    if (g_enableALPN) {
        unsigned char alpn_protos[] = { 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
        SSL_set_alpn_protos(ctx->ssl, alpn_protos, sizeof(alpn_protos));
    }

    return (SSL_connect(ctx->ssl) == 1) ? 0 : -1;
}

int tls_write(TLSContext *ctx, const char *data, int len) {
    if (!ctx->ssl) return -1;
    int written = 0;
    while (written < len) {
        int ret = SSL_write(ctx->ssl, data + written, len - written);
        if (ret > 0) { written += ret; } 
        else {
            int err = SSL_get_error(ctx->ssl, ret);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) { Sleep(1); continue; }
            return -1; 
        }
    }
    return written;
}

int tls_read(TLSContext *ctx, char *out, int max) {
    if (!ctx->ssl) return -1;
    int ret = SSL_read(ctx->ssl, out, max);
    if (ret <= 0) {
        int err = SSL_get_error(ctx->ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return 0;
        if (err == SSL_ERROR_ZERO_RETURN) return -1;
        return -1;
    }
    return ret;
}

int tls_read_exact(TLSContext *ctx, char *buf, int len) {
    int total = 0;
    while (total < len) {
        int ret = tls_read(ctx, buf + total, len - total);
        if (ret < 0) return 0; 
        if (ret == 0) { Sleep(1); continue; } 
        total += ret;
    }
    return 1;
}

void tls_close(TLSContext *ctx) {
    if (ctx->ssl) { SSL_shutdown(ctx->ssl); SSL_free(ctx->ssl); ctx->ssl = NULL; }
}

int build_ws_frame(const char *in, int len, char *out) {
    out[0] = 0x82; uint8_t mask[4]; *(uint32_t*)mask = GetTickCount(); 
    if (len < 126) { out[1] = 0x80 | len; memcpy(out+2, mask, 4); for(int i=0;i<len;i++) out[6+i] = in[i]^mask[i%4]; return 6+len; } 
    else if (len <= 65535) { out[1] = 0x80 | 126; out[2] = (len>>8)&0xFF; out[3] = len&0xFF; memcpy(out+4, mask, 4); for(int i=0;i<len;i++) out[8+i] = in[i]^mask[i%4]; return 8+len; }
    return -1; 
}

int check_ws_frame(unsigned char *in, int len, int *head_len, int *payload_len) {
    if(len < 2) return 0;
    int hl = 2; int pl = in[1] & 0x7F;
    if (pl == 126) { if (len < 4) return 0; hl = 4; pl = (in[2] << 8) | in[3]; } 
    else if (pl == 127) { if (len < 10) return 0; hl = 10; pl = 65536; }
    if (len < hl + pl) return 0;
    *head_len = hl; *payload_len = pl;
    return hl + pl; 
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

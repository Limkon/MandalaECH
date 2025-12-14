#include "crypto.h"
#include "utils.h"
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>

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

#define MAX_FRAG_COUNT 32 

static int frag_write(BIO *b, const char *in, int inl) {
    FragCtx *ctx = (FragCtx *)BIO_get_data(b);
    BIO *next = BIO_next(b);
    if (!ctx || !next) return 0;

    BIO_clear_retry_flags(b);

    if (inl > 0 && ctx->first_packet_sent == 0) {
        ctx->first_packet_sent = 1; 
        int bytes_sent = 0;
        int remaining = inl;
        int frag_count = 0;

        while (remaining > 0) {
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
            int range = g_fragSizeMax - g_fragSizeMin;
            if (range < 0) range = 0;
            chunk_size = g_fragSizeMin + (range > 0 ? (rand() % (range + 1)) : 0);
            
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
            if (remaining > 0 && g_fragDelayMs > 0) Sleep(rand() % (g_fragDelayMs + 1));
        }
        return bytes_sent;
    }
    
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
// ---------------------- End BIO Implementation ----------------------

extern SSL_CTX *g_ssl_ctx; 

void FreeGlobalSSLContext() {
    if (g_ssl_ctx) { SSL_CTX_free(g_ssl_ctx); g_ssl_ctx = NULL; }
}

void init_openssl_global() {
    if (g_ssl_ctx) return;
    SSL_library_init(); 
    OpenSSL_add_all_algorithms(); 
    SSL_load_error_strings();
    
    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_ssl_ctx) {
        log_msg("[Fatal] SSL_CTX_new failed");
        return;
    }

    SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(g_ssl_ctx, TLS1_3_VERSION);

    if (g_enableChromeCiphers) {
        const char *chrome_ciphers = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA";
        if (SSL_CTX_set_cipher_list(g_ssl_ctx, chrome_ciphers) != 1) {
             log_msg("[Warning] Failed to set Chrome ciphers");
        }
        SSL_CTX_set_options(g_ssl_ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
        SSL_CTX_set_session_cache_mode(g_ssl_ctx, SSL_SESS_CACHE_CLIENT);
        log_msg("[Security] Chrome Cipher Suites Enabled");
    } else {
        log_msg("[Security] Standard OpenSSL Cipher Suites");
    }

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
    if (!g_ssl_ctx) init_openssl_global();
    ctx->ssl = SSL_new(g_ssl_ctx);
    if (!ctx->ssl) {
        log_msg("[Err] SSL_new failed");
        return -1;
    }
    SSL_set_fd(ctx->ssl, (int)ctx->sock);
    
    if (g_enablePadding) {
        int range = g_padSizeMax - g_padSizeMin;
        if (range < 0) range = 0;
        int blockSize = g_padSizeMin + (range > 0 ? (rand() % (range + 1)) : 0);
        if (blockSize > 200) blockSize = 200; 
        if (blockSize > 0) SSL_set_block_padding(ctx->ssl, blockSize);
    }

    BIO *bio = BIO_new_socket(ctx->sock, BIO_NOCLOSE);
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
    
    log_msg("[Debug] SSL_connect starting to %s...", sni_name);
    int ret = SSL_connect(ctx->ssl);
    if (ret == 1) {
        log_msg("[Debug] SSL_connect Success. Cipher: %s", SSL_get_cipher_name(ctx->ssl));
        return 0;
    } else {
        int err = SSL_get_error(ctx->ssl, ret);
        unsigned long e = ERR_get_error();
        log_msg("[Debug] SSL_connect Fail. Ret: %d, SSL Err: %d, Sys Err: %lu", ret, err, e);
        // [New] Print OpenSSL Error Stack
        char err_buf[256];
        ERR_error_string_n(e, err_buf, sizeof(err_buf));
        log_msg("[Debug] OpenSSL Error: %s", err_buf);
        return -1;
    }
}

int tls_write(TLSContext *ctx, const char *data, int len) {
    if (!ctx || !ctx->ssl) return -1;
    int written = 0;
    while (written < len) {
        int ret = SSL_write(ctx->ssl, data + written, len - written);
        if (ret > 0) { written += ret; } 
        else {
            int err = SSL_get_error(ctx->ssl, ret);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) { Sleep(1); continue; }
            log_msg("[Error] SSL_write failed. Error: %d", err);
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
        if (err == SSL_ERROR_ZERO_RETURN) return -1; // Connection closed gracefully
        
        // [New] Log Syscall/SSL Errors
        if (err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL) {
             unsigned long e = ERR_get_error();
             if (e != 0) {
                 char err_buf[256];
                 ERR_error_string_n(e, err_buf, sizeof(err_buf));
                 log_msg("[Error] SSL_read Error: %s", err_buf);
             }
        }
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
    int idx = 0;
    out[idx++] = (char)0x82; 

    unsigned char mask[4];
    for(int i=0; i<4; i++) mask[i] = (unsigned char)(rand() & 0xFF);

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
    } 
    else if (pl == 127) { 
        if (len < 10) return 0; 
        hl = 10; 
        pl = 0;
        for(int i = 0; i < 8; i++) {
            pl = (pl << 8) | in[2 + i];
        }
    }
    
    if (in[1] & 0x80) hl += 4; 

    if (pl > BUFFER_SIZE) {
        log_msg("[Err] WS Frame too large: %llu (Max: %d). Dropping connection.", pl, BUFFER_SIZE);
        return -1; 
    }

    if ((unsigned long long)len < (unsigned long long)hl + pl) return 0;
    
    *head_len = hl; 
    *payload_len = (int)pl; 
    
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

// --- VMess Crypto Implementation (EVP) ---

void crypto_md5(const unsigned char *d, size_t n, unsigned char *md) {
    unsigned int md_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx) {
        EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
        EVP_DigestUpdate(ctx, d, n);
        EVP_DigestFinal_ex(ctx, md, &md_len);
        EVP_MD_CTX_free(ctx);
    }
}

// SHA224 for Trojan
void crypto_sha224(const char *data, size_t len, unsigned char *md) {
    unsigned int md_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx) {
        EVP_DigestInit_ex(ctx, EVP_sha224(), NULL);
        EVP_DigestUpdate(ctx, data, len);
        EVP_DigestFinal_ex(ctx, md, &md_len);
        EVP_MD_CTX_free(ctx);
    }
}

void vmess_get_auth(const unsigned char *uuid, long long ts, unsigned char *out_auth) {
    unsigned char buf[24];
    memcpy(buf, uuid, 16);
    for(int i=0; i<8; i++) buf[16+i] = (ts >> ((7-i)*8)) & 0xFF;
    crypto_md5(buf, 24, out_auth);
}

void vmess_kdf_header(const unsigned char *uuid, unsigned char *out_key, unsigned char *out_iv) {
    unsigned char k_buf[16 + 36];
    memcpy(k_buf, uuid, 16);
    memcpy(k_buf + 16, "c48619fe-8f02-49e0-b9e9-edf763e17e21", 36);
    crypto_md5(k_buf, 52, out_key);
}

void vmess_kdf_iv(long long ts, unsigned char *out_iv) {
    unsigned char t_buf[32];
    unsigned char ts_bytes[8];
    for(int i=0; i<8; i++) ts_bytes[i] = (ts >> ((7-i)*8)) & 0xFF;
    memcpy(t_buf, ts_bytes, 8);
    memcpy(t_buf+8, ts_bytes, 8);
    memcpy(t_buf+16, ts_bytes, 8);
    memcpy(t_buf+24, ts_bytes, 8);
    crypto_md5(t_buf, 32, out_iv);
}

unsigned int fnv1a_hash(const unsigned char *data, int len) {
    unsigned int prime = 16777619;
    unsigned int hash = 2166136261;
    for(int i=0;i<len;i++) {
        hash ^= data[i];
        hash *= prime;
    }
    return hash;
}

// AES-128-CFB Implementation using EVP
void aes_cfb128_init(AesCfbCtx *ctx, const unsigned char *key, const unsigned char *iv, int is_encrypt) {
    ctx->ctx = EVP_CIPHER_CTX_new();
    ctx->is_valid = (ctx->ctx != NULL);
    if (ctx->is_valid) {
        EVP_CipherInit_ex(ctx->ctx, EVP_aes_128_cfb(), NULL, key, iv, is_encrypt);
    }
}

void aes_cfb128_encrypt(AesCfbCtx *ctx, const unsigned char *in, unsigned char *out, size_t len) {
    if (!ctx->is_valid) return;
    int outl;
    EVP_CipherUpdate(ctx->ctx, out, &outl, in, (int)len);
}

void aes_cfb128_decrypt(AesCfbCtx *ctx, const unsigned char *in, unsigned char *out, size_t len) {
    if (!ctx->is_valid) return;
    int outl;
    EVP_CipherUpdate(ctx->ctx, out, &outl, in, (int)len);
}

void aes_cfb128_cleanup(AesCfbCtx *ctx) {
    if (ctx->is_valid && ctx->ctx) {
        EVP_CIPHER_CTX_free(ctx->ctx);
        ctx->ctx = NULL;
        ctx->is_valid = 0;
    }
}

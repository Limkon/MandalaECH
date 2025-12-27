#include "crypto.h"
#include "utils.h"
#include "common.h"
#include "proxy.h" 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>

// [Fix] 直接定义全局变量，而不是引用 extern
SSL_CTX *g_ssl_ctx = NULL;

static BIO_METHOD *method_frag = NULL;
static INIT_ONCE g_crypto_init_once = INIT_ONCE_STATIC_INIT;

typedef struct {
    int first_packet_sent;
    int frag_min;
    int frag_max;
    int frag_delay;
    int enable_padding;
    int pad_min;
    int pad_max;
} FragCtx;

static int frag_write(BIO *b, const char *in, int inl);
static int frag_read(BIO *b, char *out, int outl);
static long frag_ctrl(BIO *b, int cmd, long num, void *ptr);
static int frag_new(BIO *b);
static int frag_free(BIO *b);

BIO_METHOD *BIO_f_fragment(void) { return method_frag; }

static int frag_new(BIO *b) {
    FragCtx *ctx = (FragCtx *)Proxy_Malloc(sizeof(FragCtx));
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
        Proxy_Free(ctx, sizeof(FragCtx)); 
        BIO_set_data(b, NULL); 
    }
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

static char* inject_padding(const char* in, int in_len, int* out_len, int pad_min, int pad_max) {
    if (in_len < TLS_HEADER_LEN + HANDSHAKE_HEADER_LEN) return NULL;
    unsigned char* data = (unsigned char*)in;
    if (data[0] != 0x16) return NULL; 
    if (data[5] != 0x01) return NULL;

    int offset = 43; 
    if (in_len < offset + 1) return NULL;
    
    int sess_id_len = data[offset];
    offset += 1 + sess_id_len;
    if (in_len < offset + 2) return NULL;
    
    int cipher_len = (data[offset] << 8) | data[offset+1];
    offset += 2 + cipher_len;
    if (in_len < offset + 1) return NULL;
    
    int comp_len = data[offset];
    offset += 1 + comp_len;
    if (in_len < offset + 2) return NULL;
    
    int ext_len_offset = offset;
    int ext_total_len = (data[offset] << 8) | data[offset+1];
    offset += 2;
    
    if (offset + ext_total_len != in_len - TLS_HEADER_LEN) return NULL;

    int range = pad_max - pad_min;
    if (range < 0) range = 0;
    unsigned char rnd; RAND_bytes(&rnd, 1);
    int pad_data_len = pad_min + (range > 0 ? (rnd % (range + 1)) : 0);
    if (pad_data_len <= 0) return NULL;

    int pad_ext_len = 4 + pad_data_len;
    int new_total_len = in_len + pad_ext_len;
    
    char* new_buf = (char*)Proxy_Malloc(new_total_len);
    if (!new_buf) return NULL;

    memcpy(new_buf, in, in_len);
    unsigned char* p = (unsigned char*)new_buf + in_len;
    *p++ = 0x00; *p++ = 0x15; 
    *p++ = (pad_data_len >> 8) & 0xFF;
    *p++ = pad_data_len & 0xFF;
    memset(p, 0, pad_data_len);

    unsigned char* ptr = (unsigned char*)new_buf;
    int old_rec_len = (ptr[3] << 8) | ptr[4];
    int new_rec_len = old_rec_len + pad_ext_len;
    ptr[3] = (new_rec_len >> 8) & 0xFF;
    ptr[4] = new_rec_len & 0xFF;
    
    int old_hs_len = (ptr[6] << 16) | (ptr[7] << 8) | ptr[8];
    int new_hs_len = old_hs_len + pad_ext_len;
    ptr[6] = (new_hs_len >> 16) & 0xFF;
    ptr[7] = (new_hs_len >> 8) & 0xFF;
    ptr[8] = new_hs_len & 0xFF;
    
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

    if (inl > 0 && ctx->first_packet_sent == 0) {
        if (ctx->enable_padding && !g_enableECH) {
            int new_len = 0;
            char* padded = inject_padding(in, inl, &new_len, ctx->pad_min, ctx->pad_max);
            if (padded) {
                send_buf = padded;
                send_len = new_len;
                alloc_buf = padded;
                log_msg("[TLS] Padding injected: +%d bytes", new_len - inl);
            }
        }
        ctx->first_packet_sent = 1; 
    }

    int total_sent = 0;
    if (ctx->frag_min > 0 && ctx->frag_max >= ctx->frag_min) {
        int bytes_processed = 0;
        int remaining = send_len;
        int frag_count = 0;
        
        while (remaining > 0) {
            if (frag_count >= MAX_FRAG_COUNT) {
                int ret = BIO_write(next, send_buf + bytes_processed, remaining);
                if (ret <= 0) { 
                    if (alloc_buf) Proxy_Free(alloc_buf, send_len); 
                    BIO_copy_next_retry(b); 
                    return (bytes_processed > 0 ? (alloc_buf ? inl : bytes_processed) : ret); 
                }
                bytes_processed += ret; remaining -= ret; break;
            }
            int range = ctx->frag_max - ctx->frag_min; 
            if (range < 0) range = 0;
            unsigned char rnd_byte; RAND_bytes(&rnd_byte, 1);
            int chunk_size = ctx->frag_min + (range > 0 ? (rnd_byte % (range + 1)) : 0);
            if (chunk_size < 1) chunk_size = 1;
            if (chunk_size > remaining) chunk_size = remaining;
            
            int ret = BIO_write(next, send_buf + bytes_processed, chunk_size);
            if (ret <= 0) { 
                if (alloc_buf) Proxy_Free(alloc_buf, send_len); 
                BIO_copy_next_retry(b); 
                return (bytes_processed > 0 ? (alloc_buf ? inl : bytes_processed) : ret); 
            }
            bytes_processed += ret; remaining -= ret; frag_count++;
            
            if (remaining > 0 && ctx->frag_delay > 0) {
                unsigned char dly_rnd; RAND_bytes(&dly_rnd, 1);
                Sleep(dly_rnd % (ctx->frag_delay + 1));
            }
        }
        total_sent = bytes_processed;
    } else {
        total_sent = BIO_write(next, send_buf, send_len);
    }
    if (alloc_buf) Proxy_Free(alloc_buf, send_len); 
    
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
    
    const char *chrome_ciphers = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA";
    SSL_CTX_set_cipher_list(g_ssl_ctx, chrome_ciphers);

    const char *tls13_ciphers = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";
    if (SSL_CTX_set_ciphersuites(g_ssl_ctx, tls13_ciphers) != 1) {
         log_msg("[Warn] Failed to set TLS 1.3 ciphersuites");
    }

    SSL_CTX_set_options(g_ssl_ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION | SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
    SSL_CTX_set_session_cache_mode(g_ssl_ctx, SSL_SESS_CACHE_CLIENT);

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

int tls_init_connect(TLSContext *ctx, const char* target_sni, const char* target_host, const CryptoSettings* settings) {
    if (!g_ssl_ctx) return -1;

    ctx->ssl = SSL_new(g_ssl_ctx);
    if (!ctx->ssl) return -1;
    
    const char *sni_name = (target_sni && strlen(target_sni)) ? target_sni : target_host;
    SSL_set_tlsext_host_name(ctx->ssl, sni_name);

    unsigned char alpn_protos[] = { 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
    SSL_set_alpn_protos(ctx->ssl, alpn_protos, sizeof(alpn_protos));

    if (g_enableECH) {
        SSL_set_min_proto_version(ctx->ssl, TLS1_3_VERSION);
        SSL_set_max_proto_version(ctx->ssl, TLS1_3_VERSION);

        const char* query_domain = (g_echPublicName && strlen(g_echPublicName)) ? g_echPublicName : sni_name;
        size_t ech_len = 0;
        unsigned char* ech_config = FetchECHConfig(query_domain, g_echConfigServer, &ech_len);
        
        if (ech_config && ech_len > 0) {
            if (SSL_set1_ech_config_list(ctx->ssl, ech_config, ech_len) != 1) {
                 log_msg("[ECH] Failed to set ECH config for %s", query_domain);
            } else {
                 log_msg("[ECH] Config set for %s (len=%d)", query_domain, ech_len);
            }
            Proxy_Free(ech_config, ech_len);
        } else {
            log_msg("[ECH] No config found for %s, fallback to plain TLS", query_domain);
        }
    }

    BIO *internal_bio = BIO_new_socket((int)ctx->sock, BIO_NOCLOSE);
    if (!internal_bio) { SSL_free(ctx->ssl); ctx->ssl = NULL; return -1; }

    if (method_frag && !g_enableECH) {
        BIO *frag_bio = BIO_new(method_frag);
        if (frag_bio) {
            BIO_set_params(frag_bio, settings);
            BIO_push(frag_bio, internal_bio); 
            SSL_set_bio(ctx->ssl, frag_bio, frag_bio);
        } else {
            SSL_set_bio(ctx->ssl, internal_bio, internal_bio);
        }
    } else {
        SSL_set_bio(ctx->ssl, internal_bio, internal_bio);
    }
    
    int ret = SSL_connect(ctx->ssl);
    if (ret != 1) {
        int err_code = SSL_get_error(ctx->ssl, ret);
        log_msg("[Fatal] SSL_connect failed: ret=%d, ssl_err=%d", ret, err_code);
        unsigned long l;
        while ((l = ERR_get_error()) != 0) {
            char buf[256];
            ERR_error_string_n(l, buf, sizeof(buf));
            log_msg("[OpenSSL] %s", buf);
        }
        return -1;
    }
    return 0;
}

int tls_write(TLSContext *ctx, const char *data, int len) {
    if (!ctx || !ctx->ssl) return -1;
    int written = 0;
    while (written < len) {
        int ret = SSL_write(ctx->ssl, data + written, len - written);
        if (ret > 0) { written += ret; } 
        else {
            int err = SSL_get_error(ctx->ssl, ret);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) { 
                int sock = SSL_get_fd(ctx->ssl);
                fd_set fds; FD_ZERO(&fds); FD_SET(sock, &fds);
                struct timeval tv = { 1, 0 };
                if (err == SSL_ERROR_WANT_WRITE) select(0, NULL, &fds, NULL, &tv);
                else select(0, &fds, NULL, NULL, &tv);
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
            int sock = SSL_get_fd(ctx->ssl);
            fd_set rfds, wfds; FD_ZERO(&rfds); FD_ZERO(&wfds);
            if (SSL_want_read(ctx->ssl)) FD_SET(sock, &rfds);
            if (SSL_want_write(ctx->ssl)) FD_SET(sock, &wfds);
            struct timeval tv = { 1, 0 };
            int n = select(0, &rfds, &wfds, NULL, &tv);
            if (n <= 0) return 0;
            continue; 
        } 
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
    RAND_bytes(mask, 4); 
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
    memcpy(out + idx, mask, 4); idx += 4;
    for (int i = 0; i < len; i++) out[idx + i] = in[i] ^ mask[i % 4];
    return idx + len;
}

long long check_ws_frame(unsigned char *in, int len, int *head_len, int *payload_len) {
    if(len < 2) return 0;
    int hl = 2; 
    unsigned long long pl = in[1] & 0x7F;
    if (pl == 126) { if (len < 4) return 0; hl = 4; pl = ((unsigned long long)in[2] << 8) | in[3]; } 
    else if (pl == 127) { 
        if (len < 10) return 0; hl = 10; pl = 0;
        for(int i = 0; i < 8; i++) pl = (pl << 8) | in[2 + i];
    }
    if (in[1] & 0x80) hl += 4; 
    if (pl > MAX_WS_FRAME_SIZE) return -1; 
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

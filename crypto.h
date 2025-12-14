#ifndef CRYPTO_H
#define CRYPTO_H

#include "common.h"
#include <openssl/evp.h>

// 初始化与清理
void init_openssl_global();
void FreeGlobalSSLContext();

// TLS 连接相关
int tls_init_connect(TLSContext *ctx);
int tls_write(TLSContext *ctx, const char *data, int len);
int tls_read(TLSContext *ctx, char *out, int max);
int tls_read_exact(TLSContext *ctx, char *buf, int len);
void tls_close(TLSContext *ctx);

// WebSocket 协议辅助
int build_ws_frame(const char *in, int len, char *out);
long long check_ws_frame(unsigned char *in, int len, int *head_len, int *payload_len);
int ws_read_payload_exact(TLSContext *tls, char *out_buf, int expected_len);

// --- VMess/Trojan 协议加密辅助函数 (EVP Based) ---
void crypto_md5(const unsigned char *d, size_t n, unsigned char *md);
void crypto_sha224(const char *data, size_t len, unsigned char *md); 

void vmess_get_auth(const unsigned char *uuid, long long ts, unsigned char *out_auth);
void vmess_kdf_header(const unsigned char *uuid, unsigned char *out_key, unsigned char *out_iv);
void vmess_kdf_iv(long long ts, unsigned char *out_iv);
unsigned int fnv1a_hash(const unsigned char *data, int len);

// AES-128-CFB 上下文 (使用 EVP_CIPHER_CTX)
typedef struct {
    EVP_CIPHER_CTX *ctx;
    int is_valid;
} AesCfbCtx;

// is_encrypt: 1 为加密，0 为解密
void aes_cfb128_init(AesCfbCtx *ctx, const unsigned char *key, const unsigned char *iv, int is_encrypt);
void aes_cfb128_encrypt(AesCfbCtx *ctx, const unsigned char *in, unsigned char *out, size_t len);
void aes_cfb128_decrypt(AesCfbCtx *ctx, const unsigned char *in, unsigned char *out, size_t len);
void aes_cfb128_cleanup(AesCfbCtx *ctx); 

#endif // CRYPTO_H

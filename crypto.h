#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/ssl.h>
#include <openssl/bio.h>

// 前向声明，确保编译器识别该类型
typedef struct CryptoSettings CryptoSettings;

typedef struct {
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    int fd;
} TLSContext;

// 函数声明
int tls_init_connect(TLSContext *ctx, const char* target_sni, const char* target_host, const CryptoSettings* settings);
void BIO_set_params(BIO *b, const CryptoSettings *s);

#endif

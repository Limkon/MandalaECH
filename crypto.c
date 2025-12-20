#include "crypto.h"
#include "utils.h"
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

extern BOOL g_enableALPN;
extern BOOL g_enableLog;

// --------------------------------------------------------------------------
// 全局清理
// --------------------------------------------------------------------------
void tls_cleanup_global() {
    EVP_cleanup();
}

// --------------------------------------------------------------------------
// TLS 连接初始化 (修复了 ECH 顺序)
// --------------------------------------------------------------------------
int tls_init_connect(TLSContext *ctx, const char *sni, const char *host, const char *ech_config_b64) {
    if (!ctx) return -1;

    // 1. 创建 CTX
    ctx->ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx->ctx) {
        log_msg("[Error] SSL_CTX_new failed");
        return -1;
    }

    // 设置协议版本
    SSL_CTX_set_min_proto_version(ctx->ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx->ctx, TLS1_3_VERSION);
    
    // 暂时禁用证书验证 (生产环境请开启)
    SSL_CTX_set_verify(ctx->ctx, SSL_VERIFY_NONE, NULL);

    // 设置 ALPN
    if (g_enableALPN) {
        unsigned char alpn[] = { 
            2, 'h', '2', 
            8, 'h', 't', 't', 'p', '/', '1', '.', '1' 
        };
        SSL_CTX_set_alpn_protos(ctx->ctx, alpn, sizeof(alpn));
    }

    // 2. 创建 SSL
    ctx->ssl = SSL_new(ctx->ctx);
    if (!ctx->ssl) {
        log_msg("[Error] SSL_new failed");
        SSL_CTX_free(ctx->ctx);
        ctx->ctx = NULL;
        return -1;
    }

    // 3. 绑定 Socket
    SSL_set_fd(ctx->ssl, (int)ctx->sock);

    // 4. 设置 SNI (Inner SNI - 真实 Worker 域名)
    // 注意：OpenSSL ECH 文档要求，这里设置的是 Inner SNI
    const char* target_sni = (sni && strlen(sni) > 0) ? sni : host;
    if (target_sni && strlen(target_sni) > 0) {
        SSL_set_tlsext_host_name(ctx->ssl, target_sni);
    }

    // 5. 设置 ECH (Outer SNI 由此自动处理)
    if (ech_config_b64 && strlen(ech_config_b64) > 0) {
        size_t ech_len = 0;
        unsigned char *ech_bin = Base64Decode(ech_config_b64, &ech_len);
        
        if (ech_bin && ech_len > 0) {
            int ret = SSL_set1_ech_config_list(ctx->ssl, ech_bin, ech_len);
            if (ret != 1) {
                // 如果 ECH 设置失败，记录错误但允许尝试普通连接
                log_msg("[Error] SSL_set1_ech_config_list failed. Err: %s", ERR_error_string(ERR_get_error(), NULL));
            }
            free(ech_bin);
        }
    }

    // 6. 执行握手
    int ret = SSL_connect(ctx->ssl);
    if (ret != 1) {
        int err = SSL_get_error(ctx->ssl, ret);
        int sys_err = WSAGetLastError();
        unsigned long ssl_err_code = ERR_get_error();
        
        log_msg("[Debug] SSL_connect Fail. Ret: %d, SSL Err: %d, Sys Err: %d", ret, err, sys_err);
        log_msg("[Debug] OpenSSL Error String: %s", ERR_error_string(ssl_err_code, NULL));
        
        tls_close(ctx);
        return -1;
    }

    return 0;
}

// --------------------------------------------------------------------------
// 资源释放
// --------------------------------------------------------------------------
void tls_close(TLSContext *ctx) {
    if (!ctx) return;
    if (ctx->ssl) {
        SSL_shutdown(ctx->ssl); 
        SSL_free(ctx->ssl);
        ctx->ssl = NULL;
    }
    if (ctx->ctx) {
        SSL_CTX_free(ctx->ctx);
        ctx->ctx = NULL;
    }
}

// --------------------------------------------------------------------------
// 读写操作
// --------------------------------------------------------------------------
int tls_read(TLSContext *ctx, char *buf, int len) {
    if (!ctx || !ctx->ssl) return -1;
    int n = SSL_read(ctx->ssl, buf, len);
    if (n <= 0) {
        int err = SSL_get_error(ctx->ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return 0;
        return -1; 
    }
    return n;
}

int tls_write(TLSContext *ctx, const char *buf, int len) {
    if (!ctx || !ctx->ssl) return -1;
    int n = SSL_write(ctx->ssl, buf, len);
    if (n <= 0) {
        int err = SSL_get_error(ctx->ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return 0;
        return -1;
    }
    return n;
}

// --------------------------------------------------------------------------
// WebSocket 辅助
// --------------------------------------------------------------------------
int build_ws_frame(const char *payload, int len, char *out_frame) {
    if (len > 65535) return 0; 
    int pos = 0;
    out_frame[pos++] = 0x82; // Binary frame, FIN=1
    
    if (len <= 125) {
        out_frame[pos++] = (char)len;
    } else {
        out_frame[pos++] = 126;
        out_frame[pos++] = (len >> 8) & 0xFF;
        out_frame[pos++] = len & 0xFF;
    }
    
    memcpy(out_frame + pos, payload, len);
    return pos + len;
}

long long check_ws_frame(unsigned char *buf, int len, int *header_len, int *payload_len) {
    if (len < 2) return 0;
    
    int h_len = 2;
    int p_len = buf[1] & 0x7F;
    
    if (p_len == 126) {
        if (len < 4) return 0;
        p_len = (buf[2] << 8) | buf[3];
        h_len = 4;
    } else if (p_len == 127) {
        return -1; // 暂不处理超大帧
    }
    
    if (len < h_len + p_len) return 0; 
    
    *header_len = h_len;
    *payload_len = p_len;
    return h_len + p_len;
}

// --------------------------------------------------------------------------
// [Fix] 恢复完整功能的精确读取函数 (之前版本缺失导致 SOCKS5 失败)
// --------------------------------------------------------------------------
int ws_read_payload_exact(TLSContext *tls, char *buf, int exact_len) {
    int total_read = 0;
    while (total_read < exact_len) {
        int r = SSL_read(tls->ssl, buf + total_read, exact_len - total_read);
        if (r <= 0) {
            int err = SSL_get_error(tls->ssl, r);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                Sleep(1); // 简单的轮询等待
                continue;
            }
            return total_read; // 连接断开或错误
        }
        total_read += r;
    }
    return total_read;
}

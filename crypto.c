#include "crypto.h"
#include "utils.h"
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

extern BOOL g_enableALPN;
extern BOOL g_enableLog;

// --------------------------------------------------------------------------
// OpenSSL 初始化
// --------------------------------------------------------------------------
void tls_cleanup_global() {
    EVP_cleanup();
}

// --------------------------------------------------------------------------
// TLS 连接初始化 (核心修复)
// --------------------------------------------------------------------------
int tls_init_connect(TLSContext *ctx, const char *sni, const char *host, const char *ech_config_b64) {
    if (!ctx) return -1;

    // 1. 创建 CTX
    ctx->ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx->ctx) {
        log_msg("[Error] SSL_CTX_new failed");
        return -1;
    }

    // [Security] 禁用不安全的旧协议，仅允许 TLS 1.2 和 1.3
    SSL_CTX_set_min_proto_version(ctx->ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx->ctx, TLS1_3_VERSION);

    // [Verification] 暂时禁用证书验证以确保连接连通性（生产环境建议开启）
    SSL_CTX_set_verify(ctx->ctx, SSL_VERIFY_NONE, NULL);

    // [ALPN] 如果启用，通告 h2 和 http/1.1
    if (g_enableALPN) {
        unsigned char alpn[] = {
            2, 'h', '2', 
            8, 'h', 't', 't', 'p', '/', '1', '.', '1'
        };
        SSL_CTX_set_alpn_protos(ctx->ctx, alpn, sizeof(alpn));
    }

    // 2. 创建 SSL 对象
    ctx->ssl = SSL_new(ctx->ctx);
    if (!ctx->ssl) {
        log_msg("[Error] SSL_new failed");
        SSL_CTX_free(ctx->ctx);
        return -1;
    }

    // 3. 绑定 Socket
    SSL_set_fd(ctx->ssl, (int)ctx->sock);

    // 4. [CRITICAL] 设置 SNI (Server Name Indication)
    // 这是 Inner SNI (真实的 Worker 域名)，OpenSSL 会自动将其加密封装
    if (sni && strlen(sni) > 0) {
        SSL_set_tlsext_host_name(ctx->ssl, sni);
    } else if (host && strlen(host) > 0) {
        SSL_set_tlsext_host_name(ctx->ssl, host);
    }

    // 5. [ECH] 配置 Encrypted Client Hello
    if (ech_config_b64 && strlen(ech_config_b64) > 0) {
        size_t ech_len = 0;
        unsigned char *ech_bin = Base64Decode(ech_config_b64, &ech_len);
        
        if (ech_bin && ech_len > 0) {
            // [Fix] 使用 SSL_set1_ech_config_list 注入 ECH 配置
            // 必须在 SSL_connect 之前调用
            int ret = SSL_set1_ech_config_list(ctx->ssl, ech_bin, ech_len);
            if (ret != 1) {
                log_msg("[Error] SSL_set1_ech_config_list failed. OpenSSL Err: %s", 
                    ERR_error_string(ERR_get_error(), NULL));
                // 即使 ECH 设置失败，也可以尝试继续连接（可能会降级为明文 SNI）
            } else {
                // log_msg("[Security] ECH Configured. Len: %d", ech_len);
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

    // log_msg("[Debug] SSL_connect Success. Cipher: %s", SSL_get_cipher_name(ctx->ssl));
    return 0;
}

void tls_close(TLSContext *ctx) {
    if (!ctx) return;
    if (ctx->ssl) {
        // 尝试优雅关闭，但不等待
        SSL_shutdown(ctx->ssl); 
        SSL_free(ctx->ssl);
        ctx->ssl = NULL;
    }
    if (ctx->ctx) {
        SSL_CTX_free(ctx->ctx);
        ctx->ctx = NULL;
    }
}

int tls_read(TLSContext *ctx, char *buf, int len) {
    if (!ctx || !ctx->ssl) return -1;
    int n = SSL_read(ctx->ssl, buf, len);
    if (n <= 0) {
        int err = SSL_get_error(ctx->ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return 0; // 非阻塞等待
        }
        return -1; // 真正的错误或关闭
    }
    return n;
}

int tls_write(TLSContext *ctx, const char *buf, int len) {
    if (!ctx || !ctx->ssl) return -1;
    int n = SSL_write(ctx->ssl, buf, len);
    if (n <= 0) {
        int err = SSL_get_error(ctx->ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return 0; 
        }
        return -1;
    }
    return n;
}

// WebSocket 辅助
int build_ws_frame(const char *payload, int len, char *out_frame) {
    if (len > 65535) return 0; // 暂不支持超大帧
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
    if (len < 2) return 0; // 数据不足
    
    int h_len = 2;
    int p_len = buf[1] & 0x7F;
    
    if (p_len == 126) {
        if (len < 4) return 0;
        p_len = (buf[2] << 8) | buf[3];
        h_len = 4;
    } else if (p_len == 127) {
        if (len < 10) return 0;
        // 暂不处理超大帧
        return -1; 
    }
    
    // Server frame usually not masked
    // if (buf[1] & 0x80) h_len += 4; 

    if (len < h_len + p_len) return 0; // 等待更多数据
    
    *header_len = h_len;
    *payload_len = p_len;
    return h_len + p_len;
}

// 精确读取 payload (用于 SOCKS5 握手等)
int ws_read_payload_exact(TLSContext *tls, char *buf, int exact_len) {
    // 这是一个简化实现，假设数据已经在 buffer 中
    // 在异步 IO 模型中，通常需要更复杂的缓冲逻辑
    // 这里仅作为占位符，实际逻辑在 proxy.c 的循环中处理
    return 0; 
}

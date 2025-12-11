#define _WIN32_IE 0x0300
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <commctrl.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <dbghelp.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <stdarg.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define ID_EDIT_URL 101
#define ID_BTN_ACTION 102
#define ID_EDIT_LOG 103

HWND hEditUrl, hBtnAction, hEditLog, hMainWnd;
volatile int g_running = 0;
SOCKET g_listen_sock = INVALID_SOCKET;
HFONT hFont;
SSL_CTX *g_ssl_ctx = NULL;

#define BUFFER_SIZE 131072 
#define CONFIG_FILE "proxy.conf"

typedef struct {
    char host[256];
    int port;
    char path[256];
    char sni[256];
    char user[128];
    char pass[128];
} ProxyConfig;
ProxyConfig g_config;

void log_msg(const char *format, ...) {
    char buf[2048];
    char time_buf[64];
    SYSTEMTIME st; GetLocalTime(&st);
    sprintf(time_buf, "[%04d-%02d-%02d %02d:%02d:%02d] ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    va_list args; va_start(args, format);
    vsnprintf(buf, sizeof(buf) - 64, format, args);
    va_end(args);
    char final_msg[2200];
    snprintf(final_msg, sizeof(final_msg), "%s%s\r\n", time_buf, buf);
    if (hEditLog) {
        int len = GetWindowTextLength(hEditLog);
        if (len > 30000) { SendMessage(hEditLog, EM_SETSEL, 0, -1); SendMessage(hEditLog, WM_CLEAR, 0, 0); len = 0; }
        SendMessage(hEditLog, EM_SETSEL, (WPARAM)len, (LPARAM)len);
        SendMessage(hEditLog, EM_REPLACESEL, 0, (LPARAM)final_msg);
        SendMessage(hEditLog, WM_VSCROLL, SB_BOTTOM, 0);
    } else {
        OutputDebugString(final_msg);
    }
}

static const int b64_index[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
};
int b64_decode(const char* in, unsigned char* out) {
    int len = (int)strlen(in), i, j = 0, v = 0, bits = 0;
    for (i = 0; i < len; i++) {
        if (in[i] == '=') break;
        int val = b64_index[(unsigned char)in[i]];
        if (val == -1) continue;
        v = (v << 6) | val; bits += 6;
        if (bits >= 8) { bits -= 8; out[j++] = (v >> bits) & 0xFF; }
    } out[j] = 0; return j;
}
void url_decode(char *dst, const char *src) {
    char a, b;
    while (*src) {
        if ((*src == '%') && ((a = src[1]) && (b = src[2])) && (isxdigit((unsigned char)a) && isxdigit((unsigned char)b))) {
            char ah = a, bh = b;
            if (ah >= 'a') ah -= 'a'-'A';
            if (ah >= 'A') ah -= ('A' - 10); else ah -= '0';
            if (bh >= 'a') bh -= 'a'-'A';
            if (bh >= 'A') bh -= ('A' - 10); else bh -= '0';
            *dst++ = 16*ah+bh; src+=3;
        } else { *dst++ = *src++; }
    } *dst++ = 0;
}

int parse_uri(const char* uri) {
    memset(&g_config, 0, sizeof(g_config));
    char buf[2048]; strncpy(buf, uri, sizeof(buf)-1); buf[sizeof(buf)-1]=0;
    char *ptr = strstr(buf, "socks://");
    if (!ptr) { log_msg("错误: 链接必须以 socks:// 开头"); return 0; }
    ptr += 8;
    char *at = strchr(ptr, '@'); if (!at) { log_msg("错误: 找不到 '@' 分隔符"); return 0; }
    *at = 0;
    unsigned char decoded_auth[512]; memset(decoded_auth,0,sizeof(decoded_auth));
    b64_decode(ptr, decoded_auth);
    char *colon = strchr((char*)decoded_auth, ':');
    if (colon) { *colon = 0; strncpy(g_config.user, (char*)decoded_auth, sizeof(g_config.user)-1); strncpy(g_config.pass, colon + 1, sizeof(g_config.pass)-1); }
    else { log_msg("错误: base64 解码后未找到 ':' 分隔用户名和密码"); return 0; }
    ptr = at + 1;
    char *params = strchr(ptr, '?'); if (params) *params = 0;
    colon = strchr(ptr, ':');
    if (colon) { *colon = 0; strncpy(g_config.host, ptr, sizeof(g_config.host)-1); g_config.port = atoi(colon + 1); }
    else { strncpy(g_config.host, ptr, sizeof(g_config.host)-1); g_config.port = 443; }
    if (params) {
        char pbuf[1024]; strncpy(pbuf, params+1, sizeof(pbuf)-1); pbuf[sizeof(pbuf)-1]=0;
        char *tok = strtok(pbuf, "&");
        while(tok) {
            char *eq = strchr(tok, '=');
            if(eq) { *eq = 0; char *k = tok; char *v = eq+1;
                if(!strcmp(k, "sni")) strncpy(g_config.sni, v, sizeof(g_config.sni)-1);
                if(!strcmp(k, "path")) url_decode(g_config.path, v);
            }
            tok = strtok(NULL, "&");
        }
    }
    if (strlen(g_config.path) == 0) strncpy(g_config.path, "/", sizeof(g_config.path)-1);
    log_msg("=== 配置解析成功 ===");
    log_msg("服务器: %s:%d", g_config.host, g_config.port);
    log_msg("SNI: %s", g_config.sni[0] ? g_config.sni : g_config.host);
    return 1;
}

typedef struct { SOCKET sock; SSL *ssl; } TLSContext;

void init_openssl_global() {
    if (g_ssl_ctx) return;
    SSL_library_init(); OpenSSL_add_all_algorithms(); SSL_load_error_strings();
    
    // 使用通用方法，支持 TLS 1.0 - 1.3
    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
    
    if (!g_ssl_ctx) { log_msg("OpenSSL: 创建上下文失败"); return; }
    
    // [关键] 强制设置最低版本为 TLS 1.1，启用自动降级
    // 如果不设置，现代 OpenSSL 可能默认最低为 1.2
    if (!SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_1_VERSION)) {
        log_msg("警告: 无法设置最低协议版本为 TLS 1.1");
    }
    // 最高版本设为 TLS 1.3 (默认值)
    SSL_CTX_set_max_proto_version(g_ssl_ctx, TLS1_3_VERSION);

    // 禁用证书验证以确保持续运行
    SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);
    
    log_msg("OpenSSL 初始化完成 (协议范围: TLS 1.1 - 1.3)");
}

int tls_init_connect(TLSContext *ctx) {
    if (!ctx || !g_ssl_ctx) return -1;
    ctx->ssl = SSL_new(g_ssl_ctx);
    if (!ctx->ssl) return -1;
    SSL_set_fd(ctx->ssl, ctx->sock);
    const char *sni_name = (strlen(g_config.sni) ? g_config.sni : g_config.host);
    SSL_set_tlsext_host_name(ctx->ssl, sni_name);
    
    int ret = SSL_connect(ctx->ssl);
    if (ret != 1) {
        int err = SSL_get_error(ctx->ssl, ret);
        log_msg("SSL_connect 失败: 代码 %d", err);
        return -1;
    }
    
    // [调试] 打印实际协商的协议版本
    log_msg("SSL握手成功! 协议: %s, 加密: %s", SSL_get_version(ctx->ssl), SSL_get_cipher(ctx->ssl));
    return 0;
}

int tls_write(TLSContext *ctx, const char *data, int len) {
    if (!ctx || !ctx->ssl) return -1;
    return (SSL_write(ctx->ssl, data, len) <= 0) ? -1 : len;
}

int tls_read(TLSContext *ctx, char *out, int max) {
    if (!ctx || !ctx->ssl) return -1;
    int ret = SSL_read(ctx->ssl, out, max);
    if (ret <= 0) {
        int err = SSL_get_error(ctx->ssl, ret);
        if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return 0;
        return -1;
    }
    return ret;
}

void tls_close(TLSContext *ctx) {
    if (ctx->ssl) { SSL_shutdown(ctx->ssl); SSL_free(ctx->ssl); ctx->ssl = NULL; }
}

int build_frame(const char *in, int len, char *out) {
    out[0] = 0x82; uint8_t mask[4]; *(uint32_t*)mask = GetTickCount(); 
    if (len < 126) { out[1] = 0x80 | len; memcpy(out+2, mask, 4); for(int i=0;i<len;i++) out[6+i] = in[i]^mask[i%4]; return 6+len; } 
    else if (len <= 65535) { out[1] = 0x80 | 126; out[2] = (len>>8)&0xFF; out[3] = len&0xFF; memcpy(out+4, mask, 4); for(int i=0;i<len;i++) out[8+i] = in[i]^mask[i%4]; return 8+len; }
    return -1; 
}

int check_frame_complete(unsigned char *in, int len, int *head_len, int *payload_len) {
    if(len < 2) return 0;
    int hl = 2; int pl = in[1] & 0x7F;
    if (pl == 126) { if (len < 4) return 0; hl = 4; pl = (in[2] << 8) | in[3]; } 
    else if (pl == 127) { if (len < 10) return 0; hl = 10; pl = 65536; }
    if (len < hl + pl) return 0;
    *head_len = hl; *payload_len = pl;
    return hl + pl; 
}

int recv_timeout(SOCKET s, char *buf, int len, int timeout_sec) {
    fd_set fds; FD_ZERO(&fds); FD_SET(s, &fds);
    struct timeval tv = { timeout_sec, 0 };
    int n = select(0, &fds, NULL, NULL, &tv);
    if (n == 0) return -2; if (n < 0) return -1;  
    return recv(s, buf, len, 0);
}

DWORD WINAPI client_handler(LPVOID p) {
    SOCKET c = (SOCKET)(UINT_PTR)p;
    TLSContext tls; memset(&tls, 0, sizeof(tls));
    SOCKET r = INVALID_SOCKET;
    
    // log_msg("【1】浏览器发起连接 (Socket %d)", (int)c);

    char *c_buf = (char*)malloc(BUFFER_SIZE); 
    char *ws_read_buf = (char*)malloc(BUFFER_SIZE); 
    char *ws_send_buf = (char*)malloc(BUFFER_SIZE);
    
    if (!c_buf || !ws_read_buf || !ws_send_buf) { log_msg("内存不足"); goto cl_end; }

    int ws_buf_len = 0; 
    int flag = 1; 
    setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

    // 1. DNS解析与TCP连接
    r = socket(AF_INET, SOCK_STREAM, 0);
    if (r == INVALID_SOCKET) { log_msg("Socket创建失败"); goto cl_end; }
    setsockopt(r, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

    struct hostent *h = gethostbyname(g_config.host);
    if(!h) { log_msg("DNS解析失败！"); goto cl_end; }
    struct sockaddr_in a; memset(&a, 0, sizeof(a)); a.sin_family = AF_INET; a.sin_port = htons((unsigned short)g_config.port);
    a.sin_addr = *(struct in_addr*)h->h_addr;

    if (connect(r, (struct sockaddr*)&a, sizeof(a)) != 0) { 
        log_msg("连接超时或被拒绝 (WSA %d)", WSAGetLastError()); 
        goto cl_end; 
    }
    
    tls.sock = r;
    if (tls_init_connect(&tls) != 0) { log_msg("SSL握手失败"); goto cl_end; }
    
    // 2. WS 握手
    const char* request_host = (strlen(g_config.sni) > 0) ? g_config.sni : g_config.host;
    snprintf(c_buf, BUFFER_SIZE, 
        "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", 
        g_config.path, request_host);
        
    if (tls_write(&tls, c_buf, (int)strlen(c_buf)) < 0) goto cl_end;

    int len = tls_read(&tls, c_buf, BUFFER_SIZE-1);
    if (len <= 0) { log_msg("WS握手无响应"); goto cl_end; }
    c_buf[len] = 0;
    if (!strstr(c_buf, "101 Switching Protocols")) { log_msg("WS升级被拒绝"); goto cl_end; }

    // 3. 认证
    char auth[] = {0x05, 0x01, 0x02}; 
    int flen = build_frame(auth, 3, ws_send_buf);
    tls_write(&tls, ws_send_buf, flen);

    len = tls_read(&tls, ws_read_buf, BUFFER_SIZE);
    if (len <= 0) { log_msg("认证步骤1无响应"); goto cl_end; }
    ws_buf_len = len;
    
    int hl, pl;
    int frame_total = check_frame_complete((unsigned char*)ws_read_buf, ws_buf_len, &hl, &pl);
    if (frame_total > 0) {
        memmove(ws_read_buf, ws_read_buf + frame_total, ws_buf_len - frame_total);
        ws_buf_len -= frame_total;
    }

    char up[512]; int idx = 0;
    up[idx++] = 1; up[idx++] = (char)strlen(g_config.user); memcpy(up+idx, g_config.user, strlen(g_config.user)); idx += (int)strlen(g_config.user);
    up[idx++] = (char)strlen(g_config.pass); memcpy(up+idx, g_config.pass, strlen(g_config.pass)); idx += (int)strlen(g_config.pass);
    flen = build_frame(up, idx, ws_send_buf);
    tls_write(&tls, ws_send_buf, flen);

    while (1) {
        frame_total = check_frame_complete((unsigned char*)ws_read_buf, ws_buf_len, &hl, &pl);
        if (frame_total > 0) {
            if (pl >= 2 && ws_read_buf[hl+1] != 0x00) { log_msg("认证失败: 账号密码错误"); goto cl_end; }
            memmove(ws_read_buf, ws_read_buf + frame_total, ws_buf_len - frame_total);
            ws_buf_len -= frame_total;
            break; 
        }
        len = tls_read(&tls, ws_read_buf + ws_buf_len, BUFFER_SIZE - ws_buf_len);
        if (len <= 0) { log_msg("认证步骤2中断"); goto cl_end; }
        ws_buf_len += len;
    }

    // 4. 混合模式握手 (兼容 SOCKS5 和 HTTP Proxy)
    len = recv_timeout(c, c_buf, BUFFER_SIZE, 10); 
    if (len > 0) {
        if (c_buf[0] == 0x05) {
            // SOCKS5 模式
            send(c, "\x05\x00", 2, 0); 
            len = recv_timeout(c, c_buf, BUFFER_SIZE, 10);
            if (len > 0) {
                flen = build_frame(c_buf, len, ws_send_buf);
                tls_write(&tls, ws_send_buf, flen);
            } else goto cl_end;
        } 
        else if (c_buf[0] == 0x43 || c_buf[0] == 0x47 || c_buf[0] == 0x50) { 
            // HTTP Proxy 模式
            c_buf[len] = 0;
            char method[16], host[256]; int port = 80;
            if (sscanf(c_buf, "%15s %255s", method, host) == 2) {
                char *p = strchr(host, ':');
                if (p) { *p = 0; port = atoi(p+1); }
                else { if(stricmp(method, "CONNECT")==0) port = 443; }

                unsigned char socks_req[512]; int slen = 0;
                socks_req[slen++] = 0x05; socks_req[slen++] = 0x01; 
                socks_req[slen++] = 0x00; socks_req[slen++] = 0x03;
                socks_req[slen++] = (unsigned char)strlen(host);
                memcpy(socks_req + slen, host, strlen(host)); slen += (int)strlen(host);
                socks_req[slen++] = (port >> 8) & 0xFF; socks_req[slen++] = port & 0xFF;

                flen = build_frame((char*)socks_req, slen, ws_send_buf);
                tls_write(&tls, ws_send_buf, flen);

                if (stricmp(method, "CONNECT") == 0) {
                    const char *ok_resp = "HTTP/1.1 200 Connection Established\r\n\r\n";
                    send(c, ok_resp, (int)strlen(ok_resp), 0);
                }
            } else goto cl_end;
        } else {
            log_msg("未知协议头: 0x%02X", (unsigned char)c_buf[0]);
            goto cl_end;
        }

        // 等待远程 SOCKS5 响应
        while (1) {
            frame_total = check_frame_complete((unsigned char*)ws_read_buf, ws_buf_len, &hl, &pl);
            if (frame_total > 0) {
                if (c_buf[0] == 0x05) {
                    send(c, ws_read_buf + hl, pl, 0);
                }
                memmove(ws_read_buf, ws_read_buf + frame_total, ws_buf_len - frame_total);
                ws_buf_len -= frame_total;
                break; 
            }
            len = tls_read(&tls, ws_read_buf + ws_buf_len, BUFFER_SIZE - ws_buf_len);
            if (len <= 0) goto cl_end;
            ws_buf_len += len;
        }
    } else goto cl_end;

    // 5. 数据转发
    fd_set fds;
    struct timeval tv;
    u_long mode = 1;
    ioctlsocket(c, FIONBIO, &mode);
    ioctlsocket(r, FIONBIO, &mode);

    while(1) {
        FD_ZERO(&fds); FD_SET(c, &fds); FD_SET(r, &fds);
        
        int pending = SSL_pending(tls.ssl);
        tv.tv_sec = 1; tv.tv_usec = 0;
        if (pending > 0) { tv.tv_sec = 0; tv.tv_usec = 0; }

        int n = select(0, &fds, NULL, NULL, &tv);
        if (n < 0) break;

        if (FD_ISSET(c, &fds)) {
            len = recv(c, c_buf, BUFFER_SIZE, 0);
            if (len > 0) {
                flen = build_frame(c_buf, len, ws_send_buf);
                if (tls_write(&tls, ws_send_buf, flen) < 0) break;
            } else {
                if (WSAGetLastError() != WSAEWOULDBLOCK) break;
            }
        }

        if (FD_ISSET(r, &fds) || pending > 0) {
            if (ws_buf_len < BUFFER_SIZE) {
                len = tls_read(&tls, ws_read_buf + ws_buf_len, BUFFER_SIZE - ws_buf_len);
                if (len > 0) ws_buf_len += len;
            }
        }
        
        while (ws_buf_len > 0) {
            frame_total = check_frame_complete((unsigned char*)ws_read_buf, ws_buf_len, &hl, &pl);
            if (frame_total > 0) {
                int opcode = ws_read_buf[0] & 0x0F;
                if (opcode == 0x8) goto cl_end; 
                if (opcode == 0x1 || opcode == 0x2) { 
                   if (pl > 0) send(c, ws_read_buf + hl, pl, 0);
                }
                memmove(ws_read_buf, ws_read_buf + frame_total, ws_buf_len - frame_total);
                ws_buf_len -= frame_total;
            } else {
                if (ws_buf_len >= BUFFER_SIZE) goto cl_end;
                break;
            }
        }
    }

cl_end:
    if(c_buf) free(c_buf);
    if(ws_read_buf) free(ws_read_buf);
    if(ws_send_buf) free(ws_send_buf);
    tls_close(&tls);
    if (r != INVALID_SOCKET) closesocket(r);
    if (c != INVALID_SOCKET) closesocket(c);
    return 0;
}

DWORD WINAPI server_thread(LPVOID p) {
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
    init_openssl_global();
    g_listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; addr.sin_port = htons(1080); addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(g_listen_sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        log_msg("启动失败: 端口 1080 被占用");
        g_running = 0; SetWindowText(hBtnAction, "启动代理");
        return 0;
    }
    listen(g_listen_sock, 100);
    log_msg("本地服务已启动: 127.0.0.1:1080 (协议自适应)");
    while(g_running) {
        SOCKET c = accept(g_listen_sock, NULL, NULL);
        if (c != INVALID_SOCKET) {
            HANDLE th = CreateThread(NULL, 0, client_handler, (LPVOID)(UINT_PTR)c, 0, NULL);
            if(th) CloseHandle(th); else closesocket(c);
        }
    }
    if (g_ssl_ctx) SSL_CTX_free(g_ssl_ctx);
    WSACleanup(); return 0;
}

void start_proxy() {
    char url[2048]; GetWindowText(hEditUrl, url, sizeof(url));
    if (!parse_uri(url)) return;
    g_running = 1; SetWindowText(hBtnAction, "停止服务"); EnableWindow(hEditUrl, 0);
    CreateThread(NULL, 0, server_thread, NULL, 0, NULL);
}
void stop_proxy() { g_running = 0; if (g_listen_sock != INVALID_SOCKET) closesocket(g_listen_sock); SetWindowText(hBtnAction, "启动代理"); EnableWindow(hEditUrl, 1); log_msg("服务已停止。"); }

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    switch(msg) {
        case WM_CREATE:
            hFont = CreateFont(14,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,0,0,"SimSun");
            CreateWindow("STATIC", "节点链接:", WS_CHILD|WS_VISIBLE, 10,10,60,20,hwnd,0,0,0);
            hEditUrl = CreateWindow("EDIT", "", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL, 75,8,305,22,hwnd,(HMENU)ID_EDIT_URL,0,0);
            hBtnAction = CreateWindow("BUTTON", "启动代理", WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON, 390,7,80,24,hwnd,(HMENU)ID_BTN_ACTION,0,0);
            hEditLog = CreateWindow("EDIT", "", WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|ES_MULTILINE|ES_READONLY, 10,40,460,310,hwnd,(HMENU)ID_EDIT_LOG,0,0);
            SendMessage(hEditUrl, WM_SETFONT, (WPARAM)hFont, 1); SendMessage(hEditLog, WM_SETFONT, (WPARAM)hFont, 1); SendMessage(hBtnAction, WM_SETFONT, (WPARAM)hFont, 1);
            FILE *f = fopen(CONFIG_FILE, "r"); if(f) { char b[2048]; if(fgets(b,2048,f)) { b[strcspn(b,"\r\n")]=0; SetWindowText(hEditUrl, b); } fclose(f); }
            break;
        case WM_COMMAND: if (LOWORD(w)==ID_BTN_ACTION) { if(g_running) stop_proxy(); else start_proxy(); } break;
        case WM_DESTROY: stop_proxy(); if (hFont) DeleteObject(hFont); PostQuitMessage(0); break;
        default: return DefWindowProc(hwnd, msg, w, l);
    } return 0;
}

typedef BOOL (WINAPI *MINIDUMPWRITEDUMP)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE, PMINIDUMP_EXCEPTION_INFORMATION, PMINIDUMP_USER_STREAM_INFORMATION, PMINIDUMP_CALLBACK_INFORMATION);
LONG WINAPI MyExceptionFilter(EXCEPTION_POINTERS *ep) {
    char filename[MAX_PATH];
    SYSTEMTIME st; GetLocalTime(&st);
    snprintf(filename, sizeof(filename), "crash-%04d%02d%02d-%02d%02d%02d.dmp", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    HMODULE hDbgHelp = LoadLibrary("dbghelp.dll");
    if (hDbgHelp) {
        MINIDUMPWRITEDUMP pMiniDumpWriteDump = (MINIDUMPWRITEDUMP)GetProcAddress(hDbgHelp, "MiniDumpWriteDump");
        if (pMiniDumpWriteDump) {
            HANDLE hFile = CreateFile(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                MINIDUMP_EXCEPTION_INFORMATION mei; mei.ThreadId = GetCurrentThreadId(); mei.ExceptionPointers = ep; mei.ClientPointers = FALSE;
                pMiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, MiniDumpWithIndirectlyReferencedMemory | MiniDumpWithDataSegs, &mei, NULL, NULL);
                CloseHandle(hFile);
            }
        }
        FreeLibrary(hDbgHelp);
    }
    log_msg("捕获未处理异常，已尝试写入 %s", filename);
    return EXCEPTION_EXECUTE_HANDLER;
}

int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR c, int n) {
    SetUnhandledExceptionFilter(MyExceptionFilter);
    WNDCLASS wc = {0}; wc.lpfnWndProc=WndProc; wc.hInstance=h; wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1); wc.lpszClassName="DbgPro"; RegisterClass(&wc);
    hMainWnd = CreateWindow("DbgPro", "SOCKS5 代理客户端 (AutoFallback)", WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX, 300, 300, 500, 400, 0, 0, h, 0);
    ShowWindow(hMainWnd, n);
    MSG msg; while(GetMessage(&msg,0,0,0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    return 0;
}
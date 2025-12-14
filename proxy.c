#include "proxy.h"
#include "crypto.h"
#include "utils.h"
#include <openssl/sha.h>

// --- UUID 解析 ---
void parse_uuid(const char* uuid_str, unsigned char* out) {
    const char* p = uuid_str;
    int i = 0;
    while (*p && i < 16) {
        if (*p == '-') { p++; continue; }
        int v;
        sscanf(p, "%2x", &v);
        out[i++] = (unsigned char)v;
        p += 2;
    }
}

// --- Trojan Hash ---
void trojan_password_hash(const char* password, char* out_hex) {
    unsigned char digest[SHA224_DIGEST_LENGTH];
    SHA224((unsigned char*)password, strlen(password), digest);
    for(int i = 0; i < SHA224_DIGEST_LENGTH; i++) {
        sprintf(out_hex + (i * 2), "%02x", digest[i]);
    }
    out_hex[SHA224_DIGEST_LENGTH * 2] = 0;
}

int recv_timeout(SOCKET s, char *buf, int len, int timeout_sec) {
    fd_set fds; FD_ZERO(&fds); FD_SET(s, &fds);
    struct timeval tv = { timeout_sec, 0 };
    int n = select(0, &fds, NULL, NULL, &tv);
    if (n == 0) return -2; if (n < 0) return -1;  
    return recv(s, buf, len, 0);
}

int send_all(SOCKET s, const char *buf, int len) {
    int total = 0; int bytesleft = len; int n;
    while(total < len) {
        n = send(s, buf+total, bytesleft, 0);
        if (n == -1) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) { Sleep(1); continue; }
            return -1;
        }
        total += n; bytesleft -= n;
    }
    return total;
}

// 调试辅助：打印 Hex 预览
void log_hex_simple(const char* tag, unsigned char* data, int len) {
    if (len <= 0) return;
    char buf[64];
    int max = len > 6 ? 6 : len;
    int p = 0;
    for(int i=0; i<max; i++) p += sprintf(buf+p, "%02X ", data[i]);
    log_msg("%s %d bytes: %s...", tag, len, buf);
}

DWORD WINAPI client_handler(LPVOID p) {
    SOCKET c = (SOCKET)(UINT_PTR)p; TLSContext tls; memset(&tls, 0, sizeof(tls));
    SOCKET r = INVALID_SOCKET;      
    
    char *c_buf = (char*)malloc(BUFFER_SIZE); 
    char *ws_read_buf = (char*)malloc(BUFFER_SIZE); 
    char *ws_send_buf = (char*)malloc(BUFFER_SIZE + 512);

    if (!c_buf || !ws_read_buf || !ws_send_buf) { goto cl_end; }
    int ws_buf_len = 0; int flag = 1; 
    setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
    
    // 1. 读取浏览器请求
    int browser_len = recv_timeout(c, c_buf, BUFFER_SIZE, 10);
    if (browser_len <= 0) goto cl_end;
    c_buf[browser_len] = 0;
    
    char method[16], host[256]; int port = 80; int is_connect_method = 0;
    char *header_end = NULL;
    int header_len = 0;

    if (c_buf[0] == 0x05) { send(c, "\x05\x00", 2, 0); goto cl_end; }
    else {
        if (sscanf(c_buf, "%15s %255s", method, host) == 2) {
            char *p = strchr(host, ':');
            if (p) { *p = 0; port = atoi(p+1); }
            else if(stricmp(method, "CONNECT")==0) port = 443;
            if (stricmp(method, "CONNECT") == 0) is_connect_method = 1;
            
            // 计算头部长度，查找 \r\n\r\n
            header_end = strstr(c_buf, "\r\n\r\n");
            if (header_end) {
                header_len = (int)(header_end - c_buf) + 4;
            } else {
                header_len = browser_len; // 没找到结束符，假设全是头
            }
        } else { goto cl_end; }
    }
    
    // log_msg("[Info] %s %s:%d", method, host, port);

    // 2. 连接远程服务器
    struct hostent *h = gethostbyname(g_proxyConfig.host);
    if(!h) { log_msg("[Err] DNS Fail: %s", g_proxyConfig.host); goto cl_end; }
    
    r = socket(AF_INET, SOCK_STREAM, 0);
    if (r == INVALID_SOCKET) goto cl_end;
    setsockopt(r, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
    
    struct sockaddr_in a; memset(&a, 0, sizeof(a)); a.sin_family = AF_INET; a.sin_port = htons((unsigned short)g_proxyConfig.port);
    a.sin_addr = *(struct in_addr*)h->h_addr;
    
    if (connect(r, (struct sockaddr*)&a, sizeof(a)) != 0) { log_msg("[Err] Connect Fail"); goto cl_end; }
    
    tls.sock = r;
    if (tls_init_connect(&tls) != 0) { log_msg("[Err] TLS Fail"); goto cl_end; }
    
    // 3. WebSocket 握手
    const char* sni_val = (strlen(g_proxyConfig.sni) > 0) ? g_proxyConfig.sni : g_proxyConfig.host;
    int offset = snprintf(ws_send_buf, BUFFER_SIZE, 
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n", 
        g_proxyConfig.path, sni_val, g_userAgentStr);

    tls_write(&tls, ws_send_buf, offset);

    int len = tls_read(&tls, ws_read_buf, BUFFER_SIZE-1);
    if (len <= 0 || !strstr(ws_read_buf, "101")) { log_msg("[Err] WS Handshake Fail"); goto cl_end; }
    
    // 4. 发送协议头
    int flen = 0;
    unsigned char proto_buf[1024];
    int proto_len = 0;
    
    BOOL is_vless = (_stricmp(g_proxyConfig.type, "vless") == 0);
    BOOL is_trojan = (_stricmp(g_proxyConfig.type, "trojan") == 0);

    if (is_vless) {
        proto_buf[proto_len++] = 0x00; // Version
        parse_uuid(g_proxyConfig.user, proto_buf + proto_len); proto_len += 16; 
        proto_buf[proto_len++] = 0x00; // Addons
        proto_buf[proto_len++] = 0x01; // TCP
        proto_buf[proto_len++] = (port >> 8) & 0xFF; proto_buf[proto_len++] = port & 0xFF;        
        proto_buf[proto_len++] = 0x03; // Domain
        proto_buf[proto_len++] = (unsigned char)strlen(host);
        memcpy(proto_buf + proto_len, host, strlen(host)); proto_len += (int)strlen(host);
        
        flen = build_ws_frame((char*)proto_buf, proto_len, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
    } else if (is_trojan) {
        char hex_pass[56 + 1]; trojan_password_hash(g_proxyConfig.pass, hex_pass);
        memcpy(proto_buf, hex_pass, 56); proto_len = 56;
        proto_buf[proto_len++] = 0x0D; proto_buf[proto_len++] = 0x0A;
        proto_buf[proto_len++] = 0x01; proto_buf[proto_len++] = 0x03;
        proto_buf[proto_len++] = (unsigned char)strlen(host);
        memcpy(proto_buf + proto_len, host, strlen(host)); proto_len += strlen(host);
        proto_buf[proto_len++] = (port >> 8) & 0xFF; proto_buf[proto_len++] = port & 0xFF;
        proto_buf[proto_len++] = 0x0D; proto_buf[proto_len++] = 0x0A;
        flen = build_ws_frame((char*)proto_buf, proto_len, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
    } else {
        // Socks5 ... (omitted for brevity, assume vless/trojan)
    }
    
    // 5. 响应浏览器并处理“抢跑”数据
    if (is_connect_method) {
        const char *ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
        send(c, ok, strlen(ok), 0);
        
        // [关键修复] 检查 CONNECT 包中是否夹带了额外数据 (Pipeline)
        if (browser_len > header_len) {
            int extra_len = browser_len - header_len;
            log_hex_simple("[Tx] Early Data", (unsigned char*)(c_buf + header_len), extra_len);
            flen = build_ws_frame(c_buf + header_len, extra_len, ws_send_buf);
            tls_write(&tls, ws_send_buf, flen);
        }
    } else {
        // 非 CONNECT 请求（如直接 HTTP GET），直接转发全部内容
        log_hex_simple("[Tx] Direct Data", (unsigned char*)c_buf, browser_len);
        flen = build_ws_frame(c_buf, browser_len, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
    }
    
    // 6. 数据转发循环
    fd_set fds; struct timeval tv; u_long mode = 1;
    ioctlsocket(c, FIONBIO, &mode); ioctlsocket(r, FIONBIO, &mode);
    ws_buf_len = 0; int hl, pl, frame_total;
    int vless_response_header_stripped = 0;

    while(1) {
        FD_ZERO(&fds); FD_SET(c, &fds); FD_SET(r, &fds);
        int pending = SSL_pending(tls.ssl);
        tv.tv_sec = 1; tv.tv_usec = 0;
        if (pending > 0 || ws_buf_len > 0) { tv.tv_sec = 0; tv.tv_usec = 0; }
        
        int n = select(0, &fds, NULL, NULL, &tv);
        if (n < 0) break;
        
        // 浏览器 -> 发送
        if (FD_ISSET(c, &fds)) {
            len = recv(c, c_buf, BUFFER_SIZE, 0);
            if (len > 0) {
                log_hex_simple("[Tx] Browser -> Server", (unsigned char*)c_buf, len);
                flen = build_ws_frame(c_buf, len, ws_send_buf);
                if (tls_write(&tls, ws_send_buf, flen) < 0) break;
            } else if (WSAGetLastError() != WSAEWOULDBLOCK) {
                // log_msg("[Info] Browser closed connection");
                break;
            }
        }
        
        // 接收 -> 浏览器
        if (FD_ISSET(r, &fds) || pending > 0) {
            if (ws_buf_len < BUFFER_SIZE) {
                len = tls_read(&tls, ws_read_buf + ws_buf_len, BUFFER_SIZE - ws_buf_len);
                if (len > 0) ws_buf_len += len;
                else if (len == -1) break; 
            }
        }
        
        while (ws_buf_len > 0) {
            frame_total = check_ws_frame((unsigned char*)ws_read_buf, ws_buf_len, &hl, &pl);
            if (frame_total > 0) {
                int opcode = ws_read_buf[0] & 0x0F;
                if (opcode == 0x8) goto cl_end; 
                if ((opcode == 0x1 || opcode == 0x2) && pl > 0) {
                    char* payload_ptr = ws_read_buf + hl;
                    int payload_size = pl;

                    if (is_vless && !vless_response_header_stripped) {
                        if (payload_size >= 2) {
                            int addon_len = (unsigned char)payload_ptr[1];
                            int head_size = 2 + addon_len;
                            if (payload_size >= head_size) {
                                log_msg("[Rx] VLESS Header Stripped. Data: %d bytes", payload_size - head_size);
                                payload_ptr += head_size;
                                payload_size -= head_size;
                                vless_response_header_stripped = 1;
                            } else {
                                payload_size = 0; // Partial header
                            }
                        } else {
                            payload_size = 0; // Too short
                        }
                    }

                    if (payload_size > 0) {
                        log_hex_simple("[Rx] Server -> Browser", (unsigned char*)payload_ptr, payload_size);
                        if (send_all(c, payload_ptr, payload_size) < 0) goto cl_end;
                    }
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
    free(c_buf); free(ws_read_buf); free(ws_send_buf); tls_close(&tls);
    if (r != INVALID_SOCKET) closesocket(r); if (c != INVALID_SOCKET) closesocket(c);
    return 0;
}

DWORD WINAPI server_thread(LPVOID p) {
    g_listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; addr.sin_port = htons(g_localPort);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int opt = 1; setsockopt(g_listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    if (bind(g_listen_sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        log_msg("Port %d bind fail", g_localPort); g_proxyRunning = FALSE; return 0;
    }
    listen(g_listen_sock, 100);
    log_msg("Proxy Started: 127.0.0.1:%d", g_localPort);
    while(g_proxyRunning) {
        SOCKET c = accept(g_listen_sock, NULL, NULL);
        if (c != INVALID_SOCKET) {
            HANDLE hClient = CreateThread(NULL, 0, client_handler, (LPVOID)(UINT_PTR)c, 0, NULL);
            if (hClient) CloseHandle(hClient); else closesocket(c);
        } else break;
    }
    return 0;
}

void StartProxyCore() {
    if (g_proxyRunning) return;
    g_proxyRunning = TRUE;
    hProxyThread = CreateThread(NULL, 0, server_thread, NULL, 0, NULL);
    if (!hProxyThread) { log_msg("CreateThread Failed"); g_proxyRunning = FALSE; }
}

void StopProxyCore() {
    g_proxyRunning = FALSE;
    if (g_listen_sock != INVALID_SOCKET) { closesocket(g_listen_sock); g_listen_sock = INVALID_SOCKET; }
    if (hProxyThread) { WaitForSingleObject(hProxyThread, 2000); CloseHandle(hProxyThread); hProxyThread = NULL; }
    log_msg("Proxy Stopped");
}

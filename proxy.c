#include "proxy.h"
#include "crypto.h"
#include "utils.h"
#include <openssl/sha.h>

// --- 辅助函数：解析 UUID (支持带横杠或不带) ---
void parse_uuid(const char* uuid_str, unsigned char* out) {
    const char* p = uuid_str;
    int i = 0;
    while (*p && i < 16) {
        if (*p == '-' || *p == ' ' || *p == '{' || *p == '}') { 
            p++; continue; 
        }
        int v;
        if (sscanf(p, "%2x", &v) == 1) {
            out[i++] = (unsigned char)v;
            p += 2;
        } else {
            p++; // 跳过非十六进制字符
        }
    }
}

// --- 辅助函数：Trojan 密码哈希 (SHA224) ---
void trojan_password_hash(const char* password, char* out_hex) {
    unsigned char digest[SHA224_DIGEST_LENGTH];
    SHA224((unsigned char*)password, strlen(password), digest);
    for(int i = 0; i < SHA224_DIGEST_LENGTH; i++) {
        sprintf(out_hex + (i * 2), "%02x", digest[i]);
    }
    out_hex[SHA224_DIGEST_LENGTH * 2] = 0;
}

// 接收超时辅助函数
int recv_timeout(SOCKET s, char *buf, int len, int timeout_sec) {
    fd_set fds; FD_ZERO(&fds); FD_SET(s, &fds);
    struct timeval tv = { timeout_sec, 0 };
    int n = select(0, &fds, NULL, NULL, &tv);
    if (n == 0) return -2; if (n < 0) return -1;  
    return recv(s, buf, len, 0);
}

// 发送全部数据辅助函数
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

// 调试日志：打印简短 Hex 预览
void log_hex_simple(const char* tag, unsigned char* data, int len) {
    if (len <= 0) return;
    char buf[64] = {0};
    int max = len > 6 ? 6 : len;
    int p = 0;
    for(int i=0; i<max; i++) p += sprintf(buf+p, "%02X ", data[i]);
    log_msg("%s %d bytes: %s...", tag, len, buf);
}

// [修复] 正确解析 WebSocket 帧长度，支持大数据包
// 返回值: 帧总长度 (Header + Payload)。如果数据不足返回 0，出错返回 -1
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
        // 解析 64 位长度 (Big Endian)
        pl = 0;
        for(int i = 0; i < 8; i++) {
            pl = (pl << 8) | in[2 + i];
        }
    }
    
    if (in[1] & 0x80) hl += 4; // Mask key present

    // [安全检查] 检查包大小是否超过缓冲区限制
    if (pl > BUFFER_SIZE) {
        log_msg("[Err] WS Frame too large: %llu (Max: %d). Dropping connection.", pl, BUFFER_SIZE);
        return -1; 
    }

    // 检查是否有足够的数据
    if ((unsigned long long)len < (unsigned long long)hl + pl) return 0;
    
    *head_len = hl; 
    *payload_len = (int)pl; // 安全转换为 int，因为上面已检查 pl <= BUFFER_SIZE
    
    return (long long)(hl + pl); 
}

// --- 客户端处理线程 (核心逻辑) ---
DWORD WINAPI client_handler(LPVOID p) {
    SOCKET c = (SOCKET)(UINT_PTR)p; 
    TLSContext tls; memset(&tls, 0, sizeof(tls));
    SOCKET r = INVALID_SOCKET;      
    
    char *c_buf = (char*)malloc(BUFFER_SIZE); 
    char *ws_read_buf = (char*)malloc(BUFFER_SIZE); 
    char *ws_send_buf = (char*)malloc(BUFFER_SIZE + 4096); 

    if (!c_buf || !ws_read_buf || !ws_send_buf) { goto cl_end; }
    int ws_buf_len = 0; int flag = 1; 
    setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
    
    // 1. 读取浏览器首包 (分析目标地址)
    int browser_len = recv_timeout(c, c_buf, BUFFER_SIZE, 10);
    if (browser_len <= 0) goto cl_end;
    c_buf[browser_len] = 0;
    
    char method[16], host[256]; int port = 80; int is_connect_method = 0;
    char *header_end = NULL;
    int header_len = 0;

    // 简单的协议判断
    if (c_buf[0] == 0x05) { send(c, "\x05\x00", 2, 0); goto cl_end; } 
    else {
        if (sscanf(c_buf, "%15s %255s", method, host) == 2) {
            char *p = strchr(host, ':');
            if (p) { *p = 0; port = atoi(p+1); }
            else if(stricmp(method, "CONNECT")==0) port = 443;
            
            if (stricmp(method, "CONNECT") == 0) is_connect_method = 1;
            
            // 计算 HTTP 头部长度
            header_end = strstr(c_buf, "\r\n\r\n");
            if (header_end) {
                header_len = (int)(header_end - c_buf) + 4;
            } else {
                header_len = browser_len;
            }
        } else { goto cl_end; }
    }
    
    log_msg("[Access] %s %s:%d (%s)", method, host, port, g_proxyConfig.type);

    // 2. DNS 解析与连接代理服务器
    struct hostent *h = gethostbyname(g_proxyConfig.host);
    if(!h) { log_msg("[Err] DNS Fail: %s", g_proxyConfig.host); goto cl_end; }
    
    r = socket(AF_INET, SOCK_STREAM, 0);
    if (r == INVALID_SOCKET) goto cl_end;
    setsockopt(r, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
    
    struct sockaddr_in a; memset(&a, 0, sizeof(a)); a.sin_family = AF_INET; a.sin_port = htons((unsigned short)g_proxyConfig.port);
    a.sin_addr = *(struct in_addr*)h->h_addr;
    
    if (connect(r, (struct sockaddr*)&a, sizeof(a)) != 0) { log_msg("[Err] TCP Connect Fail"); goto cl_end; }
    
    // 3. TLS 握手
    tls.sock = r;
    if (tls_init_connect(&tls) != 0) { log_msg("[Err] TLS Handshake Fail"); goto cl_end; }
    
    // 4. WebSocket 握手
    const char* sni_val = (strlen(g_proxyConfig.sni) > 0) ? g_proxyConfig.sni : g_proxyConfig.host;
    const char* req_path = (strlen(g_proxyConfig.path) > 0) ? g_proxyConfig.path : "/";
    
    int offset = snprintf(ws_send_buf, BUFFER_SIZE, 
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n", 
        req_path, sni_val, g_userAgentStr);

    tls_write(&tls, ws_send_buf, offset);

    // 读取 WS 响应
    int len = tls_read(&tls, ws_read_buf, BUFFER_SIZE-1);
    if (len <= 0 || !strstr(ws_read_buf, "101")) { log_msg("[Err] WS Handshake Fail (Not 101)"); goto cl_end; }
    
    // 5. 发送代理协议请求头 (VLESS/Trojan/Socks)
    int flen = 0;
    unsigned char proto_buf[1024];
    int proto_len = 0;
    
    BOOL is_vless = (_stricmp(g_proxyConfig.type, "vless") == 0);
    BOOL is_trojan = (_stricmp(g_proxyConfig.type, "trojan") == 0);

    if (is_vless) {
        // [VLESS Request]
        proto_buf[proto_len++] = 0x00; // Version
        parse_uuid(g_proxyConfig.user, proto_buf + proto_len); proto_len += 16; 
        proto_buf[proto_len++] = 0x00; // Addons Len
        proto_buf[proto_len++] = 0x01; // Cmd: TCP
        proto_buf[proto_len++] = (port >> 8) & 0xFF; proto_buf[proto_len++] = port & 0xFF;        
        proto_buf[proto_len++] = 0x03; // Type: Domain
        proto_buf[proto_len++] = (unsigned char)strlen(host);
        memcpy(proto_buf + proto_len, host, strlen(host)); proto_len += (int)strlen(host);
        
        flen = build_ws_frame((char*)proto_buf, proto_len, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);

    } else if (is_trojan) {
        // [Trojan Request]
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
        // [Socks5 Request] (Simplified)
        char auth[] = {0x05, 0x01, 0x00};
        if (strlen(g_proxyConfig.user) > 0) auth[2] = 0x02;
        flen = build_ws_frame(auth, 3, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
        char resp_buf[256]; ws_read_payload_exact(&tls, resp_buf, 2); 
        
        unsigned char socks_req[512]; int slen = 0;
        socks_req[slen++] = 0x05; socks_req[slen++] = 0x01; socks_req[slen++] = 0x00; socks_req[slen++] = 0x03;
        socks_req[slen++] = (unsigned char)strlen(host);
        memcpy(socks_req + slen, host, strlen(host)); slen += (int)strlen(host);
        socks_req[slen++] = (port >> 8) & 0xFF; socks_req[slen++] = port & 0xFF;
        flen = build_ws_frame((char*)socks_req, slen, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
        ws_read_payload_exact(&tls, resp_buf, 4); 
    }
    
    // 6. 响应浏览器并处理 Pipeline 数据
    if (is_connect_method) {
        const char *ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
        send(c, ok, strlen(ok), 0);
        
        if (browser_len > header_len) {
            int extra_len = browser_len - header_len;
            log_hex_simple("[Tx] Early Data", (unsigned char*)(c_buf + header_len), extra_len);
            flen = build_ws_frame(c_buf + header_len, extra_len, ws_send_buf);
            tls_write(&tls, ws_send_buf, flen);
        }
    } else {
        log_hex_simple("[Tx] Direct Data", (unsigned char*)c_buf, browser_len);
        flen = build_ws_frame(c_buf, browser_len, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
    }
    
    // 7. 双向数据转发循环
    fd_set fds; struct timeval tv; u_long mode = 1;
    ioctlsocket(c, FIONBIO, &mode); ioctlsocket(r, FIONBIO, &mode);
    ws_buf_len = 0; int hl, pl;
    long long frame_total; // 改为 long long 以匹配 check_ws_frame
    int vless_response_header_stripped = 0;

    while(1) {
        FD_ZERO(&fds); FD_SET(c, &fds); FD_SET(r, &fds);
        int pending = SSL_pending(tls.ssl);
        tv.tv_sec = 1; tv.tv_usec = 0;
        if (pending > 0 || ws_buf_len > 0) { tv.tv_sec = 0; tv.tv_usec = 0; }
        
        int n = select(0, &fds, NULL, NULL, &tv);
        if (n < 0) break;
        
        // [Browser -> Proxy]
        if (FD_ISSET(c, &fds)) {
            len = recv(c, c_buf, BUFFER_SIZE, 0);
            if (len > 0) {
                flen = build_ws_frame(c_buf, len, ws_send_buf);
                if (tls_write(&tls, ws_send_buf, flen) < 0) break;
            } else if (WSAGetLastError() != WSAEWOULDBLOCK) break;
        }
        
        // [Proxy -> Browser]
        if (FD_ISSET(r, &fds) || pending > 0) {
            if (ws_buf_len < BUFFER_SIZE) {
                len = tls_read(&tls, ws_read_buf + ws_buf_len, BUFFER_SIZE - ws_buf_len);
                if (len > 0) ws_buf_len += len;
                else if (len == -1) break; 
            }
        }
        
        // 处理 WebSocket 粘包/拆包
        while (ws_buf_len > 0) {
            frame_total = check_ws_frame((unsigned char*)ws_read_buf, ws_buf_len, &hl, &pl);
            
            if (frame_total < 0) goto cl_end; // 解析错误或包过大

            if (frame_total > 0) {
                int opcode = ws_read_buf[0] & 0x0F;
                if (opcode == 0x8) goto cl_end; // Close frame
                
                // 处理数据帧 (Binary=0x2, Text=0x1)
                if ((opcode == 0x1 || opcode == 0x2) && pl > 0) {
                    char* payload_ptr = ws_read_buf + hl;
                    int payload_size = pl;

                    // [VLESS 响应头剥离逻辑]
                    if (is_vless && !vless_response_header_stripped) {
                        if (payload_size >= 2) {
                            int addon_len = (unsigned char)payload_ptr[1];
                            int head_size = 2 + addon_len;
                            if (payload_size >= head_size) {
                                log_msg("[Rx] VLESS Header Stripped. Payload: %d bytes", payload_size - head_size);
                                payload_ptr += head_size;
                                payload_size -= head_size;
                                vless_response_header_stripped = 1;
                            } else {
                                // 数据包不足以剥离头部，这种情况下非常罕见。
                                // 简单策略：本次丢弃，等待重试（实际应缓存）
                                // 但由于 check_ws_frame 保证了帧完整性，这种情况意味着
                                // 服务器在一个 WS 帧里发了不到完整的 VLESS 头，极不可能。
                                payload_size = 0; 
                            }
                        } else { payload_size = 0; }
                    }

                    if (payload_size > 0) {
                        if (send_all(c, payload_ptr, payload_size) < 0) goto cl_end;
                    }
                }
                
                // 移动缓冲区剩余数据
                // frame_total 可能很大，确保 ws_buf_len 足够
                if (frame_total < ws_buf_len) {
                    memmove(ws_read_buf, ws_read_buf + frame_total, ws_buf_len - frame_total);
                }
                ws_buf_len -= (int)frame_total;
            } else { 
                if (ws_buf_len >= BUFFER_SIZE) {
                    log_msg("[Err] Buffer Full (%d bytes) but no complete frame. Flush.", ws_buf_len);
                    goto cl_end; 
                }
                break; // 数据不全，等待更多数据
            }
        }
    }

cl_end:
    free(c_buf); free(ws_read_buf); free(ws_send_buf); tls_close(&tls);
    if (r != INVALID_SOCKET) closesocket(r); if (c != INVALID_SOCKET) closesocket(c);
    return 0;
}

// 监听线程与管理函数 (保持不变)
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

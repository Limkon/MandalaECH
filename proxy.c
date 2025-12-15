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
            if (err != WSAECONNRESET && err != WSAECONNABORTED) {
                // log_msg("[Err] send_all fail: %d", err); 
            }
            return -1;
        }
        total += n; bytesleft -= n;
    }
    return total;
}

// 调试日志
void log_hex_simple(const char* tag, unsigned char* data, int len) {
    if (len <= 0) return;
    char buf[64] = {0};
    int max = len > 6 ? 6 : len;
    int p = 0;
    for(int i=0; i<max; i++) p += sprintf(buf+p, "%02X ", data[i]);
    log_msg("%s %d bytes: %s...", tag, len, buf);
}

// --- Base64 编码 (用于生成随机 WS Key) ---
void base64_encode_key(const unsigned char* src, char* dst) {
    const char* table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for(int i=0; i<16; i+=3) {
        int n = (src[i] << 16) + (src[i+1] << 8) + src[i+2];
        dst[0] = table[(n >> 18) & 0x3F];
        dst[1] = table[(n >> 12) & 0x3F];
        dst[2] = table[(n >> 6) & 0x3F];
        dst[3] = table[n & 0x3F];
        dst += 4;
    }
    *(dst-1) = '='; 
    *dst = 0;
}

// --- 客户端处理线程 (核心逻辑) ---
DWORD WINAPI client_handler(LPVOID p) {
    SOCKET c = (SOCKET)(UINT_PTR)p; 
    TLSContext tls; 
    SOCKET r = INVALID_SOCKET;      
    
    char *c_buf = NULL; 
    char *ws_read_buf = NULL; 
    char *ws_send_buf = NULL; 
    int ws_buf_len = 0; 
    int flag = 1; 

    int browser_len;
    char method[16], host[256]; 
    int port = 80; 
    int is_connect_method = 0;
    int is_socks5 = 0; 
    char *header_end = NULL;
    int header_len = 0;

    struct hostent *h;
    struct sockaddr_in a;
    const char* sni_val;
    const char* req_path;
    int offset;
    int len;

    int flen = 0;
    unsigned char proto_buf[2048]; // [修改] 增大缓冲区以适应 Mandala 加密 Payload
    int proto_len = 0;
    
    BOOL is_vless;
    BOOL is_trojan;
    BOOL is_shadowsocks;
    BOOL is_mandala; // [新增]
    
    struct in_addr ip4; 
    struct in6_addr ip6;
    
    fd_set fds; 
    struct timeval tv; 
    u_long mode = 1;
    int hl, pl;
    long long frame_total;
    int vless_response_header_stripped = 0;
    int err_code = 0;
    int retry_count = 0;
    
    // 初始化
    memset(&tls, 0, sizeof(tls));
    c_buf = (char*)malloc(BUFFER_SIZE); 
    ws_read_buf = (char*)malloc(BUFFER_SIZE); 
    ws_send_buf = (char*)malloc(BUFFER_SIZE + 4096); 

    if (!c_buf || !ws_read_buf || !ws_send_buf) goto cl_end; 
    setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
    
    // 1. 读取浏览器首包
    browser_len = recv_timeout(c, c_buf, BUFFER_SIZE, 10);
    if (browser_len <= 0) goto cl_end; 
    c_buf[browser_len] = 0;
    
    // 协议判断
    if (c_buf[0] == 0x05) { 
        send(c, "\x05\x00", 2, 0); 
        is_socks5 = 1;
        int n = recv_timeout(c, c_buf, BUFFER_SIZE, 10);
        if (n <= 0) goto cl_end;
        browser_len = n;
        if (c_buf[1] == 0x01) { // CONNECT
             if (c_buf[3] == 0x01) {
                 struct in_addr* addr_ptr = (struct in_addr*)&c_buf[4];
                 port = ntohs(*(unsigned short*)&c_buf[8]);
                 inet_ntop(AF_INET, addr_ptr, host, sizeof(host));
             } else if (c_buf[3] == 0x03) { // Domain
                 int dlen = c_buf[4];
                 memcpy(host, &c_buf[5], dlen);
                 host[dlen] = 0;
                 port = ntohs(*(unsigned short*)&c_buf[5+dlen]);
             }
             strcpy(method, "SOCKS5");
        } else {
             goto cl_end; 
        }
    } 
    else {
        if (sscanf(c_buf, "%15s %255s", method, host) == 2) {
            char *p = strchr(host, ':');
            if (p) { *p = 0; port = atoi(p+1); }
            else if(stricmp(method, "CONNECT")==0) port = 443;
            
            if (stricmp(method, "CONNECT") == 0) is_connect_method = 1;
            
            header_end = strstr(c_buf, "\r\n\r\n");
            if (header_end) {
                header_len = (int)(header_end - c_buf) + 4;
            } else {
                header_len = browser_len;
            }
        } else { goto cl_end; }
    }
    
    // log_msg("[Access] %s %s:%d", method, host, port);

    // 2. 连接代理服务器
    h = gethostbyname(g_proxyConfig.host);
    if(!h) { log_msg("[Err] DNS Fail: %s", g_proxyConfig.host); goto cl_end; }

    for (retry_count = 0; retry_count < 3; retry_count++) {
        r = socket(AF_INET, SOCK_STREAM, 0);
        if (r == INVALID_SOCKET) goto cl_end;
        
        setsockopt(r, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
        int timeout_ms = 5000;
        setsockopt(r, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(int));
        setsockopt(r, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout_ms, sizeof(int));

        memset(&a, 0, sizeof(a)); a.sin_family = AF_INET; a.sin_port = htons((unsigned short)g_proxyConfig.port);
        a.sin_addr = *(struct in_addr*)h->h_addr;
        
        if (connect(r, (struct sockaddr*)&a, sizeof(a)) == 0) {
            tls.sock = r;
            if (tls_init_connect(&tls) == 0) break;
            else tls_close(&tls);
        }
        closesocket(r); r = INVALID_SOCKET;
        Sleep(200);
    }

    if (r == INVALID_SOCKET || tls.ssl == NULL) goto cl_end;
    
    // 3. WebSocket 握手 (随机 Key)
    sni_val = (strlen(g_proxyConfig.sni) > 0) ? g_proxyConfig.sni : g_proxyConfig.host;
    req_path = (strlen(g_proxyConfig.path) > 0) ? g_proxyConfig.path : "/";
    
    unsigned char rnd_key[16];
    char ws_key_str[32];
    for(int i=0; i<16; i++) rnd_key[i] = rand() % 256;
    base64_encode_key(rnd_key, ws_key_str);

    offset = snprintf(ws_send_buf, BUFFER_SIZE, 
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n", 
        req_path, sni_val, g_userAgentStr, ws_key_str);

    tls_write(&tls, ws_send_buf, offset);

    // 读取 WS 响应
    len = tls_read(&tls, ws_read_buf, BUFFER_SIZE-1);
    if (len <= 0) goto cl_end;
    ws_read_buf[len] = 0;
    
    if (!strstr(ws_read_buf, "101")) { 
        log_msg("[Err] WS Handshake Fail: %.50s", ws_read_buf);
        goto cl_end; 
    }
    
    // 检查 Early Data (粘包)
    char* body_start = strstr(ws_read_buf, "\r\n\r\n");
    ws_buf_len = 0;
    if (body_start) {
        body_start += 4; 
        int header_bytes = (int)(body_start - ws_read_buf);
        int remaining = len - header_bytes;
        
        if (remaining > 0) {
            memmove(ws_read_buf, body_start, remaining);
            ws_buf_len = remaining;
        }
    }
    
    // 4. 发送代理协议头
    is_vless = (_stricmp(g_proxyConfig.type, "vless") == 0);
    is_trojan = (_stricmp(g_proxyConfig.type, "trojan") == 0);
    is_shadowsocks = (_stricmp(g_proxyConfig.type, "shadowsocks") == 0);
    is_mandala = (_stricmp(g_proxyConfig.type, "mandala") == 0); // [新增] 识别 Mandala 类型

    if (is_vless) {
        proto_buf[proto_len++] = 0x00; 
        parse_uuid(g_proxyConfig.user, proto_buf + proto_len); proto_len += 16; 
        proto_buf[proto_len++] = 0x00; 
        proto_buf[proto_len++] = 0x01; 
        proto_buf[proto_len++] = (port >> 8) & 0xFF; proto_buf[proto_len++] = port & 0xFF;        
        if (inet_pton(AF_INET, host, &ip4) == 1) {
            proto_buf[proto_len++] = 0x01; memcpy(proto_buf + proto_len, &ip4, 4); proto_len += 4;
        } else if (inet_pton(AF_INET6, host, &ip6) == 1) {
            proto_buf[proto_len++] = 0x03; memcpy(proto_buf + proto_len, &ip6, 16); proto_len += 16;
        } else {
            proto_buf[proto_len++] = 0x02; proto_buf[proto_len++] = (unsigned char)strlen(host);
            memcpy(proto_buf + proto_len, host, strlen(host)); proto_len += (int)strlen(host);
        }
        flen = build_ws_frame((char*)proto_buf, proto_len, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
    } else if (is_trojan) {
        char hex_pass[56 + 1]; trojan_password_hash(g_proxyConfig.pass, hex_pass);
        memcpy(proto_buf, hex_pass, 56); proto_len = 56;
        proto_buf[proto_len++] = 0x0D; proto_buf[proto_len++] = 0x0A;
        proto_buf[proto_len++] = 0x01; 
        if (inet_pton(AF_INET, host, &ip4) == 1) {
             proto_buf[proto_len++] = 0x01; memcpy(proto_buf + proto_len, &ip4, 4); proto_len += 4;
        } else if (inet_pton(AF_INET6, host, &ip6) == 1) {
             proto_buf[proto_len++] = 0x04; memcpy(proto_buf + proto_len, &ip6, 16); proto_len += 16;
        } else {
             proto_buf[proto_len++] = 0x03; proto_buf[proto_len++] = (unsigned char)strlen(host);
             memcpy(proto_buf + proto_len, host, strlen(host)); proto_len += strlen(host);
        }
        proto_buf[proto_len++] = (port >> 8) & 0xFF; proto_buf[proto_len++] = port & 0xFF;
        proto_buf[proto_len++] = 0x0D; proto_buf[proto_len++] = 0x0A;
        flen = build_ws_frame((char*)proto_buf, proto_len, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
    } else if (is_mandala) { 
        // [新增] Mandala 协议握手逻辑
        // 结构: Salt(4) + XOR( Hash(56) + PadLen(1) + Padding(N) + Cmd(1) + Addr... + CRLF(2) )

        // 1. 生成随机 Salt (4 bytes)
        unsigned char salt[4];
        for(int i=0; i<4; i++) salt[i] = rand() % 256;

        // 2. 准备明文 Payload
        unsigned char plaintext[2048]; // 临时明文缓冲区
        int p_len = 0;

        // 2.1 哈希 ID (SHA224 Hex String, 56 bytes)
        // 复用 trojan_password_hash 函数，因为它生成的正是 56字节的 hex string
        char hex_pass[57]; 
        trojan_password_hash(g_proxyConfig.pass, hex_pass);
        memcpy(plaintext + p_len, hex_pass, 56); p_len += 56;

        // 2.2 随机填充
        int pad_len = rand() % 16; // 0-15字节随机
        plaintext[p_len++] = (unsigned char)pad_len;
        for(int i=0; i<pad_len; i++) plaintext[p_len++] = rand() % 256;

        // 2.3 指令 CMD (0x01 Connect)
        plaintext[p_len++] = 0x01;

        // 2.4 目标地址 (SOCKS5 格式)
        if (inet_pton(AF_INET, host, &ip4) == 1) { // IPv4
             plaintext[p_len++] = 0x01; 
             memcpy(plaintext + p_len, &ip4, 4); p_len += 4;
        } else if (inet_pton(AF_INET6, host, &ip6) == 1) { // IPv6
             plaintext[p_len++] = 0x04; 
             memcpy(plaintext + p_len, &ip6, 16); p_len += 16;
        } else { // Domain
             plaintext[p_len++] = 0x03; 
             plaintext[p_len++] = (unsigned char)strlen(host);
             memcpy(plaintext + p_len, host, strlen(host)); p_len += strlen(host);
        }

        // 2.5 端口
        plaintext[p_len++] = (port >> 8) & 0xFF; 
        plaintext[p_len++] = port & 0xFF;

        // 2.6 CRLF
        plaintext[p_len++] = 0x0D; plaintext[p_len++] = 0x0A;

        // 3. 构造最终包 (Salt + XOR Encrypted Payload)
        // 将 Salt 写入发送缓冲头部
        memcpy(proto_buf, salt, 4);
        
        // 执行 XOR 加密并写入发送缓冲
        for(int i=0; i<p_len; i++) {
            proto_buf[4 + i] = plaintext[i] ^ salt[i % 4];
        }
        
        proto_len = 4 + p_len;

        // 4. 封装 WebSocket 帧并发送
        flen = build_ws_frame((char*)proto_buf, proto_len, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);

    } else if (is_shadowsocks) {
        if (inet_pton(AF_INET, host, &ip4) == 1) {
             proto_buf[proto_len++] = 0x01; memcpy(proto_buf + proto_len, &ip4, 4); proto_len += 4;
        } else if (inet_pton(AF_INET6, host, &ip6) == 1) {
             proto_buf[proto_len++] = 0x04; memcpy(proto_buf + proto_len, &ip6, 16); proto_len += 16;
        } else {
             proto_buf[proto_len++] = 0x03; proto_buf[proto_len++] = (unsigned char)strlen(host);
             memcpy(proto_buf + proto_len, host, strlen(host)); proto_len += strlen(host);
        }
        proto_buf[proto_len++] = (port >> 8) & 0xFF; proto_buf[proto_len++] = port & 0xFF;
        flen = build_ws_frame((char*)proto_buf, proto_len, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
    } else {
        char auth[] = {0x05, 0x01, 0x00}; 
        if (strlen(g_proxyConfig.user) > 0) auth[2] = 0x02; 
        flen = build_ws_frame(auth, 3, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
        char resp_buf[512]; 
        if (ws_read_payload_exact(&tls, resp_buf, 2) < 2) goto cl_end;
        if (resp_buf[1] == 0x02) {
            int ulen = strlen(g_proxyConfig.user);
            int plen = strlen(g_proxyConfig.pass);
            unsigned char auth_pkg[512];
            int ap_len = 0;
            auth_pkg[ap_len++] = 0x01; 
            auth_pkg[ap_len++] = ulen; memcpy(auth_pkg+ap_len, g_proxyConfig.user, ulen); ap_len += ulen;
            auth_pkg[ap_len++] = plen; memcpy(auth_pkg+ap_len, g_proxyConfig.pass, plen); ap_len += plen;
            flen = build_ws_frame((char*)auth_pkg, ap_len, ws_send_buf);
            tls_write(&tls, ws_send_buf, flen);
            if (ws_read_payload_exact(&tls, resp_buf, 2) < 2) goto cl_end;
            if (resp_buf[1] != 0x00) goto cl_end;
        } 
        int slen = 0;
        unsigned char socks_req[512];
        socks_req[slen++] = 0x05; socks_req[slen++] = 0x01; socks_req[slen++] = 0x00; 
        if (inet_pton(AF_INET, host, &ip4) == 1) {
            socks_req[slen++] = 0x01; memcpy(socks_req + slen, &ip4, 4); slen += 4;
        } else {
            socks_req[slen++] = 0x03; socks_req[slen++] = (unsigned char)strlen(host);
            memcpy(socks_req + slen, host, strlen(host)); slen += (int)strlen(host);
        }
        socks_req[slen++] = (port >> 8) & 0xFF; socks_req[slen++] = port & 0xFF;
        flen = build_ws_frame((char*)socks_req, slen, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
        if (ws_read_payload_exact(&tls, resp_buf, 4) == 0) goto cl_end;
        if (resp_buf[1] != 0x00) goto cl_end;
    }
    
    // 5. 响应浏览器
    if (is_socks5) {
        unsigned char s5_ok[] = {0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0};
        send(c, (char*)s5_ok, 10, 0);
    } else if (is_connect_method) {
        const char *ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
        if (send(c, ok, strlen(ok), 0) == SOCKET_ERROR) goto cl_end;
        if (browser_len > header_len) {
            int extra_len = browser_len - header_len;
            flen = build_ws_frame(c_buf + header_len, extra_len, ws_send_buf);
            tls_write(&tls, ws_send_buf, flen);
        }
    } else {
        flen = build_ws_frame(c_buf, browser_len, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
    }
    
    // 6. 转发循环
    ioctlsocket(c, FIONBIO, &mode); ioctlsocket(r, FIONBIO, &mode);

    while(1) {
        FD_ZERO(&fds); FD_SET(c, &fds); FD_SET(r, &fds);
        int pending = SSL_pending(tls.ssl);
        tv.tv_sec = 1; tv.tv_usec = 0;
        // [关键修复] 如果缓冲区里有之前粘包的数据，立即处理，不要等 select 超时
        if (pending > 0 || ws_buf_len > 0) { tv.tv_sec = 0; tv.tv_usec = 0; }
        
        int n = select(0, &fds, NULL, NULL, &tv);
        if (n < 0) break;
        
        if (FD_ISSET(c, &fds)) {
            len = recv(c, c_buf, BUFFER_SIZE, 0);
            if (len > 0) {
                flen = build_ws_frame(c_buf, len, ws_send_buf);
                if (tls_write(&tls, ws_send_buf, flen) < 0) {
                    // log_msg("[Debug] TLS write fail (Server Closed)");
                    break;
                }
            } else if (len == 0) {
                // log_msg("[Debug] Browser Closed Connection");
                break;
            } else if (WSAGetLastError() != WSAEWOULDBLOCK) {
                break;
            }
        }
        
        if (FD_ISSET(r, &fds) || pending > 0) {
            if (ws_buf_len < BUFFER_SIZE) {
                len = tls_read(&tls, ws_read_buf + ws_buf_len, BUFFER_SIZE - ws_buf_len);
                if (len > 0) ws_buf_len += len;
                else if (len == -1) {
                    // log_msg("[Debug] Server Closed Connection");
                    break; 
                }
            }
        }
        
        while (ws_buf_len > 0) {
            frame_total = check_ws_frame((unsigned char*)ws_read_buf, ws_buf_len, &hl, &pl);
            if (frame_total < 0) goto cl_end;
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
                                payload_ptr += head_size;
                                payload_size -= head_size;
                                vless_response_header_stripped = 1;
                            } else { 
                                // [修复] 数据包太小无法剥离头时，暂时当作空处理(丢弃)，而不是崩溃
                                payload_size = 0; 
                            }
                        } else { payload_size = 0; }
                    }
                    if (payload_size > 0) {
                        if (send_all(c, payload_ptr, payload_size) < 0) goto cl_end;
                    }
                }
                if (frame_total < ws_buf_len) {
                    memmove(ws_read_buf, ws_read_buf + frame_total, ws_buf_len - frame_total);
                }
                ws_buf_len -= (int)frame_total;
            } else { 
                if (ws_buf_len >= BUFFER_SIZE) goto cl_end; 
                break; 
            }
        }
    }

cl_end:
    if (c_buf) free(c_buf); 
    if (ws_read_buf) free(ws_read_buf); 
    if (ws_send_buf) free(ws_send_buf); 
    tls_close(&tls);
    if (r != INVALID_SOCKET) closesocket(r); 
    if (c != INVALID_SOCKET) closesocket(c);
    return 0;
}

// 监听线程与管理函数
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

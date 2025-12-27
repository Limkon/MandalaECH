#include "proxy.h"
#include "crypto.h"
#include "utils.h"
#include "common.h"
#include <openssl/sha.h>
#include <time.h> 

// [Safety] 全局活跃连接计数器与内存水位监控
static volatile LONG g_active_connections = 0;
volatile LONG64 g_total_allocated_mem = 0; 

// [Concurrency] 客户端线程上下文 - 确保配置在线程间隔离
typedef struct {
    SOCKET clientSock;
    ProxyConfig config;          
    char userAgent[512];         
    CryptoSettings cryptoSettings; 
} ClientContext;

// --- 辅助函数：解析 UUID ---
void parse_uuid(const char* uuid_str, unsigned char* out) {
    if (!uuid_str || !out) return;
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
            p++; 
        }
    }
}

// --- 辅助函数：Trojan 密码哈希 ---
void trojan_password_hash(const char* password, char* out_hex) {
    if (!password || !out_hex) return;
    unsigned char digest[SHA224_DIGEST_LENGTH];
    SHA224((unsigned char*)password, (size_t)strlen(password), digest);
    for(int i = 0; i < SHA224_DIGEST_LENGTH; i++) {
        snprintf(out_hex + (i * 2), 3, "%02x", digest[i]); 
    }
    out_hex[SHA224_DIGEST_LENGTH * 2] = 0;
}

// 接收超时辅助函数
int recv_timeout(SOCKET s, char *buf, int len, int timeout_sec) {
    if (s == INVALID_SOCKET) return -1;
    fd_set fds; 
    FD_ZERO(&fds); 
    FD_SET(s, &fds);
    struct timeval tv = { timeout_sec, 0 };
    int n = select(0, &fds, NULL, NULL, &tv);
    if (n == 0) return -2; // Timeout
    if (n < 0) return -1;  // Error
    return recv(s, buf, len, 0);
}

// 健壮的头部读取
int read_header_robust(SOCKET s, char* buf, int max_len, int timeout_sec) {
    int total_read = 0;
    int remaining_time = timeout_sec;
    while (total_read < max_len - 1 && remaining_time > 0) {
        int n = recv_timeout(s, buf + total_read, max_len - 1 - total_read, 1);
        if (n == -2) { remaining_time--; continue; }
        if (n <= 0) return -1; 
        total_read += n;
        buf[total_read] = 0; 
        
        // SOCKS5 探测 (05 01 00 或 05 02 ...)
        if (buf[0] == 0x05) { 
            if (total_read >= 2) return total_read; 
        }
        // HTTP 探测
        else { 
            if (strstr(buf, "\r\n\r\n")) return total_read; 
        }
        
        if (total_read > 8192) break; // 防御超大头部攻击
    }
    return total_read > 0 ? total_read : -1;
}

// [Fix] 健壮的 WebSocket 响应读取 (防止握手包分片导致连接中断)
int read_ws_response_robust(TLSContext* tls, char* buf, int max_len, int timeout_ms) {
    int total_read = 0;
    DWORD start_time = GetTickCount();
    
    while (total_read < max_len - 1) {
        if ((GetTickCount() - start_time) > (DWORD)timeout_ms) break;

        // 尝试非阻塞读取
        int n = tls_read(tls, buf + total_read, max_len - 1 - total_read);
        if (n > 0) {
            total_read += n;
            buf[total_read] = 0;
            // 检查是否收到完整的 HTTP 头结束标记
            if (strstr(buf, "\r\n\r\n")) return total_read;
        } else if (n < 0) {
             // 严重错误
             return -1; 
        }
        Sleep(10);
    }
    return total_read > 0 ? total_read : -1;
}

// 发送全部数据 (非阻塞兼容)
int send_all(SOCKET s, const char *buf, int len) {
    if (s == INVALID_SOCKET) return -1;
    int total = 0; 
    int bytesleft = len; 
    int n;
    while(total < len) {
        n = send(s, buf+total, bytesleft, 0);
        if (n == -1) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) { 
                fd_set wfd; FD_ZERO(&wfd); FD_SET(s, &wfd);
                struct timeval tv = { 1, 0 };
                if (select(0, NULL, &wfd, NULL, &tv) > 0) continue;
                return -1;
            }
            return -1;
        }
        total += n; bytesleft -= n;
    }
    return total;
}

// [Fix] 修复 Base64 编码 (Win7 Runtime Error 根源)
// 原代码强制读取 16 字节后的内容导致越界
void base64_encode_key(const unsigned char* src, char* dst) {
    const char* table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i = 0;
    // 处理前 15 字节 (3 * 5)
    for(i = 0; i < 15; i += 3) {
        int n = (src[i] << 16) + (src[i+1] << 8) + src[i+2];
        dst[0] = table[(n >> 18) & 0x3F];
        dst[1] = table[(n >> 12) & 0x3F];
        dst[2] = table[(n >> 6) & 0x3F];
        dst[3] = table[n & 0x3F];
        dst += 4;
    }
    // 处理最后 1 个字节 (src[15])
    if (i < 16) {
        int n = src[i] << 16; 
        dst[0] = table[(n >> 18) & 0x3F];
        dst[1] = table[(n >> 12) & 0x3F];
        dst[2] = '=';
        dst[3] = '=';
        dst += 4;
    }
    *dst = 0;
}

// [Optimization] 动态内存分配与监控包装器
void* proxy_malloc(size_t size) {
    if (g_total_allocated_mem + (LONG64)size > MAX_TOTAL_MEMORY_USAGE) {
        // [Safety] 避免日志输出导致死锁或递归，此处静默失败或仅返回 NULL
        return NULL;
    }
    void* p = malloc(size);
    if (p) InterlockedAdd64(&g_total_allocated_mem, (LONG64)size);
    return p;
}

void proxy_free(void* p, size_t size) {
    if (p) {
        free(p);
        InterlockedAdd64(&g_total_allocated_mem, -(LONG64)size);
    }
}

// --- 客户端处理线程 (核心逻辑) ---
DWORD WINAPI client_handler(LPVOID p) {
    InterlockedIncrement(&g_active_connections);
    ClientContext* ctx = (ClientContext*)p;
    if (!ctx) { InterlockedDecrement(&g_active_connections); return 0; }

    SOCKET c = ctx->clientSock;
    ProxyConfig localConfig = ctx->config; 
    CryptoSettings localCrypto = ctx->cryptoSettings;
    char localUserAgent[512];
    
    memset(localUserAgent, 0, sizeof(localUserAgent));
    strncpy(localUserAgent, ctx->userAgent, sizeof(localUserAgent)-1);
    
    free(ctx); 

    TLSContext tls; memset(&tls, 0, sizeof(tls));
    SOCKET r = INVALID_SOCKET;      
    char *c_buf = NULL, *ws_read_buf = NULL, *ws_send_buf = NULL; 
    int ws_read_buf_cap = IO_BUFFER_SIZE; 
    int ws_buf_len = 0; 
    int browser_len;
    char method[16], host[256], port_str[16];
    int port = 80, is_connect_method = 0, is_socks5 = 0;
    char *header_end = NULL; int header_len = 0;
    struct addrinfo hints, *res = NULL, *ptr = NULL;

    // 分配初始缓冲区并记录内存占用
    c_buf = (char*)proxy_malloc(IO_BUFFER_SIZE); 
    ws_read_buf = (char*)proxy_malloc(ws_read_buf_cap); 
    ws_send_buf = (char*)proxy_malloc(IO_BUFFER_SIZE + 4096); 
    if (!c_buf || !ws_read_buf || !ws_send_buf) {
        log_msg("[Err] Memory allocation failed");
        goto cl_end; 
    }

    int flag = 1;
    setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
    
    // 1. 读取浏览器首包
    browser_len = read_header_robust(c, c_buf, IO_BUFFER_SIZE, 10);
    if (browser_len <= 0) goto cl_end; 
    c_buf[browser_len] = 0;
    
    // 协议探测
    if (c_buf[0] == 0x05) { 
        // Socks5 处理
        send(c, "\x05\x00", 2, 0); // 无需认证
        is_socks5 = 1;
        
        int n = recv_timeout(c, c_buf, IO_BUFFER_SIZE, 10);
        if (n <= 0) goto cl_end;
        browser_len = n;
        
        if (c_buf[1] == 0x01) { // CONNECT
             if (c_buf[3] == 0x01) { // IPv4
                 inet_ntop(AF_INET, &c_buf[4], host, sizeof(host));
                 port = ntohs(*(unsigned short*)&c_buf[8]);
             } else if (c_buf[3] == 0x03) { // Domain
                 int dlen = (unsigned char)c_buf[4];
                 if (dlen > 250) goto cl_end; // 防止溢出
                 memcpy(host, &c_buf[5], dlen); host[dlen] = 0;
                 port = ntohs(*(unsigned short*)&c_buf[5+dlen]);
             } else goto cl_end;
             strcpy(method, "SOCKS5");
        } else goto cl_end;
    } 
    else {
        // HTTP/HTTPS 处理
        if (sscanf(c_buf, "%15s %250s", method, host) == 2) {
            char *p_col = strchr(host, ':');
            if (p_col) { *p_col = 0; port = atoi(p_col+1); }
            else if(stricmp(method, "CONNECT")==0) port = 443;
            
            if (stricmp(method, "CONNECT") == 0) is_connect_method = 1;
            header_end = strstr(c_buf, "\r\n\r\n");
            header_len = header_end ? (int)(header_end - c_buf) + 4 : browser_len;
        } else goto cl_end;
    }
    
    // [Desensitization] 日志脱敏处理 (隐藏部分 Host 信息)
    char display_host[256]; 
    strncpy(display_host, host, 255); display_host[255] = 0;
#if LOG_DESENSITIZE
    if (strlen(display_host) > 4) {
        // 简单脱敏：保留首尾，中间打码
        size_t dlen = strlen(display_host);
        if (dlen > 8) {
            for(size_t i=3; i<dlen-3; i++) if(display_host[i]!='.') display_host[i] = '*';
        }
    }
#endif
    log_msg("[Proxy] %s -> %s:%d", method, display_host, port);
    
    // 2. 连接代理服务器
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    snprintf(port_str, sizeof(port_str), "%d", localConfig.port);

    if (getaddrinfo(localConfig.host, port_str, &hints, &res) != 0) {
        log_msg("[Err] DNS Fail: %s", localConfig.host); goto cl_end;
    }

    for (int retry = 0; retry < 3; retry++) {
        for (ptr = res; ptr != NULL; ptr = ptr->ai_next) {
            r = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
            if (r == INVALID_SOCKET) continue;

            setsockopt(r, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
            int timeout_ms = 5000;
            setsockopt(r, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(int));
            setsockopt(r, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout_ms, sizeof(int));

            if (connect(r, ptr->ai_addr, (int)ptr->ai_addrlen) == 0) {
                tls.sock = r;
                // 使用 CryptoSettings 进行 TLS 握手 (支持分片/填充/ECH)
                if (tls_init_connect(&tls, localConfig.sni, localConfig.host, &localCrypto) == 0) {
                    break;
                } else {
                    tls_close(&tls); closesocket(r); r = INVALID_SOCKET;
                }
            } else {
                closesocket(r); r = INVALID_SOCKET;
            }
        }
        if (r != INVALID_SOCKET && tls.ssl != NULL) break;
        Sleep(200);
    }
    if (r == INVALID_SOCKET || tls.ssl == NULL) {
        log_msg("[Err] Connect Failed: %s", localConfig.host);
        goto cl_end;
    }
    
    // 3. WebSocket 握手
    const char* sni_val = (strlen(localConfig.sni) > 0) ? localConfig.sni : localConfig.host;
    const char* req_path = (strlen(localConfig.path) > 0) ? localConfig.path : "/";
    unsigned char rnd_key[16]; char ws_key_str[32];
    for(int i=0; i<16; i++) rnd_key[i] = rand() % 256;
    base64_encode_key(rnd_key, ws_key_str);

    int offset = snprintf(ws_send_buf, IO_BUFFER_SIZE, 
        "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", 
        req_path, sni_val, localUserAgent, ws_key_str);

    tls_write(&tls, ws_send_buf, offset);
    
    // [Fix] 使用健壮的 WebSocket 响应读取
    int hlen = read_ws_response_robust(&tls, ws_read_buf, ws_read_buf_cap, 5000);
    if (hlen <= 0) goto cl_end;
    ws_read_buf[hlen] = 0;
    
    if (!strstr(ws_read_buf, "101")) { 
        log_msg("[Err] WS Handshake Fail: %.50s", ws_read_buf); goto cl_end; 
    }
    
    // 处理 Early Data (粘包)
    char* body_start = strstr(ws_read_buf, "\r\n\r\n");
    if (body_start) {
        body_start += 4; 
        int header_bytes = (int)(body_start - ws_read_buf);
        int remaining = hlen - header_bytes;
        if (remaining > 0) {
            memmove(ws_read_buf, body_start, remaining);
            ws_buf_len = remaining;
        } else {
            ws_buf_len = 0;
        }
    } else {
        ws_buf_len = 0;
    }
    
    // 4. 代理协议封包 (VLESS / Trojan / SS / Mandala / Socks)
    unsigned char proto_buf[2048]; 
    int proto_len = 0, flen = 0;
    struct in_addr ip4; struct in6_addr ip6;
    
    BOOL is_vless = (_stricmp(localConfig.type, "vless") == 0);
    BOOL is_trojan = (_stricmp(localConfig.type, "trojan") == 0);
    BOOL is_shadowsocks = (_stricmp(localConfig.type, "shadowsocks") == 0);
    BOOL is_mandala = (_stricmp(localConfig.type, "mandala") == 0);

    if (is_vless) {
        proto_buf[proto_len++] = 0x00; // Version
        parse_uuid(localConfig.user, proto_buf + proto_len); proto_len += 16; 
        proto_buf[proto_len++] = 0x00; // Addons
        proto_buf[proto_len++] = 0x01; // TCP
        proto_buf[proto_len++] = (port >> 8) & 0xFF; proto_buf[proto_len++] = port & 0xFF;        
        if (inet_pton(AF_INET, host, &ip4) == 1) {
            proto_buf[proto_len++] = 0x01; memcpy(proto_buf + proto_len, &ip4, 4); proto_len += 4;
        } else if (inet_pton(AF_INET6, host, &ip6) == 1) {
            proto_buf[proto_len++] = 0x03; memcpy(proto_buf + proto_len, &ip6, 16); proto_len += 16;
        } else {
            int hlen_local = strlen(host);
            proto_buf[proto_len++] = 0x02; proto_buf[proto_len++] = (unsigned char)hlen_local;
            memcpy(proto_buf + proto_len, host, hlen_local); proto_len += hlen_local;
        }
        flen = build_ws_frame((char*)proto_buf, proto_len, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
    } 
    else if (is_trojan || is_mandala) {
        char hex_pass[SHA224_DIGEST_LENGTH * 2 + 1]; 
        trojan_password_hash(localConfig.pass, hex_pass);
        
        if (is_mandala) { // Mandala 自定义协议
            unsigned char salt[4], plaintext[2048]; 
            int p_len = 0;
            for(int i=0; i<4; i++) salt[i] = rand() % 256;
            
            memcpy(plaintext, hex_pass, 56); p_len = 56;
            int pad = rand() % 16; plaintext[p_len++] = (unsigned char)pad;
            for(int i=0; i<pad; i++) plaintext[p_len++] = rand() % 256;
            
            plaintext[p_len++] = 0x01; // TCP
            if (inet_pton(AF_INET, host, &ip4) == 1) {
                 plaintext[p_len++] = 0x01; memcpy(plaintext + p_len, &ip4, 4); p_len += 4;
            } else if (inet_pton(AF_INET6, host, &ip6) == 1) {
                 plaintext[p_len++] = 0x04; memcpy(plaintext + p_len, &ip6, 16); p_len += 16;
            } else {
                 plaintext[p_len++] = 0x03; plaintext[p_len++] = (unsigned char)strlen(host);
                 memcpy(plaintext + p_len, host, strlen(host)); p_len += strlen(host);
            }
            plaintext[p_len++] = (port >> 8) & 0xFF; plaintext[p_len++] = port & 0xFF;
            plaintext[p_len++] = 0x0D; plaintext[p_len++] = 0x0A;

            memcpy(proto_buf, salt, 4);
            for(int i=0; i<p_len; i++) proto_buf[4 + i] = plaintext[i] ^ salt[i % 4];
            proto_len = 4 + p_len;
        } else { // Trojan 标准协议
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
        }
        flen = build_ws_frame((char*)proto_buf, proto_len, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
    } 
    else if (is_shadowsocks) {
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
    }
    else { // SOCKS5 Outbound
        char auth[] = {0x05, 0x01, 0x00}; 
        if (strlen(localConfig.user) > 0) auth[2] = 0x02; 
        flen = build_ws_frame(auth, 3, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
        
        char resp_buf[512]; 
        if (ws_read_payload_exact(&tls, resp_buf, 2) < 2) goto cl_end;
        if (resp_buf[1] == 0x02) {
            int ulen = strlen(localConfig.user);
            int plen = strlen(localConfig.pass);
            unsigned char auth_pkg[512]; int ap_len = 0;
            auth_pkg[ap_len++] = 0x01; 
            auth_pkg[ap_len++] = ulen; memcpy(auth_pkg+ap_len, localConfig.user, ulen); ap_len += ulen;
            auth_pkg[ap_len++] = plen; memcpy(auth_pkg+ap_len, localConfig.pass, plen); ap_len += plen;
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
        send(c, ok, strlen(ok), 0);
        if (browser_len > header_len) {
            int extra_len = browser_len - header_len;
            flen = build_ws_frame(c_buf + header_len, extra_len, ws_send_buf);
            tls_write(&tls, ws_send_buf, flen);
        }
    } else {
        flen = build_ws_frame(c_buf, browser_len, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
    }
    
    // 6. 转发循环 (非阻塞 IO)
    u_long mode = 1; 
    ioctlsocket(c, FIONBIO, &mode); 
    ioctlsocket(r, FIONBIO, &mode);
    fd_set fds; struct timeval tv; 
    int vless_response_header_stripped = 0;
    
    while(1) {
        FD_ZERO(&fds); FD_SET(c, &fds); FD_SET(r, &fds);
        int pending = SSL_pending(tls.ssl);
        tv.tv_sec = 1; tv.tv_usec = 0;
        
        // 如果有缓存数据，不再等待
        if (pending > 0 || ws_buf_len > 0) { tv.tv_sec = 0; tv.tv_usec = 0; }
        
        int n = select(0, &fds, NULL, NULL, &tv);
        if (n < 0) break;
        
        // 浏览器 -> 代理
        if (FD_ISSET(c, &fds)) {
            int len = recv(c, c_buf, IO_BUFFER_SIZE, 0);
            if (len > 0) {
                flen = build_ws_frame(c_buf, len, ws_send_buf);
                if (tls_write(&tls, ws_send_buf, flen) < 0) break;
            } else if (len == 0) {
                break;
            } else if (WSAGetLastError() != WSAEWOULDBLOCK) {
                break;
            }
        }
        
        // 代理 -> 浏览器
        if (FD_ISSET(r, &fds) || pending > 0) {
            // [Safety] 不再动态扩容，防止 OOM 或 realloc 失败
            if (ws_buf_len < ws_read_buf_cap) {
                int len = tls_read(&tls, ws_read_buf + ws_buf_len, ws_read_buf_cap - ws_buf_len);
                if (len > 0) ws_buf_len += len;
                else if (len < 0) break; 
            }
        }
        
        // 解析 WebSocket 帧
        while (ws_buf_len > 0) {
            int hl, pl;
            long long frame_total = check_ws_frame((unsigned char*)ws_read_buf, ws_buf_len, &hl, &pl);
            if (frame_total < 0) goto cl_end; // 帧过大或错误
            if (frame_total > 0) {
                int opcode = ws_read_buf[0] & 0x0F;
                if (opcode == 0x8) goto cl_end; // Close
                
                if ((opcode == 0x1 || opcode == 0x2) && pl > 0) {
                    char* payload_ptr = ws_read_buf + hl;
                    int payload_size = pl;
                    
                    // [Fix] VLESS 响应头剥离修复 (处理粘包/分包)
                    if (is_vless && !vless_response_header_stripped) {
                        if (payload_size >= 2) {
                            int addon_len = (unsigned char)payload_ptr[1];
                            int head_size = 2 + addon_len;
                            if (payload_size >= head_size) {
                                payload_ptr += head_size;
                                payload_size -= head_size;
                                vless_response_header_stripped = 1;
                            } else { 
                                // 数据不足以剥离头，跳出循环等待下一包 (不要 memmove 丢弃！)
                                break; 
                            }
                        } else {
                             // 数据太短，等待下一包
                             break;
                        }
                    }
                    
                    if (payload_size > 0) {
                        if (send_all(c, payload_ptr, payload_size) < 0) goto cl_end;
                    }
                }
                
                // 移除已处理帧
                if (frame_total < ws_buf_len) {
                    memmove(ws_read_buf, ws_read_buf + frame_total, ws_buf_len - (int)frame_total);
                }
                ws_buf_len -= (int)frame_total;
            } else break; // 数据不完整
        }
    }

cl_end:
    if (res) freeaddrinfo(res);
    // 释放内存并更新全局水位
    proxy_free(c_buf, IO_BUFFER_SIZE);
    proxy_free(ws_read_buf, ws_read_buf_cap);
    proxy_free(ws_send_buf, IO_BUFFER_SIZE + 4096);
    
    tls_close(&tls);
    if (r != INVALID_SOCKET) closesocket(r); 
    if (c != INVALID_SOCKET) closesocket(c);
    
    InterlockedDecrement(&g_active_connections);
    return 0;
}

// 监听线程与管理函数
DWORD WINAPI server_thread(LPVOID p) {
    g_listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr; 
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; 
    addr.sin_port = htons(g_localPort);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    
    int opt = 1; 
    setsockopt(g_listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    
    if (bind(g_listen_sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        log_msg("[Fatal] Port %d bind fail", g_localPort); 
        g_proxyRunning = FALSE; 
        return 0;
    }
    
    listen(g_listen_sock, SOMAXCONN);
    log_msg("[System] Server listening on 127.0.0.1:%d", g_localPort);
    
    while(g_proxyRunning) {
        SOCKET c = accept(g_listen_sock, NULL, NULL);
        if (c != INVALID_SOCKET) {
            // [Safety] 最大连接数限制
            if (g_active_connections >= MAX_CONNECTIONS) {
                closesocket(c);
                Sleep(10); 
                continue;
            }

            // [Concurrency] 配置快照
            ClientContext* ctx = (ClientContext*)malloc(sizeof(ClientContext));
            if (ctx) {
                ctx->clientSock = c;
                EnterCriticalSection(&g_configLock);
                ctx->config = g_proxyConfig; 
                strncpy(ctx->userAgent, g_userAgentStr, sizeof(ctx->userAgent)-1);
                ctx->userAgent[sizeof(ctx->userAgent)-1] = 0;
                
                ctx->cryptoSettings.enableFragment = g_enableFragment;
                ctx->cryptoSettings.fragMin = g_fragSizeMin;
                ctx->cryptoSettings.fragMax = g_fragSizeMax;
                ctx->cryptoSettings.fragDelay = g_fragDelayMs;
                ctx->cryptoSettings.enablePadding = g_enablePadding;
                ctx->cryptoSettings.padMin = g_padSizeMin;
                ctx->cryptoSettings.padMax = g_padSizeMax;
                ctx->cryptoSettings.enableChromeCiphers = g_enableChromeCiphers;
                LeaveCriticalSection(&g_configLock);

                HANDLE hClient = CreateThread(NULL, 0, client_handler, (LPVOID)ctx, 0, NULL);
                if (hClient) CloseHandle(hClient); 
                else { 
                    free(ctx); 
                    closesocket(c); 
                }
            } else {
                closesocket(c);
            }
        } else break;
    }
    return 0;
}

void StartProxyCore() {
    if (g_proxyRunning) return;
    srand((unsigned int)time(NULL)); // [Add] 初始化随机种子
    g_proxyRunning = TRUE;
    hProxyThread = CreateThread(NULL, 0, server_thread, NULL, 0, NULL);
    if (!hProxyThread) g_proxyRunning = FALSE;
}

void StopProxyCore() {
    g_proxyRunning = FALSE;
    if (g_listen_sock != INVALID_SOCKET) { 
        closesocket(g_listen_sock); 
        g_listen_sock = INVALID_SOCKET; 
    }
    if (hProxyThread) { 
        WaitForSingleObject(hProxyThread, 2000); 
        CloseHandle(hProxyThread); 
        hProxyThread = NULL; 
    }
    log_msg("[System] Proxy Stopped");
}

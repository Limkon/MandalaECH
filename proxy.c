#include <stdio.h>  // [修复] 必需的头文件
#include <stdlib.h>
#include <string.h>
#include "proxy.h"
#include "crypto.h"
#include "utils.h" 
#include <ws2tcpip.h>
#include <openssl/sha.h>

// 客户端线程上下文
typedef struct {
    SOCKET clientSock;
    ProxyConfig config;
} ClientContext;

extern char g_dohUrl[512];

// --- 辅助函数 ---
void parse_uuid(const char* uuid_str, unsigned char* out) {
    const char* p = uuid_str; int i = 0;
    while (*p && i < 16) {
        if (*p == '-' || *p == ' ' || *p == '{' || *p == '}') { p++; continue; }
        int v; if (sscanf(p, "%2x", &v) == 1) { out[i++] = (unsigned char)v; p += 2; } else { p++; }
    }
}

void trojan_password_hash(const char* password, char* out_hex) {
    unsigned char digest[SHA224_DIGEST_LENGTH];
    SHA224((unsigned char*)password, strlen(password), digest);
    for(int i = 0; i < SHA224_DIGEST_LENGTH; i++) snprintf(out_hex + (i * 2), 3, "%02x", digest[i]);
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
        } total += n; bytesleft -= n;
    } return total;
}

void base64_encode_key(const unsigned char* src, char* dst) {
    const char* table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for(int i=0; i<16; i+=3) {
        int n = (src[i] << 16) + (src[i+1] << 8) + src[i+2];
        dst[0] = table[(n >> 18) & 0x3F]; dst[1] = table[(n >> 12) & 0x3F];
        dst[2] = table[(n >> 6) & 0x3F]; dst[3] = table[n & 0x3F];
        dst += 4;
    } *(dst-1) = '='; *dst = 0;
}

// --- 客户端处理线程 ---
DWORD WINAPI client_handler(LPVOID p) {
    ClientContext* ctx = (ClientContext*)p;
    if (!ctx) return 0;

    SOCKET c = ctx->clientSock;
    ProxyConfig localConfig = ctx->config; 
    free(ctx); 

    // [ECH 自动获取]
    if (strlen(localConfig.outer_sni) > 0 && strlen(localConfig.ech) == 0) {
        char* dynEch = FetchECHFromDoH(g_dohUrl, localConfig.outer_sni);
        if (dynEch) {
            snprintf(localConfig.ech, sizeof(localConfig.ech), "%s", dynEch);
            free(dynEch);
        }
    }

    TLSContext tls; 
    SOCKET r = INVALID_SOCKET;      
    char *c_buf = (char*)malloc(BUFFER_SIZE); 
    char *ws_read_buf = (char*)malloc(BUFFER_SIZE); 
    char *ws_send_buf = (char*)malloc(BUFFER_SIZE + 4096); 
    int ws_buf_len = 0; int flag = 1; 

    if (!c_buf || !ws_read_buf || !ws_send_buf) goto cl_end; 
    setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
    
    // 读取浏览器请求
    int browser_len = recv_timeout(c, c_buf, BUFFER_SIZE, 10);
    if (browser_len <= 0) goto cl_end; 
    c_buf[browser_len] = 0;
    
    // 协议判断
    char method[16], host[256]; int port = 80; 
    int is_socks5 = 0; int is_connect_method = 0;
    int header_len = 0;

    if (c_buf[0] == 0x05) { 
        send(c, "\x05\x00", 2, 0); is_socks5 = 1;
        int n = recv_timeout(c, c_buf, BUFFER_SIZE, 10);
        if (n <= 0) goto cl_end; browser_len = n;
        if (c_buf[1] == 0x01) { 
             if (c_buf[3] == 0x01) {
                 struct in_addr* addr_ptr = (struct in_addr*)&c_buf[4];
                 port = ntohs(*(unsigned short*)&c_buf[8]);
                 inet_ntop(AF_INET, addr_ptr, host, sizeof(host));
             } else if (c_buf[3] == 0x03) { 
                 int dlen = c_buf[4]; memcpy(host, &c_buf[5], dlen); host[dlen] = 0;
                 port = ntohs(*(unsigned short*)&c_buf[5+dlen]);
             } strcpy(method, "SOCKS5");
        } else { goto cl_end; }
    } else {
        if (sscanf(c_buf, "%15s %255s", method, host) == 2) {
            char *ptr = strchr(host, ':');
            if (ptr) { *ptr = 0; port = atoi(ptr+1); }
            else if(stricmp(method, "CONNECT")==0) port = 443;
            if (stricmp(method, "CONNECT") == 0) is_connect_method = 1;
            char *hend = strstr(c_buf, "\r\n\r\n");
            header_len = hend ? (int)(hend - c_buf) + 4 : browser_len;
        } else { goto cl_end; }
    }
    
    // [连接逻辑]
    const char* connect_host = (strlen(localConfig.outer_sni) > 0) ? localConfig.outer_sni : localConfig.host;
    struct hostent *h = gethostbyname(connect_host);
    if(!h) { h = gethostbyname(localConfig.host); if (!h) goto cl_end; }

    int retry_count;
    for (retry_count = 0; retry_count < 3; retry_count++) {
        r = socket(AF_INET, SOCK_STREAM, 0);
        if (r == INVALID_SOCKET) goto cl_end;
        
        setsockopt(r, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
        int timeout_ms = 5000;
        setsockopt(r, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, 4);
        setsockopt(r, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout_ms, 4);

        struct sockaddr_in a; memset(&a, 0, sizeof(a)); 
        a.sin_family = AF_INET; a.sin_port = htons((unsigned short)localConfig.port);
        a.sin_addr = *(struct in_addr*)h->h_addr;
        
        if (connect(r, (struct sockaddr*)&a, sizeof(a)) == 0) {
            tls.sock = r;
            
            // [修复] ECH 握手：传入 Inner SNI
            const char* handshake_sni = localConfig.sni;
            if (strlen(handshake_sni) == 0) handshake_sni = localConfig.host;

            if (tls_init_connect(&tls, handshake_sni, localConfig.host, localConfig.ech) == 0) break;
            else tls_close(&tls);
        }
        closesocket(r); r = INVALID_SOCKET;
        Sleep(200);
    }

    if (r == INVALID_SOCKET || tls.ssl == NULL) goto cl_end;
    
    // WebSocket 握手
    const char* req_host = (strlen(localConfig.sni) > 0) ? localConfig.sni : localConfig.host;
    const char* req_path = (strlen(localConfig.path) > 0) ? localConfig.path : "/";
    
    unsigned char rnd_key[16]; char ws_key_str[32];
    for(int i=0; i<16; i++) rnd_key[i] = rand() % 256;
    base64_encode_key(rnd_key, ws_key_str);

    int offset = snprintf(ws_send_buf, BUFFER_SIZE, 
        "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", 
        req_path, req_host, g_userAgentStr, ws_key_str);

    tls_write(&tls, ws_send_buf, offset);

    // 读取 WS 响应
    int len = tls_read(&tls, ws_read_buf, BUFFER_SIZE-1);
    if (len <= 0 || !strstr(ws_read_buf, "101")) goto cl_end;
    
    char* body_start = strstr(ws_read_buf, "\r\n\r\n");
    if (body_start) {
        body_start += 4; 
        int rem = len - (int)(body_start - ws_read_buf);
        if (rem > 0) { memmove(ws_read_buf, body_start, rem); ws_buf_len = rem; } else ws_buf_len = 0;
    } else ws_buf_len = 0;
    
    // 发送代理协议头
    unsigned char proto_buf[2048]; int proto_len = 0;
    struct in_addr ip4; struct in6_addr ip6;
    int is_vless = (_stricmp(localConfig.type, "vless") == 0);
    int is_trojan = (_stricmp(localConfig.type, "trojan") == 0);
    int is_shadowsocks = (_stricmp(localConfig.type, "shadowsocks") == 0);
    int is_mandala = (_stricmp(localConfig.type, "mandala") == 0);

    if (is_vless) {
        proto_buf[proto_len++] = 0x00; 
        parse_uuid(localConfig.user, proto_buf + proto_len); proto_len += 16; 
        proto_buf[proto_len++] = 0x00; proto_buf[proto_len++] = 0x01; 
        proto_buf[proto_len++] = (port >> 8) & 0xFF; proto_buf[proto_len++] = port & 0xFF;        
        if (inet_pton(AF_INET, host, &ip4) == 1) {
            proto_buf[proto_len++] = 0x01; memcpy(proto_buf + proto_len, &ip4, 4); proto_len += 4;
        } else if (inet_pton(AF_INET6, host, &ip6) == 1) {
            proto_buf[proto_len++] = 0x03; memcpy(proto_buf + proto_len, &ip6, 16); proto_len += 16;
        } else {
            proto_buf[proto_len++] = 0x02; proto_buf[proto_len++] = (unsigned char)strlen(host);
            memcpy(proto_buf + proto_len, host, strlen(host)); proto_len += (int)strlen(host);
        }
        int flen = build_ws_frame((char*)proto_buf, proto_len, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
    } else if (is_trojan) {
        char hex_pass[56 + 1]; trojan_password_hash(localConfig.pass, hex_pass);
        memcpy(proto_buf, hex_pass, 56); proto_len = 56;
        proto_buf[proto_len++] = 0x0D; proto_buf[proto_len++] = 0x0A; proto_buf[proto_len++] = 0x01; 
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
        int flen = build_ws_frame((char*)proto_buf, proto_len, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
    } else if (is_mandala) { 
        unsigned char salt[4]; for(int i=0; i<4; i++) salt[i] = rand() % 256;
        unsigned char pt[2048]; int pl = 0;
        char hex_pass[57]; trojan_password_hash(localConfig.pass, hex_pass);
        memcpy(pt + pl, hex_pass, 56); pl += 56;
        int pad = rand() % 16; pt[pl++] = (unsigned char)pad;
        for(int i=0; i<pad; i++) pt[pl++] = rand() % 256;
        pt[pl++] = 0x01;
        if (inet_pton(AF_INET, host, &ip4) == 1) { pt[pl++] = 0x01; memcpy(pt + pl, &ip4, 4); pl += 4; } 
        else if (inet_pton(AF_INET6, host, &ip6) == 1) { pt[pl++] = 0x04; memcpy(pt + pl, &ip6, 16); pl += 16; } 
        else { pt[pl++] = 0x03; pt[pl++] = (unsigned char)strlen(host); memcpy(pt + pl, host, strlen(host)); pl += strlen(host); }
        pt[pl++] = (port >> 8) & 0xFF; pt[pl++] = port & 0xFF;
        pt[pl++] = 0x0D; pt[pl++] = 0x0A;
        memcpy(proto_buf, salt, 4);
        for(int i=0; i<pl; i++) proto_buf[4 + i] = pt[i] ^ salt[i % 4];
        proto_len = 4 + pl;
        int flen = build_ws_frame((char*)proto_buf, proto_len, ws_send_buf);
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
        int flen = build_ws_frame((char*)proto_buf, proto_len, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
    } else { // SOCKS5 Outbound
        char auth[] = {0x05, 0x01, 0x00}; if (strlen(localConfig.user) > 0) auth[2] = 0x02; 
        int flen = build_ws_frame(auth, 3, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
        char resp_buf[512]; 
        if (ws_read_payload_exact(&tls, resp_buf, 2) < 2) goto cl_end;
        if (resp_buf[1] == 0x02) {
            int ulen = strlen(localConfig.user), plen = strlen(localConfig.pass);
            unsigned char ap[512]; int al = 0;
            ap[al++] = 0x01; ap[al++] = ulen; memcpy(ap+al, localConfig.user, ulen); al += ulen;
            ap[al++] = plen; memcpy(ap+al, localConfig.pass, plen); al += plen;
            flen = build_ws_frame((char*)ap, al, ws_send_buf); tls_write(&tls, ws_send_buf, flen);
            if (ws_read_payload_exact(&tls, resp_buf, 2) < 2 || resp_buf[1] != 0) goto cl_end;
        } 
        unsigned char sr[512]; int sl = 0;
        sr[sl++] = 0x05; sr[sl++] = 0x01; sr[sl++] = 0x00; 
        if (inet_pton(AF_INET, host, &ip4) == 1) { sr[sl++] = 0x01; memcpy(sr+sl, &ip4, 4); sl += 4; } 
        else { sr[sl++] = 0x03; sr[sl++] = strlen(host); memcpy(sr+sl, host, strlen(host)); sl += strlen(host); }
        sr[sl++] = (port >> 8) & 0xFF; sr[sl++] = port & 0xFF;
        flen = build_ws_frame((char*)sr, sl, ws_send_buf); tls_write(&tls, ws_send_buf, flen);
        if (ws_read_payload_exact(&tls, resp_buf, 4) == 0 || resp_buf[1] != 0) goto cl_end;
    }
    
    // 响应浏览器
    if (is_socks5) { unsigned char ok[] = {0x05, 0, 0, 1, 0,0,0,0, 0,0}; send(c, (char*)ok, 10, 0); } 
    else if (is_connect_method) { 
        const char *ok = "HTTP/1.1 200 Connection Established\r\n\r\n"; send(c, ok, strlen(ok), 0);
        if (browser_len > header_len) {
            int flen = build_ws_frame(c_buf + header_len, browser_len - header_len, ws_send_buf);
            tls_write(&tls, ws_send_buf, flen);
        }
    } else {
        int flen = build_ws_frame(c_buf, browser_len, ws_send_buf); tls_write(&tls, ws_send_buf, flen);
    }
    
    // 转发循环
    fd_set fds; struct timeval tv; u_long mode = 1;
    ioctlsocket(c, FIONBIO, &mode); ioctlsocket(r, FIONBIO, &mode);
    int vless_stripped = 0; int hl, pl; long long ft;

    while(1) {
        FD_ZERO(&fds); FD_SET(c, &fds); FD_SET(r, &fds);
        tv.tv_sec = 1; tv.tv_usec = 0; int pending = SSL_pending(tls.ssl);
        if (pending > 0 || ws_buf_len > 0) { tv.tv_sec = 0; }
        if (select(0, &fds, NULL, NULL, &tv) < 0) break;
        
        if (FD_ISSET(c, &fds)) {
            int n = recv(c, c_buf, BUFFER_SIZE, 0);
            if (n > 0) { int fl = build_ws_frame(c_buf, n, ws_send_buf); if (tls_write(&tls, ws_send_buf, fl) < 0) break; }
            else if (n == 0 || WSAGetLastError() != WSAEWOULDBLOCK) break;
        }
        
        if (FD_ISSET(r, &fds) || pending > 0) {
            if (ws_buf_len < BUFFER_SIZE) {
                int n = tls_read(&tls, ws_read_buf + ws_buf_len, BUFFER_SIZE - ws_buf_len);
                if (n > 0) ws_buf_len += n; else if (n == -1) break; 
            }
        }
        
        while (ws_buf_len > 0) {
            ft = check_ws_frame((unsigned char*)ws_read_buf, ws_buf_len, &hl, &pl);
            if (ft < 0) goto cl_end;
            if (ft > 0) {
                int op = ws_read_buf[0] & 0x0F;
                if (op == 0x8) goto cl_end; 
                if ((op == 0x1 || op == 0x2) && pl > 0) {
                    char* ptr = ws_read_buf + hl; int sz = pl;
                    if (is_vless && !vless_stripped) {
                        if (sz >= 2) {
                            int adl = (unsigned char)ptr[1];
                            if (sz >= 2 + adl) { ptr += 2 + adl; sz -= 2 + adl; vless_stripped = 1; } else sz = 0;
                        } else sz = 0;
                    }
                    if (sz > 0 && send_all(c, ptr, sz) < 0) goto cl_end;
                }
                if (ft < ws_buf_len) memmove(ws_read_buf, ws_read_buf + ft, ws_buf_len - ft);
                ws_buf_len -= (int)ft;
            } else { if (ws_buf_len >= BUFFER_SIZE) goto cl_end; break; }
        }
    }

cl_end:
    if (c_buf) free(c_buf); if (ws_read_buf) free(ws_read_buf); if (ws_send_buf) free(ws_send_buf); 
    tls_close(&tls);
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
            ClientContext* ctx = (ClientContext*)malloc(sizeof(ClientContext));
            if (ctx) {
                ctx->clientSock = c; ctx->config = g_proxyConfig; 
                HANDLE h = CreateThread(NULL, 0, client_handler, (LPVOID)ctx, 0, NULL);
                if (h) CloseHandle(h); else { free(ctx); closesocket(c); }
            } else closesocket(c);
        } else break;
    } return 0;
}

void StartProxyCore() {
    if (g_proxyRunning) return; g_proxyRunning = TRUE;
    hProxyThread = CreateThread(NULL, 0, server_thread, NULL, 0, NULL);
    if (!hProxyThread) { log_msg("CreateThread Failed"); g_proxyRunning = FALSE; }
}

void StopProxyCore() {
    g_proxyRunning = FALSE;
    if (g_listen_sock != INVALID_SOCKET) { closesocket(g_listen_sock); g_listen_sock = INVALID_SOCKET; }
    if (hProxyThread) { WaitForSingleObject(hProxyThread, 2000); CloseHandle(hProxyThread); hProxyThread = NULL; }
    log_msg("Proxy Stopped");
}

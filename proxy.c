#include "proxy.h"
#include "crypto.h"
#include "utils.h"
#include "common.h"
#include <openssl/sha.h>
#include <stdio.h>

static volatile LONG g_active_connections = 0;

typedef struct {
    SOCKET clientSock;
    ProxyConfig config;          
    char userAgent[512];         
    CryptoSettings cryptoSettings; 
} ClientContext;

void parse_uuid(const char* uuid_str, unsigned char* out) {
    const char* p = uuid_str;
    int i = 0;
    while (*p && i < 16) {
        if (*p == '-' || *p == ' ' || *p == '{' || *p == '}') { p++; continue; }
        int v;
        if (sscanf(p, "%2x", &v) == 1) { out[i++] = (unsigned char)v; p += 2; } 
        else { p++; }
    }
}

void trojan_password_hash(const char* password, char* out_hex) {
    unsigned char digest[SHA224_DIGEST_LENGTH];
    SHA224((const unsigned char*)password, strlen(password), digest);
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

int read_header_robust(SOCKET s, char* buf, int max_len, int timeout_sec) {
    int total_read = 0; int remaining_time = timeout_sec;
    while (total_read < max_len - 1 && remaining_time > 0) {
        int n = recv_timeout(s, buf + total_read, max_len - 1 - total_read, 1);
        if (n == -2) { remaining_time--; continue; }
        if (n <= 0) return -1; 
        total_read += n; buf[total_read] = 0; 
        if (buf[0] == 0x05) { if (total_read >= 2) return total_read; }
        else { if (strstr(buf, "\r\n\r\n")) return total_read; }
        if (total_read > 8192) break; 
    }
    return total_read > 0 ? total_read : -1;
}

int send_all(SOCKET s, const char *buf, int len) {
    int total = 0; int bytesleft = len; 
    while(total < len) {
        int n = send(s, buf+total, bytesleft, 0);
        if (n == -1) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) { 
                fd_set wfd; FD_ZERO(&wfd); FD_SET(s, &wfd); struct timeval tv = { 1, 0 };
                if (select(0, NULL, &wfd, NULL, &tv) > 0) continue;
                return -1;
            }
            return -1;
        }
        total += n; bytesleft -= n;
    }
    return total;
}

void base64_encode_key(const unsigned char* src, char* dst) {
    const char* table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for(int i=0; i<16; i+=3) {
        int n = (src[i] << 16) + (src[i+1] << 8) + src[i+2];
        dst[0] = table[(n >> 18) & 0x3F]; dst[1] = table[(n >> 12) & 0x3F];
        dst[2] = table[(n >> 6) & 0x3F]; dst[3] = table[n & 0x3F];
        dst += 4;
    }
    *(dst-1) = '='; *dst = 0;
}

DWORD WINAPI client_handler(LPVOID p) {
    InterlockedIncrement(&g_active_connections);
    ClientContext* ctx = (ClientContext*)p;
    if (!ctx) { InterlockedDecrement(&g_active_connections); return 0; }

    SOCKET c = ctx->clientSock;
    ProxyConfig localConfig = ctx->config; 
    CryptoSettings localCrypto = ctx->cryptoSettings;
    char localUserAgent[512];
    strncpy(localUserAgent, ctx->userAgent, sizeof(localUserAgent)-1);
    localUserAgent[sizeof(localUserAgent)-1] = 0;
    free(ctx); 

    TLSContext tls; memset(&tls, 0, sizeof(tls));
    SOCKET r = INVALID_SOCKET;      
    char *c_buf = NULL, *ws_read_buf = NULL, *ws_send_buf = NULL; 
    
    int ws_read_buf_cap = IO_BUFFER_SIZE; int ws_buf_len = 0; 
    c_buf = (char*)malloc(IO_BUFFER_SIZE); 
    ws_read_buf = (char*)malloc(ws_read_buf_cap); 
    ws_send_buf = (char*)malloc(IO_BUFFER_SIZE + 4096); 
    if (!c_buf || !ws_read_buf || !ws_send_buf) goto cl_end; 

    int flag = 1; setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
    
    int browser_len = read_header_robust(c, c_buf, IO_BUFFER_SIZE, 10);
    if (browser_len <= 0) goto cl_end; 
    c_buf[browser_len] = 0;
    
    char method[16] = {0}, host[256] = {0}, port_str[16] = {0};
    int port = 80, is_connect_method = 0, is_socks5 = 0;
    char *header_end = NULL; int header_len = 0;

    if (c_buf[0] == 0x05) { 
        send(c, "\x05\x00", 2, 0); is_socks5 = 1;
        int n = recv_timeout(c, c_buf, IO_BUFFER_SIZE, 10);
        if (n <= 0) goto cl_end; browser_len = n;
        if (c_buf[1] == 0x01) { 
             if (c_buf[3] == 0x01) { inet_ntop(AF_INET, &c_buf[4], host, sizeof(host)); port = ntohs(*(unsigned short*)&c_buf[8]); } 
             else if (c_buf[3] == 0x03) { int dlen = (unsigned char)c_buf[4]; memcpy(host, &c_buf[5], dlen); host[dlen] = 0; port = ntohs(*(unsigned short*)&c_buf[5+dlen]); } 
             else goto cl_end;
             strcpy(method, "SOCKS5");
        } else goto cl_end;
    } else {
        if (sscanf(c_buf, "%15s %255s", method, host) == 2) {
            char *p_col = strchr(host, ':');
            if (p_col) { *p_col = 0; port = atoi(p_col+1); }
            else if(stricmp(method, "CONNECT")==0) port = 443;
            if (stricmp(method, "CONNECT") == 0) is_connect_method = 1;
            header_end = strstr(c_buf, "\r\n\r\n");
            header_len = header_end ? (int)(header_end - c_buf) + 4 : browser_len;
        } else goto cl_end;
    }
    
    log_msg("[Proxy] %s -> %s:%d", method, host, port);
    
    struct addrinfo hints, *res = NULL, *ptr = NULL;
    memset(&hints, 0, sizeof(hints)); hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM; hints.ai_protocol = IPPROTO_TCP;
    snprintf(port_str, sizeof(port_str), "%d", localConfig.port);

    if (getaddrinfo(localConfig.host, port_str, &hints, &res) != 0) { log_msg("[Err] DNS Fail: %s", localConfig.host); goto cl_end; }

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
                if (tls_init_connect(&tls, localConfig.sni, localConfig.host, &localCrypto) == 0) { break; } 
                else { tls_close(&tls); closesocket(r); r = INVALID_SOCKET; }
            } else { closesocket(r); r = INVALID_SOCKET; }
        }
        if (r != INVALID_SOCKET && tls.ssl != NULL) break;
        Sleep(200);
    }
    if (r == INVALID_SOCKET || tls.ssl == NULL) goto cl_end;
    
    const char* sni_val = (strlen(localConfig.sni) > 0) ? localConfig.sni : localConfig.host;
    const char* req_path = (strlen(localConfig.path) > 0) ? localConfig.path : "/";
    unsigned char rnd_key[16]; char ws_key_str[32];
    for(int i=0; i<16; i++) rnd_key[i] = rand() % 256;
    base64_encode_key(rnd_key, ws_key_str);

    int offset = snprintf(ws_send_buf, IO_BUFFER_SIZE, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", req_path, sni_val, localUserAgent, ws_key_str);
    tls_write(&tls, ws_send_buf, offset);
    int hlen = tls_read(&tls, ws_read_buf, ws_read_buf_cap - 1);
    if (hlen <= 0) goto cl_end; ws_read_buf[hlen] = 0;
    if (!strstr(ws_read_buf, "101")) { log_msg("[Err] WS Handshake Fail: %.50s", ws_read_buf); goto cl_end; }
    
    char* body_start = strstr(ws_read_buf, "\r\n\r\n");
    if (body_start) {
        body_start += 4; int header_bytes = (int)(body_start - ws_read_buf); int remaining = hlen - header_bytes;
        if (remaining > 0) { memmove(ws_read_buf, body_start, remaining); ws_buf_len = remaining; }
    }
    
    unsigned char proto_buf[2048]; int proto_len = 0, flen = 0; struct in_addr ip4; struct in6_addr ip6;
    BOOL is_vless = (_stricmp(localConfig.type, "vless") == 0);
    BOOL is_trojan = (_stricmp(localConfig.type, "trojan") == 0);
    BOOL is_shadowsocks = (_stricmp(localConfig.type, "shadowsocks") == 0);
    BOOL is_mandala = (_stricmp(localConfig.type, "mandala") == 0);

    if (is_vless) {
        proto_buf[proto_len++] = 0x00; parse_uuid(localConfig.user, proto_buf + proto_len); proto_len += 16; 
        proto_buf[proto_len++] = 0x00; proto_buf[proto_len++] = 0x01; 
        proto_buf[proto_len++] = (port >> 8) & 0xFF; proto_buf[proto_len++] = port & 0xFF;        
        if (inet_pton(AF_INET, host, &ip4) == 1) { proto_buf[proto_len++] = 0x01; memcpy(proto_buf + proto_len, &ip4, 4); proto_len += 4; } 
        else if (inet_pton(AF_INET6, host, &ip6) == 1) { proto_buf[proto_len++] = 0x03; memcpy(proto_buf + proto_len, &ip6, 16); proto_len += 16; } 
        else { proto_buf[proto_len++] = 0x02; proto_buf[proto_len++] = (unsigned char)strlen(host); memcpy(proto_buf + proto_len, host, strlen(host)); proto_len += (int)strlen(host); }
        flen = build_ws_frame((char*)proto_buf, proto_len, ws_send_buf); tls_write(&tls, ws_send_buf, flen);
    } 
    else if (is_trojan || is_mandala) {
        char hex_pass[128]; trojan_password_hash(localConfig.pass, hex_pass);
        if (is_mandala) { 
            unsigned char salt[4], plaintext[2048]; int p_len = 0;
            for(int i=0; i<4; i++) salt[i] = rand() % 256;
            memcpy(plaintext, hex_pass, 56); p_len = 56;
            int pad = rand() % 16; plaintext[p_len++] = (unsigned char)pad; for(int i=0; i<pad; i++) plaintext[p_len++] = rand() % 256;
            plaintext[p_len++] = 0x01; 
            if (inet_pton(AF_INET, host, &ip4) == 1) { plaintext[p_len++] = 0x01; memcpy(plaintext + p_len, &ip4, 4); p_len += 4; } 
            else if (inet_pton(AF_INET6, host, &ip6) == 1) { plaintext[p_len++] = 0x04; memcpy(plaintext + p_len, &ip6, 16); p_len += 16; } 
            else { plaintext[p_len++] = 0x03; plaintext[p_len++] = (unsigned char)strlen(host); memcpy(plaintext + p_len, host, strlen(host)); p_len += strlen(host); }
            plaintext[p_len++] = (port >> 8) & 0xFF; plaintext[p_len++] = port & 0xFF;
            plaintext[p_len++] = 0x0D; plaintext[p_len++] = 0x0A;
            memcpy(proto_buf, salt, 4); for(int i=0; i<p_len; i++) proto_buf[4 + i] = plaintext[i] ^ salt[i % 4];
            proto_len = 4 + p_len;
        } else { 
            memcpy(proto_buf, hex_pass, 56); proto_len = 56;
            proto_buf[proto_len++] = 0x0D; proto_buf[proto_len++] = 0x0A;
            proto_buf[proto_len++] = 0x01; 
            if (inet_pton(AF_INET, host, &ip4) == 1) { proto_buf[proto_len++] = 0x01; memcpy(proto_buf + proto_len, &ip4, 4); proto_len += 4; } 
            else if (inet_pton(AF_INET6, host, &ip6) == 1) { proto_buf[proto_len++] = 0x04; memcpy(proto_buf + proto_len, &ip6, 16); proto_len += 16; } 
            else { proto_buf[proto_len++] = 0x03; proto_buf[proto_len++] = (unsigned char)strlen(host); memcpy(proto_buf + proto_len, host, strlen(host)); proto_len += strlen(host); }
            proto_buf[proto_len++] = (port >> 8) & 0xFF; proto_buf[proto_len++] = port & 0xFF;
            proto_buf[proto_len++] = 0x0D; proto_buf[proto_len++] = 0x0A;
        }
        flen = build_ws_frame((char*)proto_buf, proto_len, ws_send_buf); tls_write(&tls, ws_send_buf, flen);
    } 
    else if (is_shadowsocks) {
        if (inet_pton(AF_INET, host, &ip4) == 1) { proto_buf[proto_len++] = 0x01; memcpy(proto_buf + proto_len, &ip4, 4); proto_len += 4; } 
        else if (inet_pton(AF_INET6, host, &ip6) == 1) { proto_buf[proto_len++] = 0x04; memcpy(proto_buf + proto_len, &ip6, 16); proto_len += 16; } 
        else { proto_buf[proto_len++] = 0x03; proto_buf[proto_len++] = (unsigned char)strlen(host); memcpy(proto_buf + proto_len, host, strlen(host)); proto_len += strlen(host); }
        proto_buf[proto_len++] = (port >> 8) & 0xFF; proto_buf[proto_len++] = port & 0xFF;
        flen = build_ws_frame((char*)proto_buf, proto_len, ws_send_buf); tls_write(&tls, ws_send_buf, flen);
    }
    else { 
        char auth[] = {0x05, 0x01, 0x00}; if (strlen(localConfig.user) > 0) auth[2] = 0x02; 
        flen = build_ws_frame(auth, 3, ws_send_buf); tls_write(&tls, ws_send_buf, flen);
        char resp_buf[512]; 
        if (ws_read_payload_exact(&tls, resp_buf, 2) < 2) goto cl_end;
        if (resp_buf[1] == 0x02) {
            int ulen = strlen(localConfig.user); int plen = strlen(localConfig.pass);
            unsigned char auth_pkg[512]; int ap_len = 0;
            auth_pkg[ap_len++] = 0x01; auth_pkg[ap_len++] = ulen; memcpy(auth_pkg+ap_len, localConfig.user, ulen); ap_len += ulen;
            auth_pkg[ap_len++] = plen; memcpy(auth_pkg+ap_len, localConfig.pass, plen); ap_len += plen;
            flen = build_ws_frame((char*)auth_pkg, ap_len, ws_send_buf); tls_write(&tls, ws_send_buf, flen);
            if (ws_read_payload_exact(&tls, resp_buf, 2) < 2) goto cl_end;
            if (resp_buf[1] != 0x00) goto cl_end;
        } 
        int slen = 0; unsigned char socks_req[512];
        socks_req[slen++] = 0x05; socks_req[slen++] = 0x01; socks_req[slen++] = 0x00; 
        if (inet_pton(AF_INET, host, &ip4) == 1) { socks_req[slen++] = 0x01; memcpy(socks_req + slen, &ip4, 4); slen += 4; } 
        else { socks_req[slen++] = 0x03; socks_req[slen++] = (unsigned char)strlen(host); memcpy(socks_req + slen, host, strlen(host)); slen += (int)strlen(host); }
        socks_req[slen++] = (port >> 8) & 0xFF; socks_req[slen++] = port & 0xFF;
        flen = build_ws_frame((char*)socks_req, slen, ws_send_buf); tls_write(&tls, ws_send_buf, flen);
        if (ws_read_payload_exact(&tls, resp_buf, 4) == 0) goto cl_end;
        if (resp_buf[1] != 0x00) goto cl_end;
    }
    
    if (is_socks5) { unsigned char s5_ok[] = {0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0}; send(c, (char*)s5_ok, 10, 0); } 
    else if (is_connect_method) {
        const char *ok = "HTTP/1.1 200 Connection Established\r\n\r\n"; send(c, ok, strlen(ok), 0);
        if (browser_len > header_len) { int extra_len = browser_len - header_len; flen = build_ws_frame(c_buf + header_len, extra_len, ws_send_buf); tls_write(&tls, ws_send_buf, flen); }
    } else { flen = build_ws_frame(c_buf, browser_len, ws_send_buf); tls_write(&tls, ws_send_buf, flen); }
    
    u_long mode = 1; ioctlsocket(c, FIONBIO, &mode); ioctlsocket(r, FIONBIO, &mode);
    fd_set fds; struct timeval tv; int vless_response_header_stripped = 0;
    
    while(1) {
        FD_ZERO(&fds); FD_SET(c, &fds); FD_SET(r, &fds);
        int pending = SSL_pending(tls.ssl); tv.tv_sec = 1; tv.tv_usec = 0;
        if (pending > 0 || ws_buf_len > 0) { tv.tv_sec = 0; tv.tv_usec = 0; }
        
        int n = select(0, &fds, NULL, NULL, &tv);
        if (n < 0) break;
        
        if (FD_ISSET(c, &fds)) {
            int len = recv(c, c_buf, IO_BUFFER_SIZE, 0);
            if (len > 0) {
                flen = build_ws_frame(c_buf, len, ws_send_buf);
                if (tls_write(&tls, ws_send_buf, flen) < 0) break;
            } else if (len == 0) break; else if (WSAGetLastError() != WSAEWOULDBLOCK) break;
        }
        
        if (FD_ISSET(r, &fds) || pending > 0) {
            if (ws_buf_len >= ws_read_buf_cap - 1024) { 
                if (ws_read_buf_cap < 8388608) {
                    int new_cap = ws_read_buf_cap * 2; if (new_cap > 8388608) new_cap = 8388608;
                    char* new_buf = (char*)realloc(ws_read_buf, new_cap);
                    if (new_buf) { ws_read_buf = new_buf; ws_read_buf_cap = new_cap; }
                }
            }
            if (ws_buf_len < ws_read_buf_cap) {
                int len = tls_read(&tls, ws_read_buf + ws_buf_len, ws_read_buf_cap - ws_buf_len);
                if (len > 0) ws_buf_len += len; else if (len < 0) break; 
            }
        }
        
        while (ws_buf_len > 0) {
            int hl, pl; long long frame_total = check_ws_frame((unsigned char*)ws_read_buf, ws_buf_len, &hl, &pl);
            if (frame_total < 0) goto cl_end; 
            if (frame_total > 0) {
                int opcode = ws_read_buf[0] & 0x0F;
                if (opcode == 0x8) goto cl_end; 
                if ((opcode == 0x1 || opcode == 0x2) && pl > 0) {
                    char* payload_ptr = ws_read_buf + hl; int payload_size = pl;
                    if (is_vless && !vless_response_header_stripped) {
                        if (payload_size >= 2) {
                            int addon_len = (unsigned char)payload_ptr[1]; int head_size = 2 + addon_len;
                            if (payload_size >= head_size) { payload_ptr += head_size; payload_size -= head_size; vless_response_header_stripped = 1; } else payload_size = 0;
                        } else payload_size = 0;
                    }
                    if (payload_size > 0) { if (send_all(c, payload_ptr, payload_size) < 0) goto cl_end; }
                }
                if (frame_total < ws_buf_len) { memmove(ws_read_buf, ws_read_buf + frame_total, ws_buf_len - (int)frame_total); }
                ws_buf_len -= (int)frame_total;
            } else break; 
        }
    }

cl_end:
    if (res) freeaddrinfo(res);
    free(c_buf); free(ws_read_buf); free(ws_send_buf);
    tls_close(&tls);
    if (r != INVALID_SOCKET) closesocket(r); if (c != INVALID_SOCKET) closesocket(c);
    InterlockedDecrement(&g_active_connections);
    return 0;
}

DWORD WINAPI server_thread(LPVOID p) {
    g_listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; addr.sin_port = htons(g_localPort); addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int opt = 1; setsockopt(g_listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    if (bind(g_listen_sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) { log_msg("[Fatal] Port %d bind fail", g_localPort); g_proxyRunning = FALSE; return 0; }
    listen(g_listen_sock, SOMAXCONN);
    log_msg("[System] Server listening on 127.0.0.1:%d", g_localPort);
    
    while(g_proxyRunning) {
        SOCKET c = accept(g_listen_sock, NULL, NULL);
        if (c != INVALID_SOCKET) {
            if (g_active_connections >= MAX_CONNECTIONS) { closesocket(c); Sleep(10); continue; }
            ClientContext* ctx = (ClientContext*)malloc(sizeof(ClientContext));
            if (ctx) {
                ctx->clientSock = c;
                EnterCriticalSection(&g_configLock);
                ctx->config = g_proxyConfig; 
                strncpy(ctx->userAgent, g_userAgentStr, sizeof(ctx->userAgent)-1); ctx->userAgent[sizeof(ctx->userAgent)-1] = 0;
                ctx->cryptoSettings.enableFragment = g_enableFragment;
                ctx->cryptoSettings.fragMin = g_fragSizeMin;
                ctx->cryptoSettings.fragMax = g_fragSizeMax;
                ctx->cryptoSettings.fragDelay = g_fragDelayMs;
                ctx->cryptoSettings.enablePadding = g_enablePadding;
                ctx->cryptoSettings.padMin = g_padSizeMin;
                ctx->cryptoSettings.padMax = g_padSizeMax;
                ctx->cryptoSettings.enableChromeCiphers = g_enableChromeCiphers;
                ctx->cryptoSettings.enableECH = g_enableECH;
                LeaveCriticalSection(&g_configLock);
                HANDLE hClient = CreateThread(NULL, 0, client_handler, (LPVOID)ctx, 0, NULL);
                if (hClient) CloseHandle(hClient); else { free(ctx); closesocket(c); }
            } else { closesocket(c); }
        } else break;
    }
    return 0;
}

void StartProxyCore() {
    if (g_proxyRunning) return;
    g_proxyRunning = TRUE;
    hProxyThread = CreateThread(NULL, 0, server_thread, NULL, 0, NULL);
    if (!hProxyThread) g_proxyRunning = FALSE;
}

void StopProxyCore() {
    g_proxyRunning = FALSE;
    if (g_listen_sock != INVALID_SOCKET) { closesocket(g_listen_sock); g_listen_sock = INVALID_SOCKET; }
    if (hProxyThread) { WaitForSingleObject(hProxyThread, 2000); CloseHandle(hProxyThread); hProxyThread = NULL; }
    log_msg("[System] Proxy Stopped");
}

#include "proxy.h"
#include "crypto.h"
#include "utils.h"

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

DWORD WINAPI client_handler(LPVOID p) {
    SOCKET c = (SOCKET)(UINT_PTR)p; TLSContext tls; memset(&tls, 0, sizeof(tls));
    SOCKET r = INVALID_SOCKET;      
    // [优化] ws_send_buf 增大 128 字节，防止 WebSocket 封包头溢出
    char *c_buf = (char*)malloc(BUFFER_SIZE); 
    char *ws_read_buf = (char*)malloc(BUFFER_SIZE); 
    char *ws_send_buf = (char*)malloc(BUFFER_SIZE + 128);

    if (!c_buf || !ws_read_buf || !ws_send_buf) { goto cl_end; }
    int ws_buf_len = 0; int flag = 1; 
    setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
    int browser_len = recv_timeout(c, c_buf, BUFFER_SIZE, 10);
    if (browser_len <= 0) goto cl_end;
    c_buf[browser_len] = 0;
    char method[16], host[256]; int port = 80; int is_connect_method = 0;
    if (c_buf[0] == 0x05) { send(c, "\x05\x00", 2, 0); goto cl_end; } 
    else {
        if (sscanf(c_buf, "%15s %255s", method, host) == 2) {
            char *p = strchr(host, ':');
            if (p) { *p = 0; port = atoi(p+1); }
            else if(stricmp(method, "CONNECT")==0) port = 443;
            if (stricmp(method, "CONNECT") == 0) is_connect_method = 1;
        } else { goto cl_end; }
    }
    log_msg("[Access] %s %s:%d", method, host, port);
    struct hostent *h = gethostbyname(g_proxyConfig.host);
    if(!h) { log_msg("[DNS] Fail"); goto cl_end; }
    r = socket(AF_INET, SOCK_STREAM, 0);
    if (r == INVALID_SOCKET) goto cl_end;
    setsockopt(r, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
    struct sockaddr_in a; memset(&a, 0, sizeof(a)); a.sin_family = AF_INET; a.sin_port = htons((unsigned short)g_proxyConfig.port);
    a.sin_addr = *(struct in_addr*)h->h_addr;
    if (connect(r, (struct sockaddr*)&a, sizeof(a)) != 0) { log_wsa_error("TCP Connect"); goto cl_end; }
    tls.sock = r;
    
    if (tls_init_connect(&tls) != 0) goto cl_end;
    
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
    if (len <= 0 || !strstr(ws_read_buf, "101 Switching Protocols")) { log_msg("[WS Error] Handshake failed"); goto cl_end; }
    char auth[] = {0x05, 0x01, 0x00};
    if (strlen(g_proxyConfig.user) > 0) auth[2] = 0x02;
    int flen = build_ws_frame(auth, 3, ws_send_buf);
    tls_write(&tls, ws_send_buf, flen);
    char resp_buf[256];
    if (ws_read_payload_exact(&tls, resp_buf, 2) < 2) goto cl_end;
    if (resp_buf[1] == 0x02) {
        char up[512]; int idx = 0;
        up[idx++] = 1; up[idx++] = (char)strlen(g_proxyConfig.user); memcpy(up+idx, g_proxyConfig.user, strlen(g_proxyConfig.user)); idx += (int)strlen(g_proxyConfig.user);
        up[idx++] = (char)strlen(g_proxyConfig.pass); memcpy(up+idx, g_proxyConfig.pass, strlen(g_proxyConfig.pass)); idx += (int)strlen(g_proxyConfig.pass);
        flen = build_ws_frame(up, idx, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
        if (ws_read_payload_exact(&tls, resp_buf, 2) < 2) goto cl_end; 
        if (resp_buf[1] != 0x00) goto cl_end;
    }
    unsigned char socks_req[512]; int slen = 0;
    socks_req[slen++] = 0x05; socks_req[slen++] = 0x01; socks_req[slen++] = 0x00; socks_req[slen++] = 0x03;
    socks_req[slen++] = (unsigned char)strlen(host);
    memcpy(socks_req + slen, host, strlen(host)); slen += (int)strlen(host);
    socks_req[slen++] = (port >> 8) & 0xFF; socks_req[slen++] = port & 0xFF;
    flen = build_ws_frame((char*)socks_req, slen, ws_send_buf);
    tls_write(&tls, ws_send_buf, flen);
    if (ws_read_payload_exact(&tls, resp_buf, 4) < 4 || resp_buf[1] != 0x00) goto cl_end;
    if (is_connect_method) {
        const char *ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
        send(c, ok, strlen(ok), 0);
    } else {
        flen = build_ws_frame(c_buf, browser_len, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
    }
    fd_set fds; struct timeval tv; u_long mode = 1;
    ioctlsocket(c, FIONBIO, &mode); ioctlsocket(r, FIONBIO, &mode);
    ws_buf_len = 0; int hl, pl, frame_total;
    while(1) {
        FD_ZERO(&fds); FD_SET(c, &fds); FD_SET(r, &fds);
        int pending = SSL_pending(tls.ssl);
        tv.tv_sec = 1; tv.tv_usec = 0;
        if (pending > 0 || ws_buf_len > 0) { tv.tv_sec = 0; tv.tv_usec = 0; }
        int n = select(0, &fds, NULL, NULL, &tv);
        if (n < 0) break;
        if (FD_ISSET(c, &fds)) {
            len = recv(c, c_buf, BUFFER_SIZE, 0);
            if (len > 0) {
                flen = build_ws_frame(c_buf, len, ws_send_buf);
                if (tls_write(&tls, ws_send_buf, flen) < 0) break;
            } else if (WSAGetLastError() != WSAEWOULDBLOCK) break;
        }
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
                    if (send_all(c, ws_read_buf + hl, pl) < 0) goto cl_end;
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
    init_openssl_global();
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
        if (c != INVALID_SOCKET) CloseHandle(CreateThread(NULL, 0, client_handler, (LPVOID)(UINT_PTR)c, 0, NULL));
        else break;
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
    FreeGlobalSSLContext();
    log_msg("Proxy Stopped");
}

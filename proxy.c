#include "proxy.h"
#include "crypto.h"
#include "utils.h"
#include "common.h"
#include <openssl/sha.h>
#include <process.h>

// [Safety] 全局活跃连接计数器与内存水位监控
static volatile LONG g_active_connections = 0;
volatile LONG64 g_total_allocated_mem = 0; 
HANDLE hIOCP = NULL;

// [Safety] 自动初始化锁的标志位，防止崩溃
static volatile LONG g_locksInitialized = 0;

// [Concurrency] 客户端初始化上下文 (仅用于握手线程启动)
typedef struct {
    SOCKET clientSock;
    ProxyConfig config;          
    char userAgent[512];         
    CryptoSettings cryptoSettings; 
} ClientInitContext;

// --------------------------------------------------------------------------
// 辅助函数
// --------------------------------------------------------------------------

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
            p++; 
        }
    }
}

void trojan_password_hash(const char* password, char* out_hex) {
    unsigned char digest[SHA224_DIGEST_LENGTH];
    SHA224((unsigned char*)password, (size_t)strlen(password), digest);
    for(int i = 0; i < SHA224_DIGEST_LENGTH; i++) {
        snprintf(out_hex + (i * 2), 3, "%02x", digest[i]); 
    }
    out_hex[SHA224_DIGEST_LENGTH * 2] = 0;
}

int recv_timeout(SOCKET s, char *buf, int len, int timeout_sec) {
    fd_set fds; 
    FD_ZERO(&fds); 
    FD_SET(s, &fds);
    struct timeval tv = { timeout_sec, 0 };
    int n = select(0, &fds, NULL, NULL, &tv);
    if (n == 0) return -2; 
    if (n < 0) return -1;  
    return recv(s, buf, len, 0);
}

int read_header_robust(SOCKET s, char* buf, int max_len, int timeout_sec) {
    int total_read = 0;
    int remaining_time = timeout_sec;
    while (total_read < max_len - 1 && remaining_time > 0) {
        int n = recv_timeout(s, buf + total_read, max_len - 1 - total_read, 1);
        if (n == -2) { remaining_time--; continue; }
        if (n <= 0) return -1; 
        total_read += n;
        buf[total_read] = 0; 
        if (buf[0] == 0x05) { if (total_read >= 2) return total_read; }
        else { if (strstr(buf, "\r\n\r\n")) return total_read; }
        if (total_read > 8192) break; 
    }
    return total_read > 0 ? total_read : -1;
}

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
    *(dst-1) = '='; *dst = 0;
}

void* proxy_malloc(size_t size) {
    if (g_total_allocated_mem + (LONG64)size > MAX_TOTAL_MEMORY_USAGE) return NULL;
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

// --------------------------------------------------------------------------
// IOCP 核心逻辑
// --------------------------------------------------------------------------

IO_CONTEXT* AllocIoContext(IO_OPERATION_TYPE type) {
    IO_CONTEXT* ctx = (IO_CONTEXT*)proxy_malloc(sizeof(IO_CONTEXT));
    if (!ctx) return NULL;
    memset(ctx, 0, sizeof(IO_CONTEXT));
    ctx->opType = type;
    ctx->wsaBuf.buf = ctx->buffer;
    ctx->wsaBuf.len = IO_BUFFER_SIZE;
    return ctx;
}

void FreeIoContext(IO_CONTEXT* ctx) {
    if (ctx) proxy_free(ctx, sizeof(IO_CONTEXT));
}

void FreeConnectionContext(CONNECTION_CONTEXT* conn) {
    if (!conn) return;
    if (conn->clientSock != INVALID_SOCKET) { closesocket(conn->clientSock); conn->clientSock = INVALID_SOCKET; }
    if (conn->remoteSock != INVALID_SOCKET) { closesocket(conn->remoteSock); conn->remoteSock = INVALID_SOCKET; }
    if (conn->ssl) { SSL_free(conn->ssl); conn->ssl = NULL; }
    if (conn->ws_frag_buf) proxy_free(conn->ws_frag_buf, conn->ws_frag_cap);
    proxy_free(conn, sizeof(CONNECTION_CONTEXT));
    InterlockedDecrement(&g_active_connections);
}

BOOL PostRecv(SOCKET s, IO_CONTEXT* ioCtx) {
    DWORD flags = 0;
    ioCtx->wsaBuf.len = IO_BUFFER_SIZE; 
    ioCtx->bytesTransferred = 0;
    memset(&ioCtx->overlapped, 0, sizeof(OVERLAPPED));
    int n = WSARecv(s, &ioCtx->wsaBuf, 1, NULL, &flags, &ioCtx->overlapped, NULL);
    if (n == SOCKET_ERROR && WSAGetLastError() != ERROR_IO_PENDING) return FALSE;
    return TRUE;
}

BOOL PostSend(SOCKET s, const char* data, int len) {
    if (len <= 0) return TRUE;
    IO_CONTEXT* sendCtx = AllocIoContext(IO_WRITE_CLIENT); 
    if (!sendCtx) return FALSE;
    if (len > IO_BUFFER_SIZE) len = IO_BUFFER_SIZE; 
    memcpy(sendCtx->buffer, data, len);
    sendCtx->wsaBuf.len = len;
    sendCtx->opType = IO_WRITE_CLIENT; 
    int n = WSASend(s, &sendCtx->wsaBuf, 1, NULL, 0, &sendCtx->overlapped, NULL);
    if (n == SOCKET_ERROR && WSAGetLastError() != ERROR_IO_PENDING) {
        FreeIoContext(sendCtx);
        return FALSE;
    }
    return TRUE;
}

void OnClientRead(CONNECTION_CONTEXT* conn, DWORD bytesTransferred) {
    if (bytesTransferred == 0) return; 
    char* plain_data = conn->rxClient.buffer;
    int plain_len = bytesTransferred;
    char* frame_buf = (char*)proxy_malloc(plain_len + 14); 
    if (!frame_buf) return;
    int frame_len = build_ws_frame(plain_data, plain_len, frame_buf);
    int max_cipher = frame_len + 1024; 
    char* cipher_buf = (char*)proxy_malloc(max_cipher);
    if (!cipher_buf) { proxy_free(frame_buf, plain_len + 14); return; }
    int cipher_len = tls_encrypt_to_mem(conn, frame_buf, frame_len, cipher_buf, max_cipher);
    proxy_free(frame_buf, plain_len + 14);
    if (cipher_len > 0) PostSend(conn->remoteSock, cipher_buf, cipher_len);
    proxy_free(cipher_buf, max_cipher);
}

void OnRemoteRead(CONNECTION_CONTEXT* conn, DWORD bytesTransferred) {
    if (bytesTransferred == 0) return;
    char* cipher_data = conn->rxRemote.buffer;
    int cipher_len = bytesTransferred;
    int max_plain = cipher_len + 1024; 
    char* plain_buf = (char*)proxy_malloc(max_plain);
    if (!plain_buf) return;
    
    int plain_len = tls_decrypt_from_mem(conn, cipher_data, cipher_len, plain_buf, max_plain);
    
    if (plain_len > 0) {
        if (conn->ws_frag_len + plain_len > conn->ws_frag_cap) {
            int new_cap = conn->ws_frag_cap * 2;
            if (new_cap < conn->ws_frag_len + plain_len) new_cap = conn->ws_frag_len + plain_len + 1024;
            if (new_cap > MAX_WS_FRAME_SIZE) { proxy_free(plain_buf, max_plain); return; }
            char* new_buf = (char*)proxy_malloc(new_cap);
            if (new_buf) {
                if (conn->ws_frag_buf) {
                    memcpy(new_buf, conn->ws_frag_buf, conn->ws_frag_len);
                    proxy_free(conn->ws_frag_buf, conn->ws_frag_cap);
                }
                conn->ws_frag_buf = new_buf;
                conn->ws_frag_cap = new_cap;
            } else { proxy_free(plain_buf, max_plain); return; }
        }
        memcpy(conn->ws_frag_buf + conn->ws_frag_len, plain_buf, plain_len);
        conn->ws_frag_len += plain_len;
        
        while (conn->ws_frag_len > 0) {
            int hl, pl;
            long long frame_total = check_ws_frame((unsigned char*)conn->ws_frag_buf, conn->ws_frag_len, &hl, &pl);
            if (frame_total < 0) break; 
            if (frame_total == 0) break;
            
            int opcode = conn->ws_frag_buf[0] & 0x0F;
            if (opcode == 0x8) break;
            
            if ((opcode == 0x1 || opcode == 0x2) && pl > 0) {
                char* payload = conn->ws_frag_buf + hl;
                int payload_size = pl;
                
                // VLESS Response Header Stripping
                if (conn->is_vless && !conn->header_stripped) {
                    if (payload_size >= 2) {
                        int addon_len = (unsigned char)payload[1];
                        int head_size = 2 + addon_len;
                        if (payload_size >= head_size) {
                            payload += head_size;
                            payload_size -= head_size;
                            conn->header_stripped = TRUE;
                        } else {
                             payload_size = 0; 
                        }
                    } else payload_size = 0;
                }

                if (payload_size > 0) PostSend(conn->clientSock, payload, payload_size);
            }
            if (frame_total < conn->ws_frag_len) memmove(conn->ws_frag_buf, conn->ws_frag_buf + frame_total, conn->ws_frag_len - (int)frame_total);
            conn->ws_frag_len -= (int)frame_total;
        }
    }
    proxy_free(plain_buf, max_plain);
}

DWORD WINAPI WorkerThread(LPVOID lpParam) {
    DWORD bytesTransferred = 0;
    ULONG_PTR completionKey = 0;
    LPOVERLAPPED pOverlapped = NULL;

    while (g_proxyRunning) {
        BOOL ret = GetQueuedCompletionStatus(hIOCP, &bytesTransferred, &completionKey, &pOverlapped, 1000);
        if (!ret && pOverlapped == NULL) { if (GetLastError() == WAIT_TIMEOUT) continue; continue; }

        CONNECTION_CONTEXT* conn = (CONNECTION_CONTEXT*)completionKey;
        IO_CONTEXT* ioCtx = (IO_CONTEXT*)pOverlapped;

        if (!ret || (bytesTransferred == 0 && (ioCtx->opType == IO_READ_CLIENT || ioCtx->opType == IO_READ_REMOTE))) {
            if (conn && !conn->closing) { conn->closing = TRUE; FreeConnectionContext(conn); }
            if (ioCtx && (ioCtx->opType == IO_WRITE_CLIENT || ioCtx->opType == IO_WRITE_REMOTE)) FreeIoContext(ioCtx);
            continue;
        }

        if (ioCtx) {
            switch (ioCtx->opType) {
                case IO_READ_CLIENT:
                    OnClientRead(conn, bytesTransferred);
                    if (!conn->closing) PostRecv(conn->clientSock, &conn->rxClient);
                    break;
                case IO_READ_REMOTE:
                    OnRemoteRead(conn, bytesTransferred);
                    if (!conn->closing) PostRecv(conn->remoteSock, &conn->rxRemote);
                    break;
                case IO_WRITE_CLIENT:
                case IO_WRITE_REMOTE:
                    FreeIoContext(ioCtx);
                    break;
            }
        }
    }
    return 0;
}

// [Fix] Add early_data support
void SwitchToIOCP(SOCKET c, SOCKET r, TLSContext* tls, BOOL is_vless, const char* early_data, int early_len) {
    CONNECTION_CONTEXT* conn = (CONNECTION_CONTEXT*)proxy_malloc(sizeof(CONNECTION_CONTEXT));
    if (!conn) return;
    memset(conn, 0, sizeof(CONNECTION_CONTEXT));
    
    conn->clientSock = c;
    conn->remoteSock = r;
    conn->refCount = 1;
    conn->is_vless = is_vless;
    
    conn->ws_frag_cap = 4096;
    conn->ws_frag_buf = (char*)proxy_malloc(conn->ws_frag_cap);
    
    conn->rxClient.opType = IO_READ_CLIENT;
    conn->rxClient.wsaBuf.buf = conn->rxClient.buffer;
    conn->rxClient.wsaBuf.len = IO_BUFFER_SIZE;
    conn->rxRemote.opType = IO_READ_REMOTE;
    conn->rxRemote.wsaBuf.buf = conn->rxRemote.buffer;
    conn->rxRemote.wsaBuf.len = IO_BUFFER_SIZE;

    if (!CreateIoCompletionPort((HANDLE)c, hIOCP, (ULONG_PTR)conn, 0) || !CreateIoCompletionPort((HANDLE)r, hIOCP, (ULONG_PTR)conn, 0)) {
        FreeConnectionContext(conn); return;
    }

    if (!tls_switch_to_mem_bio(conn, tls)) { FreeConnectionContext(conn); return; }

    // [Fix] Process Early Data (WS Handshake residue)
    if (early_data && early_len > 0) {
        if (conn->ws_frag_len + early_len > conn->ws_frag_cap) {
             // Resize logic... simplified
             int new_cap = conn->ws_frag_cap + early_len + 1024;
             char* tmp = (char*)proxy_malloc(new_cap);
             if(tmp) {
                 memcpy(tmp, conn->ws_frag_buf, conn->ws_frag_len);
                 proxy_free(conn->ws_frag_buf, conn->ws_frag_cap);
                 conn->ws_frag_buf = tmp;
                 conn->ws_frag_cap = new_cap;
             }
        }
        memcpy(conn->ws_frag_buf, early_data, early_len);
        conn->ws_frag_len = early_len;
        
        while (conn->ws_frag_len > 0) {
            int hl, pl;
            long long frame_total = check_ws_frame((unsigned char*)conn->ws_frag_buf, conn->ws_frag_len, &hl, &pl);
            if (frame_total <= 0) break;
            
            int opcode = conn->ws_frag_buf[0] & 0x0F;
            if ((opcode == 0x1 || opcode == 0x2) && pl > 0) {
                char* payload = conn->ws_frag_buf + hl;
                int payload_size = pl;
                if (conn->is_vless && !conn->header_stripped) {
                     if (payload_size >= 2) {
                        int addon_len = (unsigned char)payload[1];
                        int head_size = 2 + addon_len;
                        if (payload_size >= head_size) {
                            payload += head_size; payload_size -= head_size;
                            conn->header_stripped = TRUE;
                        } else payload_size = 0;
                     } else payload_size = 0;
                }
                if (payload_size > 0) PostSend(conn->clientSock, payload, payload_size);
            }
            if (frame_total < conn->ws_frag_len) memmove(conn->ws_frag_buf, conn->ws_frag_buf + frame_total, conn->ws_frag_len - (int)frame_total);
            conn->ws_frag_len -= (int)frame_total;
        }
    }

    PostRecv(c, &conn->rxClient);
    PostRecv(r, &conn->rxRemote);
}

DWORD WINAPI handshake_thread(LPVOID p) {
    InterlockedIncrement(&g_active_connections);
    ClientInitContext* ctx = (ClientInitContext*)p;
    if (!ctx) { InterlockedDecrement(&g_active_connections); return 0; }
    SOCKET c = ctx->clientSock;
    ProxyConfig localConfig = ctx->config; 
    CryptoSettings localCrypto = ctx->cryptoSettings;
    char localUserAgent[512]; strncpy(localUserAgent, ctx->userAgent, 511); localUserAgent[511] = 0;
    free(ctx); 

    TLSContext tls; memset(&tls, 0, sizeof(tls));
    SOCKET r = INVALID_SOCKET;      
    char *c_buf = NULL, *ws_send_buf = NULL, *ws_read_buf_tmp = NULL; 
    int browser_len, port = 80, is_connect_method = 0, is_socks5 = 0;
    char method[16], host[256], port_str[16], *header_end;
    int header_len = 0;
    struct addrinfo hints, *res = NULL, *ptr = NULL;

    c_buf = (char*)proxy_malloc(IO_BUFFER_SIZE); 
    ws_send_buf = (char*)proxy_malloc(IO_BUFFER_SIZE + 4096); 
    ws_read_buf_tmp = (char*)proxy_malloc(IO_BUFFER_SIZE);
    if (!c_buf || !ws_send_buf || !ws_read_buf_tmp) goto cl_err; 

    int flag = 1; setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
    browser_len = read_header_robust(c, c_buf, IO_BUFFER_SIZE, 10);
    if (browser_len <= 0) goto cl_err; 
    c_buf[browser_len] = 0;
    
    if (c_buf[0] == 0x05) { 
        send(c, "\x05\x00", 2, 0); is_socks5 = 1;
        int n = recv_timeout(c, c_buf, IO_BUFFER_SIZE, 10);
        if (n <= 0) goto cl_err;
        browser_len = n;
        if (c_buf[1] == 0x01) { 
             if (c_buf[3] == 0x01) { inet_ntop(AF_INET, &c_buf[4], host, sizeof(host)); port = ntohs(*(unsigned short*)&c_buf[8]); }
             else if (c_buf[3] == 0x03) { int dlen = (unsigned char)c_buf[4]; memcpy(host, &c_buf[5], dlen); host[dlen] = 0; port = ntohs(*(unsigned short*)&c_buf[5+dlen]); }
             else goto cl_err;
             strcpy(method, "SOCKS5");
        } else goto cl_err;
    } else {
        if (sscanf(c_buf, "%15s %255s", method, host) == 2) {
            char *p_col = strchr(host, ':');
            if (p_col) { *p_col = 0; port = atoi(p_col+1); }
            else if(stricmp(method, "CONNECT")==0) port = 443;
            if (stricmp(method, "CONNECT") == 0) is_connect_method = 1;
            header_end = strstr(c_buf, "\r\n\r\n");
            header_len = header_end ? (int)(header_end - c_buf) + 4 : browser_len;
        } else goto cl_err;
    }
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM; hints.ai_protocol = IPPROTO_TCP;
    snprintf(port_str, sizeof(port_str), "%d", localConfig.port);
    if (getaddrinfo(localConfig.host, port_str, &hints, &res) != 0) goto cl_err;
    for (int retry = 0; retry < 2; retry++) {
        for (ptr = res; ptr != NULL; ptr = ptr->ai_next) {
            r = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
            if (r == INVALID_SOCKET) continue;
            setsockopt(r, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
            if (connect(r, ptr->ai_addr, (int)ptr->ai_addrlen) == 0) {
                tls.sock = r;
                if (tls_init_connect(&tls, localConfig.sni, localConfig.host, &localCrypto) == 0) break;
                else { tls_close(&tls); closesocket(r); r = INVALID_SOCKET; }
            } else { closesocket(r); r = INVALID_SOCKET; }
        }
        if (r != INVALID_SOCKET && tls.ssl != NULL) break;
        Sleep(100);
    }
    if (r == INVALID_SOCKET || tls.ssl == NULL) goto cl_err;
    
    const char* sni_val = (strlen(localConfig.sni) > 0) ? localConfig.sni : localConfig.host;
    const char* req_path = (strlen(localConfig.path) > 0) ? localConfig.path : "/";
    unsigned char rnd_key[16]; char ws_key_str[32];
    for(int i=0; i<16; i++) rnd_key[i] = rand() % 256;
    base64_encode_key(rnd_key, ws_key_str);
    int offset = snprintf(ws_send_buf, IO_BUFFER_SIZE, 
        "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", req_path, sni_val, localUserAgent, ws_key_str);
    tls_write(&tls, ws_send_buf, offset);
    
    int hlen = tls_read(&tls, ws_read_buf_tmp, IO_BUFFER_SIZE - 1);
    if (hlen <= 0 || !strstr(ws_read_buf_tmp, "101")) goto cl_err;
    
    char* early_data = NULL;
    int early_len = 0;
    char* body_start = strstr(ws_read_buf_tmp, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
        early_len = hlen - (int)(body_start - ws_read_buf_tmp);
        if (early_len > 0) early_data = body_start;
    }

    unsigned char proto_buf[2048]; int proto_len = 0, flen = 0;
    struct in_addr ip4; 
    BOOL is_vless = (_stricmp(localConfig.type, "vless") == 0);
    
    if (is_vless) {
        proto_buf[proto_len++] = 0x00; parse_uuid(localConfig.user, proto_buf + proto_len); proto_len += 16; 
        proto_buf[proto_len++] = 0x00; proto_buf[proto_len++] = 0x01; 
        proto_buf[proto_len++] = (port >> 8) & 0xFF; proto_buf[proto_len++] = port & 0xFF;        
        if (inet_pton(AF_INET, host, &ip4) == 1) { proto_buf[proto_len++] = 0x01; memcpy(proto_buf + proto_len, &ip4, 4); proto_len += 4; } 
        else { proto_buf[proto_len++] = 0x02; proto_buf[proto_len++] = (unsigned char)strlen(host); memcpy(proto_buf + proto_len, host, strlen(host)); proto_len += (int)strlen(host); }
        flen = build_ws_frame((char*)proto_buf, proto_len, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
    } 

    if (is_socks5) send(c, "\x05\x00\x00\x01\0\0\0\0\0\0", 10, 0);
    else if (is_connect_method) send(c, "HTTP/1.1 200 Connection Established\r\n\r\n", 39, 0);
    
    if (!is_socks5 && is_connect_method && browser_len > header_len) {
        flen = build_ws_frame(c_buf + header_len, browser_len - header_len, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
    } else if (!is_connect_method && !is_socks5) {
        flen = build_ws_frame(c_buf, browser_len, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
    }

    SwitchToIOCP(c, r, &tls, is_vless, early_data, early_len);

    if (res) freeaddrinfo(res);
    proxy_free(c_buf, IO_BUFFER_SIZE);
    proxy_free(ws_send_buf, IO_BUFFER_SIZE + 4096);
    proxy_free(ws_read_buf_tmp, IO_BUFFER_SIZE);
    return 0;

cl_err:
    if (res) freeaddrinfo(res);
    proxy_free(c_buf, IO_BUFFER_SIZE);
    proxy_free(ws_send_buf, IO_BUFFER_SIZE + 4096);
    proxy_free(ws_read_buf_tmp, IO_BUFFER_SIZE);
    tls_close(&tls);
    if (r != INVALID_SOCKET) closesocket(r); 
    if (c != INVALID_SOCKET) closesocket(c);
    InterlockedDecrement(&g_active_connections);
    return 0;
}

DWORD WINAPI server_thread(LPVOID p) {
    // [Safety] 确保锁被初始化
    if (InterlockedCompareExchange(&g_locksInitialized, 1, 0) == 0) {
        InitGlobalLocks(); 
    }

    g_listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; addr.sin_port = htons(g_localPort); addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int opt = 1; setsockopt(g_listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    if (bind(g_listen_sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) { g_proxyRunning = FALSE; return 0; }
    listen(g_listen_sock, SOMAXCONN);
    
    while(g_proxyRunning) {
        SOCKET c = accept(g_listen_sock, NULL, NULL);
        if (c != INVALID_SOCKET) {
            ClientInitContext* ctx = (ClientInitContext*)malloc(sizeof(ClientInitContext));
            if (ctx) {
                ctx->clientSock = c;
                EnterCriticalSection(&g_configLock); // Now safe
                ctx->config = g_proxyConfig; 
                strncpy(ctx->userAgent, g_userAgentStr, 511);
                ctx->cryptoSettings.enableFragment = g_enableFragment;
                ctx->cryptoSettings.fragMin = g_fragSizeMin;
                ctx->cryptoSettings.fragMax = g_fragSizeMax;
                ctx->cryptoSettings.fragDelay = g_fragDelayMs;
                ctx->cryptoSettings.enablePadding = g_enablePadding;
                ctx->cryptoSettings.padMin = g_padSizeMin;
                ctx->cryptoSettings.padMax = g_padSizeMax;
                ctx->cryptoSettings.enableChromeCiphers = g_enableChromeCiphers;
                LeaveCriticalSection(&g_configLock);
                HANDLE hClient = (HANDLE)_beginthreadex(NULL, 0, (unsigned int (__stdcall *)(void *))handshake_thread, (void*)ctx, 0, NULL);
                if (hClient) CloseHandle(hClient); else { free(ctx); closesocket(c); }
            } else closesocket(c);
        } else break;
    }
    return 0;
}

void StartProxyCore() {
    if (g_proxyRunning) return;
    
    // [Safety] 确保锁被初始化 (双重保障)
    if (InterlockedCompareExchange(&g_locksInitialized, 1, 0) == 0) {
        InitGlobalLocks(); 
    }

    g_proxyRunning = TRUE;
    hIOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    SYSTEM_INFO si; GetSystemInfo(&si);
    for (int i = 0; i < (int)si.dwNumberOfProcessors * 2; i++) {
        CloseHandle((HANDLE)_beginthreadex(NULL, 0, (unsigned int (__stdcall *)(void *))WorkerThread, NULL, 0, NULL));
    }
    hProxyThread = CreateThread(NULL, 0, server_thread, NULL, 0, NULL);
}

void StopProxyCore() {
    g_proxyRunning = FALSE;
    if (g_listen_sock != INVALID_SOCKET) { closesocket(g_listen_sock); g_listen_sock = INVALID_SOCKET; }
    if (hIOCP) {
        SYSTEM_INFO si; GetSystemInfo(&si);
        for (int i=0; i < (int)si.dwNumberOfProcessors * 2; i++) PostQueuedCompletionStatus(hIOCP, 0, 0, NULL);
    }
    if (hProxyThread) { WaitForSingleObject(hProxyThread, 2000); CloseHandle(hProxyThread); hProxyThread = NULL; }
}

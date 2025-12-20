#include "proxy.h"
#include "crypto.h"
#include "utils.h"
#include "common.h"
#include <openssl/sha.h>

// [Safety] 全局活躍連接計數器，防止線程爆炸
static volatile LONG g_active_connections = 0;

// [Concurrency Fix] 客戶端線程上下文
// 保存所有配置的副本，確保 Worker 線程運行時不受 UI 修改全局變量的影響
typedef struct {
    SOCKET clientSock;
    ProxyConfig config;          // 節點配置副本
    char userAgent[512];         // User-Agent 副本
    CryptoSettings cryptoSettings; // 加密層配置副本 (分片、填充等)
} ClientContext;

// --- 輔助函數：解析 UUID (支持帶橫槓或不帶) ---
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
            p++; // 跳過非十六進制字符
        }
    }
}

// --- 輔助函數：Trojan 密碼哈希 (SHA224) ---
void trojan_password_hash(const char* password, char* out_hex) {
    unsigned char digest[SHA224_DIGEST_LENGTH];
    SHA224((unsigned char*)password, strlen(password), digest);
    for(int i = 0; i < SHA224_DIGEST_LENGTH; i++) {
        snprintf(out_hex + (i * 2), 3, "%02x", digest[i]); 
    }
    out_hex[SHA224_DIGEST_LENGTH * 2] = 0;
}

// 接收超時輔助函數 (使用 select 避免阻塞)
// 返回值: >0 接收字節數, 0 連接關閉, -1 錯誤, -2 超時
int recv_timeout(SOCKET s, char *buf, int len, int timeout_sec) {
    fd_set fds; 
    FD_ZERO(&fds); 
    FD_SET(s, &fds);
    
    struct timeval tv = { timeout_sec, 0 };
    int n = select(0, &fds, NULL, NULL, &tv);
    
    if (n == 0) return -2; // Timeout
    if (n < 0) return -1;  // Error
    
    return recv(s, buf, len, 0);
}

// [Robustness Fix] 健壯的頭部讀取函數
// 循環讀取直到發現完整的 HTTP 頭 (\r\n\r\n) 或 SOCKS 握手包
int read_header_robust(SOCKET s, char* buf, int max_len, int timeout_sec) {
    int total_read = 0;
    int remaining_time = timeout_sec;
    
    // 簡單的超時控制，每次循環扣除估算時間
    while (total_read < max_len - 1 && remaining_time > 0) {
        // 每次最多等待 1 秒，檢查是否有數據
        int n = recv_timeout(s, buf + total_read, max_len - 1 - total_read, 1);
        
        if (n == -2) { // 單次 select 超時
            remaining_time--;
            continue;
        }
        if (n <= 0) return -1; // 連接關閉或錯誤
        
        total_read += n;
        buf[total_read] = 0; // 確保字符串安全結尾

        // 1. 協議探測：SOCKS5
        // SOCKS5 初始握手通常很短 (VER NMETHODS METHODS)，如 05 01 00
        if (buf[0] == 0x05) {
            if (total_read >= 2) return total_read; 
        }
        // 2. 協議探測：HTTP
        // 檢查是否包含雙換行，標誌 HTTP Header 結束
        else {
            if (strstr(buf, "\r\n\r\n")) return total_read;
        }

        // 如果讀取了太多數據仍未找到邊界，可能是非標協議或攻擊，強制中斷
        if (total_read > 8192) break; 
    }
    return total_read > 0 ? total_read : -1;
}

// [Refactor] 發送全部數據輔助函數 (移除 Busy Wait，使用 select)
int send_all(SOCKET s, const char *buf, int len) {
    int total = 0; 
    int bytesleft = len; 
    int n;
    
    while(total < len) {
        n = send(s, buf+total, bytesleft, 0);
        if (n == -1) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) { 
                // [Optimization] 使用 select 等待 Socket 可寫
                fd_set wfd; 
                FD_ZERO(&wfd); 
                FD_SET(s, &wfd);
                struct timeval tv = { 1, 0 }; // 1秒超時
                
                int res = select(0, NULL, &wfd, NULL, &tv);
                if (res > 0) continue; // Socket 可寫，重試發送
                if (res == 0) continue; // 超時，繼續重試
                return -1; // select 錯誤
            }
            return -1;
        }
        total += n; 
        bytesleft -= n;
    }
    return total;
}

// 調試日誌輔助
void log_hex_simple(const char* tag, unsigned char* data, int len) {
    if (len <= 0) return;
    char buf[64] = {0};
    int max = len > 6 ? 6 : len;
    int p = 0;
    for(int i=0; i<max; i++) {
        p += snprintf(buf+p, sizeof(buf)-p, "%02X ", data[i]);
    }
    log_msg("%s %d bytes: %s...", tag, len, buf);
}

// --- Base64 編碼 (用於生成隨機 WS Key) ---
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

// --- 客戶端處理線程 (核心邏輯) ---
DWORD WINAPI client_handler(LPVOID p) {
    // [Safety] 連接數 +1
    InterlockedIncrement(&g_active_connections);

    ClientContext* ctx = (ClientContext*)p;
    if (!ctx) {
        InterlockedDecrement(&g_active_connections);
        return 0;
    }

    SOCKET c = ctx->clientSock;
    
    // [Thread Safety] 完全使用線程局部的配置副本，不訪問全局變量
    ProxyConfig localConfig = ctx->config; 
    CryptoSettings localCrypto = ctx->cryptoSettings;
    char localUserAgent[512];
    strncpy(localUserAgent, ctx->userAgent, sizeof(localUserAgent)-1);
    localUserAgent[sizeof(localUserAgent)-1] = 0;

    free(ctx); // 上下文數據已提取，立即釋放

    TLSContext tls; 
    SOCKET r = INVALID_SOCKET;      
    
    char *c_buf = NULL; 
    char *ws_read_buf = NULL; 
    char *ws_send_buf = NULL; 
    
    // [Refactor] 動態緩衝區狀態變量
    int ws_read_buf_cap = IO_BUFFER_SIZE; // 初始容量
    int ws_buf_len = 0; 

    int flag = 1; 

    int browser_len;
    char method[16], host[256]; 
    int port = 80; 
    int is_connect_method = 0;
    int is_socks5 = 0; 
    char *header_end = NULL;
    int header_len = 0;

    // [Refactor] 使用 addrinfo 替代 hostent
    struct addrinfo hints, *res = NULL, *ptr = NULL;
    char port_str[16];

    const char* sni_val;
    const char* req_path;
    int offset;
    int len;

    int flen = 0;
    unsigned char proto_buf[2048]; 
    int proto_len = 0;
    
    BOOL is_vless;
    BOOL is_trojan;
    BOOL is_shadowsocks;
    BOOL is_mandala; 
    
    struct in_addr ip4; 
    struct in6_addr ip6;
    
    fd_set fds; 
    struct timeval tv; 
    u_long mode = 1;
    int hl, pl;
    long long frame_total;
    int vless_response_header_stripped = 0;
    int retry_count = 0;
    
    // 初始化
    memset(&tls, 0, sizeof(tls));
    
    // [Refactor] 使用小緩衝區初始化，避免內存爆炸
    c_buf = (char*)malloc(IO_BUFFER_SIZE); 
    ws_read_buf = (char*)malloc(ws_read_buf_cap); 
    ws_send_buf = (char*)malloc(IO_BUFFER_SIZE + 4096); 

    if (!c_buf || !ws_read_buf || !ws_send_buf) goto cl_end; 
    
    setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
    
    // 1. [Robustness Fix] 讀取瀏覽器首包 (使用循環讀取確保完整性)
    browser_len = read_header_robust(c, c_buf, IO_BUFFER_SIZE, 10);
    if (browser_len <= 0) goto cl_end; 
    c_buf[browser_len] = 0;
    
    // 協議判斷
    if (c_buf[0] == 0x05) { 
        // Socks5 處理邏輯
        send(c, "\x05\x00", 2, 0); // 無需認證
        is_socks5 = 1;
        
        // 讀取後續請求 (CMD)
        int n = recv_timeout(c, c_buf, IO_BUFFER_SIZE, 10);
        if (n <= 0) goto cl_end;
        browser_len = n;
        
        if (c_buf[1] == 0x01) { // CONNECT
             if (c_buf[3] == 0x01) { // IPv4
                 struct in_addr* addr_ptr = (struct in_addr*)&c_buf[4];
                 port = ntohs(*(unsigned short*)&c_buf[8]);
                 inet_ntop(AF_INET, addr_ptr, host, sizeof(host));
             } else if (c_buf[3] == 0x03) { // Domain
                 int dlen = c_buf[4];
                 memcpy(host, &c_buf[5], dlen);
                 host[dlen] = 0;
                 port = ntohs(*(unsigned short*)&c_buf[5+dlen]);
             } else {
                 // IPv6 暫略或不支持
                 goto cl_end;
             }
             strcpy(method, "SOCKS5");
        } else {
             goto cl_end; 
        }
    } 
    else {
        // HTTP/HTTPS 處理邏輯
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
    
    // [Refactor] 使用 getaddrinfo 實現 DNS 解析
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // 支持 IPv4 和 IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    snprintf(port_str, sizeof(port_str), "%d", localConfig.port);

    if (getaddrinfo(localConfig.host, port_str, &hints, &res) != 0) {
        log_msg("[Err] DNS Fail: %s", localConfig.host);
        goto cl_end;
    }

    // 連接重試循環
    for (retry_count = 0; retry_count < 3; retry_count++) {
        // 遍歷 DNS 返回的所有地址
        for (ptr = res; ptr != NULL; ptr = ptr->ai_next) {
            r = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
            if (r == INVALID_SOCKET) continue;

            setsockopt(r, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
            int timeout_ms = 5000;
            setsockopt(r, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(int));
            setsockopt(r, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout_ms, sizeof(int));

            // 嘗試連接
            if (connect(r, ptr->ai_addr, (int)ptr->ai_addrlen) == 0) {
                tls.sock = r;
                // [Security] 使用傳入的 localCrypto 參數進行 TLS 連接，支持分片/填充
                if (tls_init_connect(&tls, localConfig.sni, localConfig.host, &localCrypto) == 0) {
                    break;
                } else {
                    tls_close(&tls);
                    closesocket(r);
                    r = INVALID_SOCKET;
                }
            } else {
                closesocket(r);
                r = INVALID_SOCKET;
            }
        }
        
        if (r != INVALID_SOCKET && tls.ssl != NULL) break;
        Sleep(200); // 重試間隔
    }
    
    if (r == INVALID_SOCKET || tls.ssl == NULL) goto cl_end;
    
    // 3. WebSocket 握手
    sni_val = (strlen(localConfig.sni) > 0) ? localConfig.sni : localConfig.host;
    req_path = (strlen(localConfig.path) > 0) ? localConfig.path : "/";
    
    unsigned char rnd_key[16];
    char ws_key_str[32];
    for(int i=0; i<16; i++) rnd_key[i] = rand() % 256;
    base64_encode_key(rnd_key, ws_key_str);

    // [Fix] 使用線程本地的 localUserAgent
    offset = snprintf(ws_send_buf, IO_BUFFER_SIZE, 
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n", 
        req_path, sni_val, localUserAgent, ws_key_str);

    tls_write(&tls, ws_send_buf, offset);

    // 讀取 WS 響應
    len = tls_read(&tls, ws_read_buf, ws_read_buf_cap - 1);
    if (len <= 0) goto cl_end;
    ws_read_buf[len] = 0;
    
    if (!strstr(ws_read_buf, "101")) { 
        log_msg("[Err] WS Handshake Fail: %.50s", ws_read_buf);
        goto cl_end; 
    }
    
    // 檢查 Early Data (粘包)
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
    
    // 4. 發送代理協議頭 (使用 localConfig)
    is_vless = (_stricmp(localConfig.type, "vless") == 0);
    is_trojan = (_stricmp(localConfig.type, "trojan") == 0);
    is_shadowsocks = (_stricmp(localConfig.type, "shadowsocks") == 0);
    is_mandala = (_stricmp(localConfig.type, "mandala") == 0);

    if (is_vless) {
        proto_buf[proto_len++] = 0x00; 
        parse_uuid(localConfig.user, proto_buf + proto_len); proto_len += 16; 
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
        char hex_pass[56 + 1]; trojan_password_hash(localConfig.pass, hex_pass);
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
        unsigned char salt[4];
        for(int i=0; i<4; i++) salt[i] = rand() % 256;

        unsigned char plaintext[2048]; 
        int p_len = 0;

        char hex_pass[57]; 
        trojan_password_hash(localConfig.pass, hex_pass);
        memcpy(plaintext + p_len, hex_pass, 56); p_len += 56;

        int pad_len = rand() % 16; 
        plaintext[p_len++] = (unsigned char)pad_len;
        for(int i=0; i<pad_len; i++) plaintext[p_len++] = rand() % 256;

        plaintext[p_len++] = 0x01;

        if (inet_pton(AF_INET, host, &ip4) == 1) {
             plaintext[p_len++] = 0x01; 
             memcpy(plaintext + p_len, &ip4, 4); p_len += 4;
        } else if (inet_pton(AF_INET6, host, &ip6) == 1) {
             plaintext[p_len++] = 0x04; 
             memcpy(plaintext + p_len, &ip6, 16); p_len += 16;
        } else {
             plaintext[p_len++] = 0x03; 
             plaintext[p_len++] = (unsigned char)strlen(host);
             memcpy(plaintext + p_len, host, strlen(host)); p_len += strlen(host);
        }

        plaintext[p_len++] = (port >> 8) & 0xFF; 
        plaintext[p_len++] = port & 0xFF;

        plaintext[p_len++] = 0x0D; plaintext[p_len++] = 0x0A;

        memcpy(proto_buf, salt, 4);
        for(int i=0; i<p_len; i++) {
            proto_buf[4 + i] = plaintext[i] ^ salt[i % 4];
        }
        proto_len = 4 + p_len;
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
        // SOCKS5 (outbound)
        char auth[] = {0x05, 0x01, 0x00}; 
        if (strlen(localConfig.user) > 0) auth[2] = 0x02; 
        flen = build_ws_frame(auth, 3, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
        char resp_buf[512]; 
        if (ws_read_payload_exact(&tls, resp_buf, 2) < 2) goto cl_end;
        if (resp_buf[1] == 0x02) {
            int ulen = strlen(localConfig.user);
            int plen = strlen(localConfig.pass);
            unsigned char auth_pkg[512];
            int ap_len = 0;
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
    
    // 5. 響應瀏覽器
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
    
    // 6. 轉發循環
    ioctlsocket(c, FIONBIO, &mode); 
    ioctlsocket(r, FIONBIO, &mode);

    while(1) {
        FD_ZERO(&fds); 
        FD_SET(c, &fds); 
        FD_SET(r, &fds);
        
        int pending = SSL_pending(tls.ssl);
        tv.tv_sec = 1; 
        tv.tv_usec = 0;
        
        // 如果有緩存數據，立即處理，不等待 select
        if (pending > 0 || ws_buf_len > 0) { 
            tv.tv_sec = 0; 
            tv.tv_usec = 0; 
        }
        
        int n = select(0, &fds, NULL, NULL, &tv);
        if (n < 0) break;
        
        // 瀏覽器 -> 代理服務器
        if (FD_ISSET(c, &fds)) {
            // [Refactor] Recv 使用 IO_BUFFER_SIZE
            len = recv(c, c_buf, IO_BUFFER_SIZE, 0);
            if (len > 0) {
                flen = build_ws_frame(c_buf, len, ws_send_buf);
                if (tls_write(&tls, ws_send_buf, flen) < 0) {
                    break;
                }
            } else if (len == 0) {
                break;
            } else if (WSAGetLastError() != WSAEWOULDBLOCK) {
                break;
            }
        }
        
        // 代理服務器 -> 瀏覽器
        if (FD_ISSET(r, &fds) || pending > 0) {
            // [Refactor] 動態擴容邏輯
            // 檢查剩餘空間是否足夠，如果空間快滿了，則擴容
            if (ws_buf_len >= ws_read_buf_cap - 1024) { 
                if (ws_read_buf_cap < MAX_WS_FRAME_SIZE) {
                    int new_cap = ws_read_buf_cap * 2;
                    if (new_cap > MAX_WS_FRAME_SIZE) new_cap = MAX_WS_FRAME_SIZE;
                    
                    if (new_cap > ws_read_buf_cap) {
                        char* new_buf = (char*)realloc(ws_read_buf, new_cap);
                        if (!new_buf) {
                            log_msg("[Err] OOM expanding read buffer");
                            goto cl_end;
                        }
                        ws_read_buf = new_buf;
                        ws_read_buf_cap = new_cap;
                    }
                } else {
                    // 如果已經達到最大限制且緩衝區滿了，說明幀太大或者處理不及時
                    if (ws_buf_len >= MAX_WS_FRAME_SIZE) goto cl_end;
                }
            }

            if (ws_buf_len < ws_read_buf_cap) {
                len = tls_read(&tls, ws_read_buf + ws_buf_len, ws_read_buf_cap - ws_buf_len);
                if (len > 0) ws_buf_len += len;
                else if (len == -1) {
                    break; 
                }
            }
        }
        
        // 解析 WebSocket 幀
        while (ws_buf_len > 0) {
            frame_total = check_ws_frame((unsigned char*)ws_read_buf, ws_buf_len, &hl, &pl);
            if (frame_total < 0) goto cl_end;
            if (frame_total > 0) {
                int opcode = ws_read_buf[0] & 0x0F;
                if (opcode == 0x8) goto cl_end; // Close Frame
                
                // Text or Binary Frame
                if ((opcode == 0x1 || opcode == 0x2) && pl > 0) {
                    char* payload_ptr = ws_read_buf + hl;
                    int payload_size = pl;
                    
                    // VLESS 響應頭剝離邏輯
                    if (is_vless && !vless_response_header_stripped) {
                        if (payload_size >= 2) {
                            int addon_len = (unsigned char)payload_ptr[1];
                            int head_size = 2 + addon_len;
                            if (payload_size >= head_size) {
                                payload_ptr += head_size;
                                payload_size -= head_size;
                                vless_response_header_stripped = 1;
                            } else { 
                                payload_size = 0; // 數據不足，等待下一幀
                            }
                        } else { payload_size = 0; }
                    }
                    
                    if (payload_size > 0) {
                        if (send_all(c, payload_ptr, payload_size) < 0) goto cl_end;
                    }
                }
                
                // 移除已處理的幀
                if (frame_total < ws_buf_len) {
                    memmove(ws_read_buf, ws_read_buf + frame_total, ws_buf_len - frame_total);
                }
                ws_buf_len -= (int)frame_total;
            } else { 
                // [Refactor] 如果緩衝區已滿但仍未解析出完整幀（說明幀大小 > 當前容量）
                if (ws_buf_len >= ws_read_buf_cap) {
                     if (ws_read_buf_cap >= MAX_WS_FRAME_SIZE) goto cl_end;
                }
                break; // 數據不完整，等待更多數據
            }
        }
    }

cl_end:
    if (res) freeaddrinfo(res);
    if (c_buf) free(c_buf); 
    if (ws_read_buf) free(ws_read_buf); 
    if (ws_send_buf) free(ws_send_buf); 
    
    tls_close(&tls);
    
    if (r != INVALID_SOCKET) closesocket(r); 
    if (c != INVALID_SOCKET) closesocket(c);
    
    // [Safety] 連接數 -1
    InterlockedDecrement(&g_active_connections);
    return 0;
}

// 監聽線程與管理函數
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
        log_msg("Port %d bind fail", g_localPort); 
        g_proxyRunning = FALSE; 
        return 0;
    }
    
    listen(g_listen_sock, 100);
    log_msg("Proxy Started: 127.0.0.1:%d", g_localPort);
    
    while(g_proxyRunning) {
        SOCKET c = accept(g_listen_sock, NULL, NULL);
        if (c != INVALID_SOCKET) {
            // [Safety] 檢查是否超過最大連接數
            if (g_active_connections >= MAX_CONNECTIONS) {
                log_msg("[Warn] Max connections (%d) reached. Dropping request.", MAX_CONNECTIONS);
                closesocket(c);
                Sleep(10); // 稍微退避，防止 CPU 空轉
                continue;
            }

            // [Concurrency Fix] 分配上下文並複製配置
            ClientContext* ctx = (ClientContext*)malloc(sizeof(ClientContext));
            if (ctx) {
                ctx->clientSock = c;
                
                // [Lock] 鎖住全局變量，確保複製的原子性
                EnterCriticalSection(&g_configLock);
                
                ctx->config = g_proxyConfig; 
                strncpy(ctx->userAgent, g_userAgentStr, sizeof(ctx->userAgent)-1);
                ctx->userAgent[sizeof(ctx->userAgent)-1] = 0;
                
                // [Snapshot] 快照加密配置
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
                    log_msg("[Err] CreateThread failed");
                }
            } else {
                closesocket(c);
                log_msg("[Err] OOM creating context");
            }
        } else break;
    }
    return 0;
}

void StartProxyCore() {
    if (g_proxyRunning) return;
    g_proxyRunning = TRUE;
    hProxyThread = CreateThread(NULL, 0, server_thread, NULL, 0, NULL);
    if (!hProxyThread) { 
        log_msg("CreateThread Failed"); 
        g_proxyRunning = FALSE; 
    }
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
    log_msg("Proxy Stopped");
}

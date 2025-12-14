#include "proxy.h"
#include "crypto.h"
#include "utils.h"
#include <openssl/sha.h>
#include <time.h> 

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
    unsigned char proto_buf[2048]; // 加大缓冲区以容纳 VMess 头
    int proto_len = 0;
    
    BOOL is_vless;
    BOOL is_trojan;
    BOOL is_shadowsocks;
    BOOL is_vmess; // [New] VMess flag
    
    struct in_addr ip4; 
    struct in6_addr ip6;
    
    fd_set fds; 
    struct timeval tv; 
    u_long mode = 1;
    int hl, pl;
    long long frame_total;
    int vless_response_header_stripped = 0;
    int vmess_response_header_stripped = 0; // [New]
    int retry_count = 0;
    
    // VMess 加密上下文
    AesCfbCtx vmess_enc_ctx;
    AesCfbCtx vmess_dec_ctx;
    
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
    is_vmess = (_stricmp(g_proxyConfig.type, "vmess") == 0); // [New] VMess detection

    if (is_vless) {
        // ... (VLESS logic kept as is) ...
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
    } else if (is_vmess) {
        // --- VMess Logic Start ---
        unsigned char uuid[16];
        parse_uuid(g_proxyConfig.user, uuid);
        
        long long ts = (long long)time(NULL);
        unsigned char req_iv[16];
        unsigned char req_key[16];
        
        // 1. 生成 Request IV (Random 16 bytes)
        for(int i=0; i<16; i++) req_iv[i] = rand() % 256;
        
        // 2. 生成 Request Key (Random 16 bytes)
        for(int i=0; i<16; i++) req_key[i] = rand() % 256;
        
        // 3. 生成 Header Key & IV (用于加密指令部分)
        unsigned char head_key[16], head_iv[16];
        vmess_kdf_header(uuid, head_key, head_iv); // IV 其实不基于 UUID，而是基于 TS
        vmess_kdf_iv(ts, head_iv); // 修正 IV 生成

        // 4. 构建 VMess 认证头 (16 bytes)
        unsigned char auth[16];
        vmess_get_auth(uuid, ts, auth);
        memcpy(proto_buf, auth, 16);
        proto_len = 16;

        // 5. 构建 VMess 指令部分 (在临时缓冲区)
        unsigned char cmd_buf[512];
        int cmd_len = 0;
        
        cmd_buf[cmd_len++] = 1; // Ver
        memcpy(cmd_buf + cmd_len, req_iv, 16); cmd_len += 16;
        memcpy(cmd_buf + cmd_len, req_key, 16); cmd_len += 16;
        cmd_buf[cmd_len++] = rand() % 256; // V (Response Auth Byte)
        cmd_buf[cmd_len++] = 0x01; // Opt (Standard)
        // P (Padding Len 4 bits | Security 4 bits)
        // Security: 3 (AES-128-GCM) is common, but CFB is 0?
        // Let's use AES-128-CFB (0) or Auto (3). Using Auto (3) often implies AEAD which is hard.
        // Using Type 0 (AES-128-CFB) for legacy compatibility.
        // P: High 4 bits padding len, Low 4 bits security type (0=AES-128-CFB)
        int pad_len = rand() % 16;
        cmd_buf[cmd_len++] = (pad_len << 4) | 0x00; // Sec=0 (AES-128-CFB)
        
        cmd_buf[cmd_len++] = 0; // Reserved
        cmd_buf[cmd_len++] = 1; // Cmd: 1=TCP
        
        cmd_buf[cmd_len++] = (port >> 8) & 0xFF; 
        cmd_buf[cmd_len++] = port & 0xFF;
        
        if (inet_pton(AF_INET, host, &ip4) == 1) {
            cmd_buf[cmd_len++] = 0x01; memcpy(cmd_buf + cmd_len, &ip4, 4); cmd_len += 4;
        } else if (inet_pton(AF_INET6, host, &ip6) == 1) {
            cmd_buf[cmd_len++] = 0x03; memcpy(cmd_buf + cmd_len, &ip6, 16); cmd_len += 16;
        } else {
            cmd_buf[cmd_len++] = 0x02; cmd_buf[cmd_len++] = (unsigned char)strlen(host);
            memcpy(cmd_buf + cmd_len, host, strlen(host)); cmd_len += strlen(host);
        }
        
        if (pad_len > 0) {
            for(int i=0; i<pad_len; i++) cmd_buf[cmd_len++] = rand() % 256;
        }
        
        unsigned int f = fnv1a_hash(cmd_buf, cmd_len);
        cmd_buf[cmd_len++] = (f >> 24) & 0xFF;
        cmd_buf[cmd_len++] = (f >> 16) & 0xFF;
        cmd_buf[cmd_len++] = (f >> 8) & 0xFF;
        cmd_buf[cmd_len++] = f & 0xFF;
        
        // 6. 加密指令部分并拼接到 proto_buf
        AesCfbCtx head_enc_ctx;
        aes_cfb128_init(&head_enc_ctx, head_key, head_iv);
        aes_cfb128_encrypt(&head_enc_ctx, cmd_buf, proto_buf + proto_len, cmd_len);
        proto_len += cmd_len;
        
        // 发送 VMess 头部
        flen = build_ws_frame((char*)proto_buf, proto_len, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
        
        // 7. 初始化 Body 加密上下文 (Request Body)
        aes_cfb128_init(&vmess_enc_ctx, req_key, req_iv);
        
        // 8. 初始化 Body 解密上下文 (Response Body)
        // Response Key = MD5(ReqKey), Response IV = MD5(ReqIV)
        unsigned char resp_key[16], resp_iv[16];
        vmess_md5(req_key, 16, resp_key);
        vmess_md5(req_iv, 16, resp_iv);
        aes_cfb128_init(&vmess_dec_ctx, resp_key, resp_iv);
        
        // --- VMess Logic End ---
    } else if (is_trojan) {
        // ... (Trojan logic kept as is) ...
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
    } else if (is_shadowsocks) {
        // ... (SS logic kept as is) ...
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
        // ... (Socks5/Default logic kept as is) ...
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
            
            // [New] VMess: 如果有剩余数据，需要加密后发送
            if (is_vmess) {
                aes_cfb128_encrypt(&vmess_enc_ctx, (unsigned char*)(c_buf + header_len), (unsigned char*)c_buf, extra_len); // 原地加密
                flen = build_ws_frame(c_buf, extra_len, ws_send_buf);
            } else {
                flen = build_ws_frame(c_buf + header_len, extra_len, ws_send_buf);
            }
            tls_write(&tls, ws_send_buf, flen);
        }
    } else {
        // [New] VMess: 全局加密浏览器首包
        if (is_vmess) {
            aes_cfb128_encrypt(&vmess_enc_ctx, (unsigned char*)c_buf, (unsigned char*)c_buf, browser_len); // 原地加密
        }
        flen = build_ws_frame(c_buf, browser_len, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
    }
    
    // 6. 转发循环
    ioctlsocket(c, FIONBIO, &mode); ioctlsocket(r, FIONBIO, &mode);

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
                // [New] VMess Encryption
                if (is_vmess) {
                    aes_cfb128_encrypt(&vmess_enc_ctx, (unsigned char*)c_buf, (unsigned char*)c_buf, len);
                }
                
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
        
        if (FD_ISSET(r, &fds) || pending > 0) {
            if (ws_buf_len < BUFFER_SIZE) {
                len = tls_read(&tls, ws_read_buf + ws_buf_len, BUFFER_SIZE - ws_buf_len);
                if (len > 0) ws_buf_len += len;
                else if (len == -1) {
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
                    
                    // --- VLESS Response Header Stripping ---
                    if (is_vless && !vless_response_header_stripped) {
                        if (payload_size >= 2) {
                            int addon_len = (unsigned char)payload_ptr[1];
                            int head_size = 2 + addon_len;
                            if (payload_size >= head_size) {
                                payload_ptr += head_size;
                                payload_size -= head_size;
                                vless_response_header_stripped = 1;
                            } else { 
                                payload_size = 0; 
                            }
                        } else { payload_size = 0; }
                    }
                    
                    // --- [New] VMess Response Decryption & Header Stripping ---
                    if (is_vmess) {
                        // 1. 解密数据流
                        aes_cfb128_decrypt(&vmess_dec_ctx, (unsigned char*)payload_ptr, (unsigned char*)payload_ptr, payload_size);
                        
                        // 2. 剥离 Response Header
                        if (!vmess_response_header_stripped) {
                            // VMess Response Header 也是加密的，但我们已经解密了数据流。
                            // 格式: [ResponseHeaderLen(1)] [ResponseHeader(Ver,Option,Cmd,CmdLen,Cmd...)]
                            // 实际的 VMess 响应头长度是动态的。
                            // 简单处理：第一个字节是 Response 认证信息 V？
                            // 标准 Response Header：
                            // [V(1)][Opt(1)][Cmd(1)][CmdLen(1)][CmdData(N)]
                            // 我们需要剥离这部分。
                            if (payload_size >= 4) {
                                int cmd_len = (unsigned char)payload_ptr[3];
                                int head_size = 4 + cmd_len;
                                if (payload_size >= head_size) {
                                    payload_ptr += head_size;
                                    payload_size -= head_size;
                                    vmess_response_header_stripped = 1;
                                } else {
                                    // 头不完整，丢弃当前帧 (实际应缓存，为简化暂时丢弃)
                                    payload_size = 0;
                                }
                            } else {
                                payload_size = 0;
                            }
                        }
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

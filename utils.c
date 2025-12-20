#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wininet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "crypto.h" 

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

// 系统代理注册表路径
#define REG_PATH_PROXY L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"

extern int g_localPort; 
extern BOOL g_enableLog; 

// --- 日志函数 ---
void log_msg(const char *format, ...) {
    // 生产环境安全建议：保留 Fatal 错误日志，即使 g_enableLog 为 FALSE
    if (!g_enableLog && strstr(format, "[Fatal]") == NULL) return;

    char buf[2048]; 
    char time_buf[64]; 
    SYSTEMTIME st; 
    GetLocalTime(&st);
    
    // [Safety] 使用 snprintf 防止溢出
    snprintf(time_buf, sizeof(time_buf), "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
    
    va_list args; 
    va_start(args, format); 
    vsnprintf(buf, sizeof(buf)-64, format, args); 
    va_end(args);
    
    char final_msg[2200]; 
    snprintf(final_msg, sizeof(final_msg), "%s%s\r\n", time_buf, buf);
    
    OutputDebugStringA(final_msg);
    HWND hLogViewerWnd = FindWindowW(L"LogWnd", NULL);
    if (hLogViewerWnd && IsWindow(hLogViewerWnd)) {
        int wLen = MultiByteToWideChar(CP_UTF8, 0, final_msg, -1, NULL, 0);
        wchar_t* wBuf = (wchar_t*)malloc((wLen + 1) * sizeof(wchar_t));
        if (wBuf) {
            MultiByteToWideChar(CP_UTF8, 0, final_msg, -1, wBuf, wLen);
            wBuf[wLen] = 0;
            PostMessageW(hLogViewerWnd, WM_LOG_UPDATE, 0, (LPARAM)wBuf);
        }
    }
}

void log_wsa_error(const char* context) {
    int err = WSAGetLastError();
    log_msg("[Error] %s Failed. Code: %d", context, err);
}

// --- 文件操作 ---
BOOL ReadFileToBuffer(const wchar_t* filename, char** buffer, long* fileSize) {
    // [Fix] 使用 _wfopen 替代 _wfopen_s 以兼容 MinGW
    FILE* f = _wfopen(filename, L"rb");
    if (!f) { *fileSize=0; return FALSE; }
    
    fseek(f, 0, SEEK_END); 
    *fileSize = ftell(f); 
    fseek(f, 0, SEEK_SET);
    
    *buffer = (char*)malloc(*fileSize + 1);
    if (*buffer) {
        fread(*buffer, 1, *fileSize, f); 
        (*buffer)[*fileSize] = 0;
    }
    fclose(f); 
    return (*buffer != NULL);
}

BOOL WriteBufferToFile(const wchar_t* filename, const char* buffer) {
    FILE* f = _wfopen(filename, L"wb");
    if (!f) return FALSE;
    fwrite(buffer, 1, strlen(buffer), f);
    fclose(f); 
    return TRUE;
}

// --- 字符串处理 ---
void TrimString(char* str) {
    if(!str) return;
    char* p = str; while(isspace((unsigned char)*p)) p++;
    if(p != str) memmove(str, p, strlen(p)+1);
    size_t len = strlen(str); while(len > 0 && isspace((unsigned char)str[len-1])) str[--len] = 0;
}

void UrlDecode(char* dst, const char* src) {
    char a, b;
    while (*src) {
        if ((*src == '%') && ((a = src[1]) && (b = src[2])) && (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a') a -= 'a' - 'A'; else if (a >= 'A') a -= ('A' - 10); else a -= '0';
            if (b >= 'a') b -= 'a' - 'A'; else if (b >= 'A') b -= ('A' - 10); else b -= '0';
            *dst++ = 16 * a + b; src += 3;
        } else if (*src == '+') { *dst++ = ' '; src++; } else { *dst++ = *src++; }
    }
    *dst = '\0';
}

// [修复] 循环版 GetQueryParam，增加对 '#' 的判断
char* GetQueryParam(const char* query, const char* key) {
    if (!query || !key) return NULL;
    char keyEq[128]; 
    // [Security Fix] 使用 snprintf
    snprintf(keyEq, sizeof(keyEq), "%s=", key);
    size_t keyEqLen = strlen(keyEq);

    const char* p = query;
    while ((p = strstr(p, keyEq)) != NULL) {
        // 确保匹配的是参数名，而不是值的后缀 (例如 key=...&real_key=...)
        if (p == query || *(p - 1) == '&' || *(p - 1) == '?') {
            const char* start = p + keyEqLen;
            size_t len = 0;
            // 读取直到遇到 '&' 或 '#' 或 字符串结束
            while (start[len] && start[len] != '&' && start[len] != '#') {
                len++;
            }
            if (len == 0) return NULL;
            
            char* value = (char*)malloc(len + 1);
            if (!value) return NULL;
            strncpy(value, start, len);
            value[len] = '\0';

            char* decoded = (char*)malloc(len + 1);
            if (!decoded) { free(value); return NULL; }
            UrlDecode(decoded, value);
            free(value);
            return decoded;
        }
        p += 1; 
    }
    return NULL;
}

// --- Base64 和其他辅助函数 ---
static int GetBase64Val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62; 
    if (c == '/' || c == '_') return 63; 
    return -1;
}

unsigned char* Base64Decode(const char* src, size_t* out_len) {
    if (!src) return NULL;
    size_t len = strlen(src);
    // 移除末尾的填充和空白
    while (len > 0 && (src[len-1] == '\n' || src[len-1] == '\r' || src[len-1] == ' ' || src[len-1] == '=')) len--;
    if (len == 0) { *out_len = 0; return NULL; }
    
    *out_len = (len * 3) / 4;
    unsigned char* out = (unsigned char*)malloc(*out_len + 4); 
    if (!out) return NULL;
    
    size_t i = 0, j = 0;
    while (i < len) {
        // 跳过非 Base64 字符 (换行符等)
        if (src[i] == '\r' || src[i] == '\n' || src[i] == ' ') { i++; continue; }
        
        int vals[4]; 
        int val_cnt = 0;
        while (i < len && val_cnt < 4) {
            char c = src[i];
            if (c == '\r' || c == '\n' || c == ' ') { i++; continue; }
            if (c == '=') { i++; break; } // 遇到填充符提前结束
            int v = GetBase64Val(c);
            if (v == -1) { 
                // 遇到非法字符，视为解码失败
                free(out); return NULL; 
            }
            vals[val_cnt++] = v; 
            i++;
        }
        
        if (val_cnt > 0) {
            uint32_t triple = (vals[0] << 18) | 
                              ((val_cnt > 1 ? vals[1] : 0) << 12) | 
                              ((val_cnt > 2 ? vals[2] : 0) << 6) | 
                              ((val_cnt > 3 ? vals[3] : 0));
            
            if (j < *out_len) out[j++] = (triple >> 16) & 0xFF;
            if (val_cnt > 2 && j < *out_len) out[j++] = (triple >> 8) & 0xFF;
            if (val_cnt > 3 && j < *out_len) out[j++] = triple & 0xFF;
        }
    }
    out[j] = '\0'; 
    *out_len = j; 
    return out;
}

char* GetClipboardText() {
    if (!OpenClipboard(NULL)) return NULL;
    HANDLE hData = GetClipboardData(CF_UNICODETEXT);
    if (hData != NULL) {
        wchar_t* pszTextW = (wchar_t*)GlobalLock(hData);
        if (pszTextW != NULL) {
            int utf8Len = WideCharToMultiByte(CP_UTF8, 0, pszTextW, -1, NULL, 0, NULL, NULL);
            char* text = (char*)malloc(utf8Len + 1);
            if (text) {
                WideCharToMultiByte(CP_UTF8, 0, pszTextW, -1, text, utf8Len, NULL, NULL);
                text[utf8Len] = 0;
                TrimString(text);
            }
            GlobalUnlock(hData); CloseClipboard(); return text;
        }
    }
    hData = GetClipboardData(CF_TEXT);
    if (hData != NULL) {
        char* pszText = (char*)GlobalLock(hData);
        if (pszText != NULL) {
            char* text = strdup(pszText);
            GlobalUnlock(hData); CloseClipboard(); 
            if (text) TrimString(text); 
            return text;
        }
    }
    CloseClipboard(); return NULL;
}

// --- URL 解析结构 ---
typedef struct {
    char host[256];
    char path[2048];
    int port;
} URL_COMPONENTS_SIMPLE;

static BOOL ParseUrl(const char* url, URL_COMPONENTS_SIMPLE* out) {
    if (!url || !out) return FALSE;
    memset(out, 0, sizeof(URL_COMPONENTS_SIMPLE));
    
    const char* p = url;
    if (strncmp(p, "https://", 8) == 0) { out->port = 443; p += 8; }
    else if (strncmp(p, "http://", 7) == 0) { out->port = 80; p += 7; }
    else return FALSE; 

    const char* slash = strchr(p, '/');
    int hostLen = (slash) ? (int)(slash - p) : (int)strlen(p);
    if (hostLen >= sizeof(out->host)) return FALSE;
    strncpy(out->host, p, hostLen);
    out->host[hostLen] = '\0';

    char* colon = strchr(out->host, ':');
    if (colon) {
        *colon = '\0';
        out->port = atoi(colon + 1);
    }

    if (slash) {
        if (strlen(slash) >= sizeof(out->path)) return FALSE; 
        strcpy(out->path, slash);
    } else {
        strcpy(out->path, "/");
    }
    return TRUE;
}

static char* InternalHttpsGet(const char* url, BOOL useProxy) {
    URL_COMPONENTS_SIMPLE u;
    if (!ParseUrl(url, &u)) { log_msg("[Utils] Invalid URL or too long: %s", url); return NULL; }

    static int ssl_inited = 0;
    if (!ssl_inited) {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ssl_inited = 1;
    }

    SOCKET s = INVALID_SOCKET;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    char* result = NULL;

    const char* targetHost = useProxy ? "127.0.0.1" : u.host;
    int targetPort = useProxy ? g_localPort : u.port;

    if (useProxy) log_msg("[Utils] Connecting via Proxy: %s:%d", targetHost, targetPort);
    else log_msg("[Utils] Connecting DIRECT to: %s:%d", targetHost, targetPort);

    struct hostent *he = gethostbyname(targetHost);
    if (!he) { log_msg("[Utils] DNS resolution failed for %s", targetHost); return NULL; }

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return NULL;

    DWORD timeout = 10000; 
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(targetPort);
    addr.sin_addr = *((struct in_addr *)he->h_addr);

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        log_wsa_error("Socket Connect");
        closesocket(s);
        return NULL;
    }

    if (useProxy) {
        char connectReq[512];
        snprintf(connectReq, sizeof(connectReq), 
            "CONNECT %s:%d HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "\r\n", 
            u.host, u.port, u.host, u.port);
        send(s, connectReq, (int)strlen(connectReq), 0);
        char buf[1024];
        int n = recv(s, buf, sizeof(buf)-1, 0);
        if (n <= 0) { log_msg("[Utils] Proxy handshake failed (recv)"); closesocket(s); return NULL; }
        buf[n] = 0;
        if (!strstr(buf, "200 Connection Established")) {
            log_msg("[Utils] Proxy handshake failed. Response: %s", buf);
            closesocket(s); return NULL;
        }
    }

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { closesocket(s); return NULL; }
    
    // [Note] 下载订阅时暂不验证证书，防止自签证书订阅失败
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)s);

    SSL_set_tlsext_host_name(ssl, u.host);

    if (SSL_connect(ssl) != 1) {
        log_msg("[Utils] SSL Handshake Failed.");
        goto cleanup;
    }

    char request[4096];
    snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: Mandala/1.0\r\n"
        "Connection: close\r\n"
        "\r\n",
        u.path, u.host);
    
    if (SSL_write(ssl, request, (int)strlen(request)) <= 0) goto cleanup;

    int buffer_size = 65536; 
    int total_read = 0;
    char* resp_buf = (char*)malloc(buffer_size);
    if(!resp_buf) goto cleanup;

    while (1) {
        if (total_read + 4096 >= buffer_size) {
            buffer_size *= 2;
            char* new_buf = (char*)realloc(resp_buf, buffer_size);
            if (!new_buf) { free(resp_buf); resp_buf=NULL; goto cleanup; }
            resp_buf = new_buf;
        }
        int r = SSL_read(ssl, resp_buf + total_read, 4096);
        if (r <= 0) break; 
        total_read += r;
    }
    resp_buf[total_read] = 0;

    char* body_start = strstr(resp_buf, "\r\n\r\n");
    if (!body_start) {
        body_start = strstr(resp_buf, "\n\n");
    }

    if (body_start) {
        if (body_start[0] == '\r') body_start += 4;
        else body_start += 2;

        int header_len = (int)(body_start - resp_buf);
        int body_len = total_read - header_len;
        
        if (body_len > 0) {
            result = (char*)malloc(body_len + 1);
            memcpy(result, body_start, body_len);
            result[body_len] = 0;
        }
    } else {
        log_msg("[Utils] Invalid HTTP response format");
    }

    free(resp_buf); 

cleanup:
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    if (ctx) SSL_CTX_free(ctx);
    if (s != INVALID_SOCKET) closesocket(s);
    return result;
}

char* Utils_HttpGet(const char* url) {
    if (!url) return NULL;
    if (g_localPort > 0) {
        char* res = InternalHttpsGet(url, TRUE);
        if (res) return res;
        log_msg("[Utils] Proxy download failed, falling back to DIRECT mode...");
    }
    return InternalHttpsGet(url, FALSE);
}

// ==========================================
// [ECH] 新增功能：Base64/Base64Url/DoH
// ==========================================

static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// 标准 Base64 编码 (用于 ECH 导出)
void Base64Encode(const unsigned char* src, int len, char* dst) {
    int i = 0, j = 0;
    for (; i < len; i += 3) {
        int val = (src[i] << 16) + (i + 1 < len ? src[i+1] << 8 : 0) + (i + 2 < len ? src[i+2] : 0);
        dst[j++] = base64_chars[(val >> 18) & 0x3F];
        dst[j++] = base64_chars[(val >> 12) & 0x3F];
        if (i + 1 < len) dst[j++] = base64_chars[(val >> 6) & 0x3F];
        else dst[j++] = '=';
        if (i + 2 < len) dst[j++] = base64_chars[val & 0x3F];
        else dst[j++] = '=';
    }
    dst[j] = 0;
}

// Base64Url 编码 (用于 DoH 查询参数)
void Base64UrlEncode(const unsigned char* src, int len, char* dst) {
    const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    int i = 0, j = 0;
    for (; i < len; i += 3) {
        int val = (src[i] << 16) + (i + 1 < len ? src[i+1] << 8 : 0) + (i + 2 < len ? src[i+2] : 0);
        dst[j++] = tbl[(val >> 18) & 0x3F];
        dst[j++] = tbl[(val >> 12) & 0x3F];
        if (i + 1 < len) dst[j++] = tbl[(val >> 6) & 0x3F];
        else dst[j++] = '='; 
        if (i + 2 < len) dst[j++] = tbl[val & 0x3F];
        else dst[j++] = '=';
    }
    // Remove padding for Base64Url
    while (j > 0 && dst[j-1] == '=') j--;
    dst[j] = 0;
}

int BuildDNSQueryHTTPS(const char* domain, unsigned char* buf) {
    int pos = 0;
    // Header
    buf[pos++] = 0; buf[pos++] = 0; // ID
    buf[pos++] = 0x01; buf[pos++] = 0x00; // RD=1
    buf[pos++] = 0; buf[pos++] = 1; // QDCOUNT
    buf[pos++] = 0; buf[pos++] = 0; // ANCOUNT
    buf[pos++] = 0; buf[pos++] = 0; // NSCOUNT
    buf[pos++] = 0; buf[pos++] = 0; // ARCOUNT
    
    // QNAME
    const char* p = domain;
    const char* dot;
    while ((dot = strchr(p, '.'))) {
        int len = (int)(dot - p);
        buf[pos++] = len;
        memcpy(buf + pos, p, len);
        pos += len;
        p = dot + 1;
    }
    if (*p) {
        int len = (int)strlen(p);
        buf[pos++] = len;
        memcpy(buf + pos, p, len);
        pos += len;
    }
    buf[pos++] = 0;
    
    // Type 65 (HTTPS), Class 1 (IN)
    buf[pos++] = 0; buf[pos++] = 65;
    buf[pos++] = 0; buf[pos++] = 1;
    return pos;
}

// 支持二进制返回的 HTTP GET (二进制安全，用于 DoH)
char* Utils_HttpBytesGet(const char* url, int* out_len) {
    if (!url) return NULL;
    char host[256] = {0}; 
    char path[2048] = {0}; 
    int port = 443;
    
    const char* p = url;
    if (strncmp(p, "https://", 8) == 0) p += 8;
    else if (strncmp(p, "http://", 7) == 0) { p += 7; port = 80; } 
    
    const char* slash = strchr(p, '/');
    int hostLen = slash ? (int)(slash - p) : (int)strlen(p);
    strncpy(host, p, hostLen);
    if (slash) strcpy(path, slash); else strcpy(path, "/");
    
    char* colon = strchr(host, ':');
    if (colon) { *colon = 0; port = atoi(colon + 1); }

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    
    SSL *ssl = SSL_new(ctx);
    struct hostent *he = gethostbyname(host);
    if (!he) { SSL_free(ssl); SSL_CTX_free(ctx); return NULL; }
    
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr; 
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; 
    addr.sin_port = htons(port);
    addr.sin_addr = *((struct in_addr *)he->h_addr);
    
    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        closesocket(s); SSL_free(ssl); SSL_CTX_free(ctx); return NULL;
    }
    
    SSL_set_fd(ssl, (int)s);
    SSL_set_tlsext_host_name(ssl, host);
    
    if (SSL_connect(ssl) != 1) { 
        closesocket(s); SSL_free(ssl); SSL_CTX_free(ctx); return NULL; 
    }
    
    char req[4096];
    snprintf(req, sizeof(req), 
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: Mandala-Client/1.0\r\n"
        "Accept: application/dns-message\r\n"
        "Connection: close\r\n\r\n", 
        path, host);
    
    if (SSL_write(ssl, req, (int)strlen(req)) <= 0) {
        closesocket(s); SSL_free(ssl); SSL_CTX_free(ctx); return NULL; 
    }
    
    int buf_size = 65536; 
    char* resp = (char*)malloc(buf_size); 
    int total = 0;
    
    while(1) {
        int r = SSL_read(ssl, resp + total, 4096);
        if (r <= 0) break;
        total += r;
        if (total + 4096 > buf_size) { 
            buf_size *= 2; 
            char* new_buf = (char*)realloc(resp, buf_size);
            if (!new_buf) { free(resp); resp = NULL; break; }
            resp = new_buf;
        }
    }
    
    if (!resp) { closesocket(s); SSL_free(ssl); SSL_CTX_free(ctx); return NULL; }

    int body_start_idx = -1;
    for(int i=0; i<total-3; i++) {
        if (resp[i]=='\r' && resp[i+1]=='\n' && resp[i+2]=='\r' && resp[i+3]=='\n') {
            body_start_idx = i + 4; 
            break;
        }
    }
    
    char* result = NULL;
    if (body_start_idx != -1 && body_start_idx < total) {
        *out_len = total - body_start_idx;
        result = (char*)malloc(*out_len);
        memcpy(result, resp + body_start_idx, *out_len);
    } else {
        *out_len = 0;
    }
    
    free(resp); 
    SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); 
    closesocket(s);
    return result;
}

char* FetchECHFromDoH(const char* dohUrl, const char* sni) {
    if (!dohUrl || !sni) return NULL;
    log_msg("[ECH] Querying DoH for: %s", sni);
    
    unsigned char query[512];
    int qlen = BuildDNSQueryHTTPS(sni, query);
    
    char b64query[1024];
    Base64UrlEncode(query, qlen, b64query);
    
    char fullUrl[2048];
    snprintf(fullUrl, sizeof(fullUrl), "%s?dns=%s", dohUrl, b64query);
    
    int resp_len = 0;
    unsigned char* resp = (unsigned char*)Utils_HttpBytesGet(fullUrl, &resp_len);
    
    if (!resp || resp_len < 12) { 
        log_msg("[ECH] DoH request failed (len=%d)", resp_len); 
        if(resp) free(resp); 
        return NULL; 
    }
    
    int pos = 12; // Header
    while (pos < resp_len && resp[pos] != 0) pos += resp[pos] + 1; 
    pos += 5; // Null byte + QTYPE + QCLASS
    
    if (pos >= resp_len) { free(resp); return NULL; }
    
    int ancount = (resp[6] << 8) | resp[7];
    
    for (int i=0; i<ancount; i++) {
        if (pos >= resp_len) break;
        
        // [Fix] 更健壮的名称跳过逻辑 (处理混合压缩)
        while (pos < resp_len) {
            if (resp[pos] == 0) { pos++; break; } // End of labels
            if ((resp[pos] & 0xC0) == 0xC0) { pos += 2; break; } // Pointer
            pos += resp[pos] + 1; // Skip label
        }
        
        if (pos + 10 > resp_len) break;
        
        int type = (resp[pos] << 8) | resp[pos+1];
        int rdlen = (resp[pos+8] << 8) | resp[pos+9];
        pos += 10;
        
        if (pos + rdlen > resp_len) break;
        
        if (type == 65) { // HTTPS
            unsigned char* rdata = resp + pos;
            int rpos = 2; // 跳过 Priority
            
            // [Fix] 正确解析 TargetName，跳过结束符 0
            while(rpos < rdlen && rdata[rpos] != 0) {
                 int label_len = rdata[rpos];
                 if (rpos + label_len + 1 > rdlen) break; // 防止越界
                 rpos += label_len + 1;
            }
            if (rpos < rdlen) rpos++; // 跳过最后的 0 (Root terminator)

            while (rpos + 4 <= rdlen) {
                int key = (rdata[rpos] << 8) | rdata[rpos+1];
                int vlen = (rdata[rpos+2] << 8) | rdata[rpos+3];
                rpos += 4;
                if (key == 5) { // ECH Config
                    if (rpos + vlen > rdlen) break; // 防止越界
                    int b64len = (vlen * 4 / 3) + 8;
                    char* out = (char*)malloc(b64len);
                    Base64Encode(rdata + rpos, vlen, out); 
                    free(resp);
                    return out;
                }
                rpos += vlen;
            }
        }
        pos += rdlen;
    }
    free(resp);
    return NULL;
}

// --- 系统代理设置 (保持原样) ---
BOOL IsWindows8OrGreater() {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32 == NULL) return FALSE;
    FARPROC pFunc = GetProcAddress(hKernel32, "SetProcessMitigationPolicy");
    return (pFunc != NULL);
}

void SetSystemProxy(BOOL enable) {
    if (enable && g_localPort <= 0) return;
    wchar_t proxyServerString[256] = {0};
    wchar_t proxyBypassString[64] = {0};
    if (enable) {
        _snwprintf(proxyServerString, 256, L"127.0.0.1:%d", g_localPort);
        wcsncpy(proxyBypassString, L"<local>", 63);
    }
    if (IsWindows8OrGreater()) {
        HKEY hKey;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, REG_PATH_PROXY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            if (enable) {
                DWORD dwEnable = 1;
                RegSetValueExW(hKey, L"ProxyEnable", 0, REG_DWORD, (const BYTE*)&dwEnable, sizeof(dwEnable));
                RegSetValueExW(hKey, L"ProxyOverride", 0, REG_SZ, (const BYTE*)proxyBypassString, (wcslen(proxyBypassString) + 1) * sizeof(wchar_t));
                RegSetValueExW(hKey, L"ProxyServer", 0, REG_SZ, (const BYTE*)proxyServerString, (wcslen(proxyServerString) + 1) * sizeof(wchar_t));
                RegDeleteValueW(hKey, L"SocksProxyServer"); 
                RegDeleteValueW(hKey, L"AutoConfigURL"); 
            } else {
                DWORD dwEnable = 0;
                RegSetValueExW(hKey, L"ProxyEnable", 0, REG_DWORD, (const BYTE*)&dwEnable, sizeof(dwEnable));
                RegSetValueExW(hKey, L"ProxyServer", 0, REG_SZ, (const BYTE*)L"", sizeof(wchar_t));
                RegDeleteValueW(hKey, L"SocksProxyServer");
            }
            RegCloseKey(hKey);
        }
    } else {
        INTERNET_PER_CONN_OPTION_LISTW list;
        INTERNET_PER_CONN_OPTIONW options[3];
        DWORD dwBufSize = sizeof(list);
        options[0].dwOption = INTERNET_PER_CONN_FLAGS;
        options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
        options[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
        if (enable) {
            options[0].Value.dwValue = PROXY_TYPE_PROXY;
            options[1].Value.pszValue = proxyServerString;
            options[2].Value.pszValue = proxyBypassString;
        } else {
            options[0].Value.dwValue = PROXY_TYPE_DIRECT;
            options[1].Value.pszValue = L"";
            options[2].Value.pszValue = L"";
        }
        list.dwSize = sizeof(list);
        list.pszConnection = NULL;
        list.dwOptionCount = 3;
        list.dwOptionError = 0;
        list.pOptions = options;
        InternetSetOptionW(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, dwBufSize);
    }
    InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
    InternetSetOptionW(NULL, INTERNET_OPTION_REFRESH, NULL, 0);
}

BOOL IsSystemProxyEnabled() {
    HKEY hKey;
    DWORD dwEnable = 0;
    DWORD dwSize = sizeof(dwEnable);
    wchar_t proxyServer[1024] = {0};
    DWORD dwProxySize = sizeof(proxyServer);
    if (RegOpenKeyExW(HKEY_CURRENT_USER, REG_PATH_PROXY, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, L"ProxyEnable", NULL, NULL, (LPBYTE)&dwEnable, &dwSize) == ERROR_SUCCESS) {
            if (dwEnable == 1) {
                if (RegQueryValueExW(hKey, L"ProxyServer", NULL, NULL, (LPBYTE)proxyServer, &dwProxySize) == ERROR_SUCCESS) {
                    wchar_t expectedPart[64];
                    _snwprintf(expectedPart, 64, L"127.0.0.1:%d", g_localPort);
                    if (wcsstr(proxyServer, expectedPart) != NULL) return TRUE;
                }
            }
        }
        RegCloseKey(hKey);
    }
    return FALSE;
}

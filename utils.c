#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "crypto.h" 

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

extern int g_localPort; 
extern BOOL g_enableLog; 

// --- 日志与错误处理 ---

void log_msg(const char *format, ...) {
    if (!g_enableLog) return;
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    time_t now; time(&now);
    struct tm t; localtime_s(&t, &now);
    wchar_t wMsg[2048];
    swprintf_s(wMsg, 2048, L"[%02d:%02d:%02d] %S\r\n", t.tm_hour, t.tm_min, t.tm_sec, buffer);

    HWND hLogWnd = FindWindowW(L"LogWnd", NULL);
    if (hLogWnd) {
        HWND hEdit = GetDlgItem(hLogWnd, 2001); // ID_LOGVIEWER_EDIT
        if (hEdit) {
            wchar_t* p = _wcsdup(wMsg);
            PostMessage(hLogWnd, WM_LOG_UPDATE, 0, (LPARAM)p);
        }
    }
}

void log_wsa_error(const char* context) {
    if (!g_enableLog) return;
    int err = WSAGetLastError();
    log_msg("%s failed with error: %d", context, err);
}

// --- 文件操作 ---

BOOL ReadFileToBuffer(const wchar_t* filename, char** buffer, long* fileSize) {
    FILE* f = NULL;
    if (_wfopen_s(&f, filename, L"rb") != 0 || !f) return FALSE;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    *buffer = (char*)malloc(size + 1);
    if (!*buffer) { fclose(f); return FALSE; }
    fread(*buffer, 1, size, f);
    (*buffer)[size] = 0;
    if (fileSize) *fileSize = size;
    fclose(f);
    return TRUE;
}

BOOL WriteBufferToFile(const wchar_t* filename, const char* buffer) {
    FILE* f = NULL;
    if (_wfopen_s(&f, filename, L"wb") != 0 || !f) return FALSE;
    fwrite(buffer, 1, strlen(buffer), f);
    fclose(f);
    return TRUE;
}

// --- 字符串处理 ---

void TrimString(char* str) {
    char* p = str;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (p != str) memmove(str, p, strlen(p) + 1);
    p = str + strlen(str) - 1;
    while (p >= str && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) *p-- = 0;
}

void UrlDecode(char* dst, const char* src) {
    char a, b;
    while (*src) {
        if ((*src == '%') &&
            ((a = src[1]) && (b = src[2])) &&
            (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a') a -= 'a' - 'A';
            if (a >= 'A') a -= ('A' - 10);
            else a -= '0';
            if (b >= 'a') b -= 'a' - 'A';
            if (b >= 'A') b -= ('A' - 10);
            else b -= '0';
            *dst++ = 16 * a + b;
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst++ = '\0';
}

char* GetQueryParam(const char* query, const char* key) {
    if (!query || !key) return NULL;
    char keyEq[128]; snprintf(keyEq, 128, "%s=", key);
    const char* p = strstr(query, keyEq);
    if (!p) return NULL;
    if (p != query && *(p-1) != '&' && *(p-1) != '?') {
        p = strstr(p+1, keyEq);
        if(!p) return NULL;
    }
    p += strlen(keyEq);
    const char* end = strchr(p, '&');
    int len = end ? (int)(end - p) : (int)strlen(p);
    char* val = (char*)malloc(len + 1);
    char* encoded = (char*)malloc(len + 1);
    strncpy(encoded, p, len); encoded[len] = 0;
    UrlDecode(val, encoded);
    free(encoded);
    return val;
}

static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

unsigned char* Base64Decode(const char* src, size_t* out_len) {
    size_t len = strlen(src);
    if (len % 4 != 0) { 
        int pad = 4 - (len % 4);
        char* padded = (char*)malloc(len + pad + 1);
        strcpy(padded, src);
        for(int k=0; k<pad; k++) strcat(padded, "=");
        unsigned char* ret = Base64Decode(padded, out_len);
        free(padded);
        return ret;
    }

    size_t dlen = len / 4 * 3;
    if (src[len - 1] == '=') (dlen)--;
    if (src[len - 2] == '=') (dlen)--;

    unsigned char* out = (unsigned char*)malloc(dlen + 1);
    if (!out) return NULL;

    int inv[256];
    memset(inv, -1, sizeof(inv));
    for (int i = 0; i < 64; i++) inv[base64_table[i]] = i;

    for (size_t i = 0, j = 0; i < len; i += 4, j += 3) {
        int v = (inv[src[i]] << 18) | (inv[src[i + 1]] << 12) | (inv[src[i + 2]] << 6) | inv[src[i + 3]];
        out[j] = (v >> 16) & 0xFF;
        if (src[i + 2] != '=') out[j + 1] = (v >> 8) & 0xFF;
        if (src[i + 3] != '=') out[j + 2] = v & 0xFF;
    }
    out[dlen] = 0;
    if (out_len) *out_len = dlen;
    return out;
}

char* GetClipboardText() {
    if (!OpenClipboard(NULL)) return NULL;
    HANDLE hData = GetClipboardData(CF_TEXT);
    if (!hData) { CloseClipboard(); return NULL; }
    char* pszText = (char*)GlobalLock(hData);
    if (!pszText) { CloseClipboard(); return NULL; }
    char* text = strdup(pszText);
    GlobalUnlock(hData);
    CloseClipboard();
    return text;
}

// 简单的 HTTP GET (文本版，复用二进制版)
char* Utils_HttpGet(const char* url) {
    int len = 0;
    char* data = Utils_HttpBytesGet(url, &len);
    if (data) {
        char* str = (char*)realloc(data, len + 1);
        str[len] = 0;
        return str;
    }
    return NULL;
}

// --- ECH 相关功能实现 ---

// 标准 Base64 编码 (用于 ECH 导出)
void Base64Encode(const unsigned char* src, int len, char* dst) {
    int i = 0, j = 0;
    for (; i < len; i += 3) {
        int val = (src[i] << 16) + (i + 1 < len ? src[i+1] << 8 : 0) + (i + 2 < len ? src[i+2] : 0);
        dst[j++] = base64_table[(val >> 18) & 0x3F];
        dst[j++] = base64_table[(val >> 12) & 0x3F];
        if (i + 1 < len) dst[j++] = base64_table[(val >> 6) & 0x3F];
        else dst[j++] = '=';
        if (i + 2 < len) dst[j++] = base64_table[val & 0x3F];
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
        int len = dot - p;
        buf[pos++] = len;
        memcpy(buf + pos, p, len);
        pos += len;
        p = dot + 1;
    }
    if (*p) {
        int len = strlen(p);
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

// 支持二进制返回的 HTTP GET (OpenSSL 实现)
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
    
    if (SSL_write(ssl, req, strlen(req)) <= 0) {
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
            resp = (char*)realloc(resp, buf_size); 
        }
    }
    
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
        if ((resp[pos] & 0xC0) == 0xC0) pos += 2; 
        else while(pos < resp_len && resp[pos]!=0) pos += resp[pos]+1; 
        if (pos < resp_len && resp[pos] == 0) pos++;
        
        if (pos + 10 > resp_len) break;
        
        int type = (resp[pos] << 8) | resp[pos+1];
        int rdlen = (resp[pos+8] << 8) | resp[pos+9];
        pos += 10;
        
        if (pos + rdlen > resp_len) break;
        
        if (type == 65) { // HTTPS
            unsigned char* rdata = resp + pos;
            int rpos = 2; 
            if (rpos < rdlen && rdata[rpos] == 0) rpos++; 
            else while(rpos < rdlen && rdata[rpos]!=0) rpos += rdata[rpos]+1;
            
            while (rpos + 4 <= rdlen) {
                int key = (rdata[rpos] << 8) | rdata[rpos+1];
                int vlen = (rdata[rpos+2] << 8) | rdata[rpos+3];
                rpos += 4;
                if (key == 5) { // ECH Config
                    int b64len = (vlen * 4 / 3) + 8;
                    char* out = (char*)malloc(b64len);
                    Base64Encode(rdata + rpos, vlen, out); // 使用标准 Base64 编码
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

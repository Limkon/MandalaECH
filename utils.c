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

#define REG_PATH_PROXY L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"

extern int g_localPort; 
extern BOOL g_enableLog; 

// --------------------------------------------------------------------------
// 日志函数
// --------------------------------------------------------------------------
void log_msg(const char *format, ...) {
    if (!g_enableLog && strstr(format, "[Fatal]") == NULL) return;
    char buf[2048]; char time_buf[64]; SYSTEMTIME st; GetLocalTime(&st);
    snprintf(time_buf, sizeof(time_buf), "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
    va_list args; va_start(args, format); vsnprintf(buf, sizeof(buf)-64, format, args); va_end(args);
    char final_msg[2200]; snprintf(final_msg, sizeof(final_msg), "%s%s\r\n", time_buf, buf);
    OutputDebugStringA(final_msg);
    HWND h = FindWindowW(L"LogWnd", NULL);
    if (h && IsWindow(h)) {
        int wLen = MultiByteToWideChar(CP_UTF8, 0, final_msg, -1, NULL, 0);
        wchar_t* wBuf = (wchar_t*)malloc((wLen + 1) * sizeof(wchar_t));
        if (wBuf) { MultiByteToWideChar(CP_UTF8, 0, final_msg, -1, wBuf, wLen); wBuf[wLen] = 0; PostMessageW(h, WM_LOG_UPDATE, 0, (LPARAM)wBuf); }
    }
}

void log_wsa_error(const char* context) { log_msg("[Error] %s Failed. Code: %d", context, WSAGetLastError()); }

// --------------------------------------------------------------------------
// 文件操作
// --------------------------------------------------------------------------
BOOL ReadFileToBuffer(const wchar_t* filename, char** buffer, long* fileSize) {
    FILE* f = _wfopen(filename, L"rb"); if (!f) { *fileSize = 0; return FALSE; }
    fseek(f, 0, SEEK_END); *fileSize = ftell(f); fseek(f, 0, SEEK_SET);
    *buffer = (char*)malloc(*fileSize + 1);
    if (*buffer) { fread(*buffer, 1, *fileSize, f); (*buffer)[*fileSize] = 0; }
    fclose(f); return (*buffer != NULL);
}

BOOL WriteBufferToFile(const wchar_t* filename, const char* buffer) {
    FILE* f = _wfopen(filename, L"wb"); if (!f) return FALSE;
    fwrite(buffer, 1, strlen(buffer), f); fclose(f); return TRUE;
}

// --------------------------------------------------------------------------
// 字符串/剪贴板
// --------------------------------------------------------------------------
void TrimString(char* str) {
    if (!str) return; char* p = str; while (isspace((unsigned char)*p)) p++;
    if (p != str) memmove(str, p, strlen(p) + 1);
    size_t len = strlen(str); while (len > 0 && isspace((unsigned char)str[len - 1])) str[--len] = 0;
}

void UrlDecode(char* dst, const char* src) {
    char a, b; while (*src) {
        if ((*src == '%') && ((a = src[1]) && (b = src[2])) && (isxdigit(a) && isxdigit(b))) {
            a = (a >= 'a') ? a - 'a' + 10 : (a >= 'A' ? a - 'A' + 10 : a - '0');
            b = (b >= 'a') ? b - 'a' + 10 : (b >= 'A' ? b - 'A' + 10 : b - '0');
            *dst++ = 16 * a + b; src += 3;
        } else if (*src == '+') { *dst++ = ' '; src++; } else { *dst++ = *src++; }
    } *dst = '\0';
}

char* GetQueryParam(const char* query, const char* key) {
    if (!query || !key) return NULL; char keyEq[128]; snprintf(keyEq, sizeof(keyEq), "%s=", key);
    size_t keyEqLen = strlen(keyEq); const char* p = query;
    while ((p = strstr(p, keyEq)) != NULL) {
        if (p == query || *(p - 1) == '&' || *(p - 1) == '?') {
            const char* start = p + keyEqLen; size_t len = 0;
            while (start[len] && start[len] != '&' && start[len] != '#') len++;
            if (len == 0) return NULL;
            char* val = (char*)malloc(len + 1); strncpy(val, start, len); val[len] = 0;
            char* dec = (char*)malloc(len + 1); UrlDecode(dec, val); free(val); return dec;
        } p++;
    } return NULL;
}

char* GetClipboardText() {
    if (!OpenClipboard(NULL)) return NULL;
    HANDLE hData = GetClipboardData(CF_UNICODETEXT);
    if (hData) {
        wchar_t* pszTextW = (wchar_t*)GlobalLock(hData);
        if (pszTextW) {
            int len = WideCharToMultiByte(CP_UTF8, 0, pszTextW, -1, NULL, 0, NULL, NULL);
            char* text = (char*)malloc(len + 1);
            WideCharToMultiByte(CP_UTF8, 0, pszTextW, -1, text, len, NULL, NULL);
            text[len] = 0; TrimString(text); GlobalUnlock(hData); CloseClipboard(); return text;
        }
    }
    hData = GetClipboardData(CF_TEXT);
    if (hData) {
        char* pszText = (char*)GlobalLock(hData);
        if (pszText) { char* text = _strdup(pszText); TrimString(text); GlobalUnlock(hData); CloseClipboard(); return text; }
    }
    CloseClipboard(); return NULL;
}

// --------------------------------------------------------------------------
// Base64
// --------------------------------------------------------------------------
static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static int GetBase64Val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A'; if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52; if (c == '+' || c == '-') return 62; if (c == '/' || c == '_') return 63; return -1;
}

unsigned char* Base64Decode(const char* src, size_t* out_len) {
    if (!src) return NULL; size_t len = strlen(src);
    while (len > 0 && strchr("\r\n =", src[len - 1])) len--;
    if (len == 0) { *out_len = 0; return NULL; }
    *out_len = (len * 3) / 4; unsigned char* out = (unsigned char*)malloc(*out_len + 4); if (!out) return NULL;
    size_t i = 0, j = 0;
    while (i < len) {
        if (strchr("\r\n ", src[i])) { i++; continue; }
        int vals[4], cnt = 0;
        while (i < len && cnt < 4) {
            char c = src[i]; if (strchr("\r\n ", c)) { i++; continue; } if (c == '=') { i++; break; }
            int v = GetBase64Val(c); if (v == -1) { free(out); return NULL; } vals[cnt++] = v; i++;
        }
        if (cnt > 0) {
            uint32_t t = (vals[0] << 18) | ((cnt > 1 ? vals[1] : 0) << 12) | ((cnt > 2 ? vals[2] : 0) << 6) | ((cnt > 3 ? vals[3] : 0));
            if (j < *out_len) out[j++] = (t >> 16) & 0xFF; if (cnt > 2 && j < *out_len) out[j++] = (t >> 8) & 0xFF; if (cnt > 3 && j < *out_len) out[j++] = t & 0xFF;
        }
    } out[j] = 0; *out_len = j; return out;
}

void Base64Encode(const unsigned char* src, int len, char* dst) {
    int i = 0, j = 0;
    for (; i < len; i += 3) {
        int v = (src[i] << 16) + (i + 1 < len ? src[i+1] << 8 : 0) + (i + 2 < len ? src[i+2] : 0);
        dst[j++] = base64_chars[(v >> 18) & 0x3F]; dst[j++] = base64_chars[(v >> 12) & 0x3F];
        dst[j++] = (i + 1 < len) ? base64_chars[(v >> 6) & 0x3F] : '='; dst[j++] = (i + 2 < len) ? base64_chars[v & 0x3F] : '=';
    } dst[j] = 0;
}

void Base64UrlEncode(const unsigned char* src, int len, char* dst) {
    const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    int i = 0, j = 0;
    for (; i < len; i += 3) {
        int v = (src[i] << 16) + (i + 1 < len ? src[i+1] << 8 : 0) + (i + 2 < len ? src[i+2] : 0);
        dst[j++] = tbl[(v >> 18) & 0x3F]; dst[j++] = tbl[(v >> 12) & 0x3F];
        dst[j++] = (i + 1 < len) ? tbl[(v >> 6) & 0x3F] : '='; dst[j++] = (i + 2 < len) ? tbl[v & 0x3F] : '=';
    } while (j > 0 && dst[j - 1] == '=') j--; dst[j] = 0;
}

// --------------------------------------------------------------------------
// HTTP Helper & Chunked Decoder
// --------------------------------------------------------------------------
typedef struct { char host[256]; char path[2048]; int port; } URL_COMP;

static BOOL ParseUrl(const char* url, URL_COMP* out) {
    memset(out, 0, sizeof(URL_COMP)); const char* p = url;
    if (!strncmp(p, "https://", 8)) { out->port = 443; p += 8; } else if (!strncmp(p, "http://", 7)) { out->port = 80; p += 7; } else return FALSE;
    const char* sl = strchr(p, '/'); int hLen = sl ? (int)(sl - p) : (int)strlen(p); if (hLen >= 256) return FALSE;
    strncpy(out->host, p, hLen); char* col = strchr(out->host, ':'); if (col) { *col = 0; out->port = atoi(col + 1); }
    if (sl) strcpy(out->path, sl); else strcpy(out->path, "/"); return TRUE;
}

// [智能功能] Chunked 数据解码器
// 解析 HTTP 分块传输编码，还原原始数据
static char* DechunkBody(const char* raw_body, int raw_len, int* out_len) {
    if (!raw_body || raw_len <= 0) return NULL;
    char* new_buf = (char*)malloc(raw_len + 1); 
    if (!new_buf) return NULL;
    
    int write_pos = 0;
    const char* p = raw_body;
    const char* end = raw_body + raw_len;
    
    while (p < end) {
        // 读取块大小 (Hex)
        char hex_str[16] = {0};
        const char* eol = strstr(p, "\r\n");
        if (!eol) break; 
        
        int hex_len = (int)(eol - p);
        if (hex_len > 15) hex_len = 15;
        strncpy(hex_str, p, hex_len);
        
        long chunk_size = strtol(hex_str, NULL, 16);
        p = eol + 2; // 跳过 CRLF
        
        if (chunk_size == 0) break; // 结束块
        if (p + chunk_size > end) break; // 数据不完整
        
        memcpy(new_buf + write_pos, p, chunk_size);
        write_pos += chunk_size;
        p += chunk_size + 2; // 跳过数据后的 CRLF
    }
    
    new_buf[write_pos] = 0;
    *out_len = write_pos;
    log_msg("[Utils] De-chunked data: %d bytes -> %d bytes", raw_len, write_pos);
    return new_buf;
}

static char* InternalHttpsGet(const char* url, BOOL useProxy, int* out_len) {
    URL_COMP u; if (!ParseUrl(url, &u)) { log_msg("[Utils] Invalid URL: %s", url); return NULL; }
    if (out_len) *out_len = 0;
    static int ini = 0; if (!ini) { SSL_library_init(); OpenSSL_add_all_algorithms(); SSL_load_error_strings(); ini = 1; }

    const char* tHost = useProxy ? "127.0.0.1" : u.host; int tPort = useProxy ? g_localPort : u.port;
    struct hostent *he = gethostbyname(tHost); if (!he) return NULL;

    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a,0,sizeof(a)); a.sin_family=AF_INET; a.sin_port=htons(tPort); a.sin_addr=*((struct in_addr*)he->h_addr);
    if (connect(s, (struct sockaddr*)&a, sizeof(a))) { closesocket(s); return NULL; }

    if (useProxy) {
        char req[512], buf[1024]; snprintf(req, 512, "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", u.host, u.port, u.host, u.port);
        send(s, req, strlen(req), 0); if (recv(s, buf, 1023, 0) <= 0 || !strstr(buf, "200 Connection")) { closesocket(s); return NULL; }
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method()); SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL *ssl = SSL_new(ctx); SSL_set_fd(ssl, (int)s); SSL_set_tlsext_host_name(ssl, u.host);
    if (SSL_connect(ssl) != 1) { SSL_free(ssl); SSL_CTX_free(ctx); closesocket(s); return NULL; }

    // [智能] 使用 HTTP/1.1
    char req[4096]; const char* acc = out_len ? "application/dns-message" : "*/*";
    snprintf(req, 4096, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mandala/1.0\r\nAccept: %s\r\nConnection: close\r\n\r\n", u.path, u.host, acc);
    SSL_write(ssl, req, strlen(req));

    int bSize = 65536, tRead = 0; char* resp = (char*)malloc(bSize);
    while (1) {
        if (tRead + 4096 >= bSize) { bSize *= 2; resp = realloc(resp, bSize); }
        int r = SSL_read(ssl, resp + tRead, 4096); if (r <= 0) break; tRead += r;
    }
    resp[tRead] = 0;

    if (!strstr(resp, " 200 OK")) { 
        log_msg("[Utils] HTTP request failed. Response: %.50s", resp);
        free(resp); SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); closesocket(s); return NULL; 
    }

    // 检查是否 Chunked (不区分大小写简单检查)
    BOOL isChunked = (strstr(resp, "Transfer-Encoding: chunked") != NULL) || (strstr(resp, "transfer-encoding: chunked") != NULL);

    char* body = strstr(resp, "\r\n\r\n"); if (!body) body = strstr(resp, "\n\n");
    char* final_res = NULL;

    if (body) {
        body += (body[0] == '\r' ? 4 : 2); 
        int raw_len = tRead - (int)(body - resp);
        
        if (raw_len > 0) {
            if (isChunked) {
                // [智能] 解码 Chunked 数据
                int dechunked_len = 0;
                final_res = DechunkBody(body, raw_len, &dechunked_len);
                if (out_len) *out_len = dechunked_len;
            } else {
                // 普通模式
                final_res = (char*)malloc(raw_len + 1); 
                memcpy(final_res, body, raw_len); 
                final_res[raw_len] = 0; 
                if (out_len) *out_len = raw_len;
            }
        }
    }
    
    free(resp); SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); closesocket(s); 
    return final_res;
}

char* Utils_HttpGet(const char* url) { if (g_localPort > 0) { char* r = InternalHttpsGet(url, TRUE, NULL); if (r) return r; } return InternalHttpsGet(url, FALSE, NULL); }
char* Utils_HttpBytesGet(const char* url, int* out_len) { return InternalHttpsGet(url, FALSE, out_len); }

// --- ECH DoH ---
int BuildDNSQueryHTTPS(const char* domain, unsigned char* buf) {
    int p = 0; buf[p++] = 0; buf[p++] = 1; buf[p++] = 1; buf[p++] = 0; buf[p++] = 0; buf[p++] = 1; 
    buf[p++] = 0; buf[p++] = 0; buf[p++] = 0; buf[p++] = 0; buf[p++] = 0; buf[p++] = 0; 
    const char* ptr = domain; const char* dot;
    while ((dot = strchr(ptr, '.'))) { int l = (int)(dot - ptr); buf[p++] = l; memcpy(buf+p, ptr, l); p += l; ptr = dot + 1; }
    if (*ptr) { int l = strlen(ptr); buf[p++] = l; memcpy(buf+p, ptr, l); p += l; }
    buf[p++] = 0; buf[p++] = 0; buf[p++] = 65; buf[p++] = 0; buf[p++] = 1; return p;
}

char* FetchECHFromDoH(const char* dohUrl, const char* sni) {
    if (!dohUrl || !sni) return NULL;
    log_msg("[ECH] Querying DoH for: %s", sni);
    unsigned char q[512]; int ql = BuildDNSQueryHTTPS(sni, q);
    char b64[1024]; Base64UrlEncode(q, ql, b64);
    char url[2048]; snprintf(url, 2048, "%s?dns=%s", dohUrl, b64);

    int rLen = 0; unsigned char* resp = (unsigned char*)Utils_HttpBytesGet(url, &rLen);
    if (!resp || rLen < 12) { if (resp) free(resp); return NULL; }

    int p = 12; while (p < rLen && resp[p] != 0) p += resp[p] + 1; p += 5; if (p >= rLen) { free(resp); return NULL; }
    int anC = (resp[6] << 8) | resp[7];
    for (int i = 0; i < anC; i++) {
        if (p >= rLen) break;
        if ((resp[p] & 0xC0) == 0xC0) p += 2; else { while (p < rLen && resp[p] != 0) p += resp[p] + 1; p++; }
        if (p + 10 > rLen) break;
        int type = (resp[p] << 8) | resp[p+1]; int rdLen = (resp[p+8] << 8) | resp[p+9]; p += 10;
        if (p + rdLen > rLen) break;
        if (type == 65) {
            unsigned char* rdata = resp + p; int rp = 2; 
            if (rp < rdLen && rdata[rp] == 0) rp++; else while (rp < rdLen && rdata[rp] != 0) rp += rdata[rp] + 1; rp++; 
            while (rp + 4 <= rdLen) {
                int k = (rdata[rp] << 8) | rdata[rp+1]; int vl = (rdata[rp+2] << 8) | rdata[rp+3]; rp += 4;
                if (rp + vl > rdLen) break;
                if (k == 5) {
                    if (vl >= 2) log_msg("[ECH] Config Found. Version ID: %02X%02X", rdata[rp], rdata[rp+1]);
                    char* out = (char*)malloc(vl * 2); Base64Encode(rdata + rp, vl, out); free(resp); return out;
                } rp += vl;
            }
        } p += rdLen;
    } free(resp); return NULL;
}

// --- System Proxy ---
BOOL IsWindows8OrGreater() { return GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SetProcessMitigationPolicy") != NULL; }
void SetSystemProxy(BOOL enable) {
    if (enable && g_localPort <= 0) return;
    wchar_t server[64], bypass[] = L"<local>"; _snwprintf(server, 64, L"127.0.0.1:%d", g_localPort);
    if (IsWindows8OrGreater()) {
        HKEY k; if (RegCreateKeyExW(HKEY_CURRENT_USER, REG_PATH_PROXY, 0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL) == 0) {
            DWORD en = enable ? 1 : 0; RegSetValueExW(k, L"ProxyEnable", 0, REG_DWORD, (BYTE*)&en, 4);
            if (enable) { RegSetValueExW(k, L"ProxyServer", 0, REG_SZ, (BYTE*)server, (wcslen(server)+1)*2); RegSetValueExW(k, L"ProxyOverride", 0, REG_SZ, (BYTE*)bypass, (wcslen(bypass)+1)*2); }
            RegCloseKey(k);
        }
    } else {
        INTERNET_PER_CONN_OPTIONW opts[3]; opts[0].dwOption = INTERNET_PER_CONN_FLAGS; opts[0].Value.dwValue = enable ? PROXY_TYPE_PROXY : PROXY_TYPE_DIRECT;
        opts[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER; opts[1].Value.pszValue = server;
        opts[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS; opts[2].Value.pszValue = bypass;
        INTERNET_PER_CONN_OPTION_LISTW list = {sizeof(list), NULL, 3, 0, opts}; InternetSetOptionW(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, sizeof(list));
    } InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0); InternetSetOptionW(NULL, INTERNET_OPTION_REFRESH, NULL, 0);
}
BOOL IsSystemProxyEnabled() { HKEY k; DWORD en = 0, sz = 4; if (RegOpenKeyExW(HKEY_CURRENT_USER, REG_PATH_PROXY, 0, KEY_READ, &k) == 0) { RegQueryValueExW(k, L"ProxyEnable", NULL, NULL, (BYTE*)&en, &sz); RegCloseKey(k); } return en == 1; }

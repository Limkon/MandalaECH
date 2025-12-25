#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wininet.h>
#include <ctype.h> 
#include <stdarg.h> 

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "crypto.h"
#include "common.h"
#include "gui.h" 
#include "cJSON.h" 

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wininet.lib")

static CRITICAL_SECTION g_logLock;
static int g_logLockInit = 0;

BOOL IsWindows8OrGreater() {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32 == NULL) return FALSE;
    FARPROC pFunc = GetProcAddress(hKernel32, "SetProcessMitigationPolicy");
    return (pFunc != NULL);
}

void log_msg(const char *format, ...) {
    if (!g_logLockInit) {
        InitializeCriticalSection(&g_logLock);
        g_logLockInit = 1;
    }

    char time_buf[64]; 
    SYSTEMTIME st; 
    GetLocalTime(&st);
    snprintf(time_buf, sizeof(time_buf), "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    
    char buf[4096]; 
    va_list args; 
    va_start(args, format); 
    vsnprintf(buf, sizeof(buf) - 2, format, args); 
    va_end(args);
    buf[sizeof(buf) - 1] = 0; 
    
    char final_msg[4200]; 
    snprintf(final_msg, sizeof(final_msg), "%s%s\n", time_buf, buf); 
    
    OutputDebugStringA(final_msg);
    
    extern HWND hLogViewerWnd; 
    if (hLogViewerWnd && IsWindow(hLogViewerWnd)) {
        char gui_msg[4200];
        snprintf(gui_msg, sizeof(gui_msg), "%s%s\r\n", time_buf, buf);
        int wLen = MultiByteToWideChar(CP_UTF8, 0, gui_msg, -1, NULL, 0);
        if (wLen > 0) {
            wchar_t* wBuf = (wchar_t*)malloc((wLen + 1) * sizeof(wchar_t));
            if (wBuf) {
                MultiByteToWideChar(CP_UTF8, 0, gui_msg, -1, wBuf, wLen);
                wBuf[wLen] = 0;
                PostMessageW(hLogViewerWnd, WM_LOG_UPDATE, 0, (LPARAM)wBuf);
            }
        }
    }

    EnterCriticalSection(&g_logLock);
    FILE* fp = fopen("log.txt", "a+"); 
    if (fp) {
        fprintf(fp, "%s", final_msg);
        fflush(fp); 
        fclose(fp);
    }
    LeaveCriticalSection(&g_logLock);
}

// --- 文件 IO ---
BOOL ReadFileToBuffer(const wchar_t* filename, char** buffer, long* size) {
    log_msg("[FileIO] Reading file: %ls", filename);
    FILE* f = _wfopen(filename, L"rb");
    if (!f) {
        log_msg("[FileIO] Failed to open file: %ls", filename);
        return FALSE;
    }
    
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (fsize < 0) { fclose(f); return FALSE; }

    *buffer = (char*)malloc(fsize + 1);
    if (!*buffer) { 
        log_msg("[Fatal] Memory allocation failed for file buffer!");
        fclose(f); 
        return FALSE; 
    }
    
    size_t read_bytes = fread(*buffer, 1, fsize, f);
    (*buffer)[read_bytes] = 0; 
    
    if (size) *size = (long)read_bytes;
    
    fclose(f);
    log_msg("[FileIO] File read successfully.");
    return TRUE;
}

BOOL WriteBufferToFile(const wchar_t* filename, const char* buffer) {
    log_msg("[FileIO] Writing to file: %ls", filename);
    FILE* f = _wfopen(filename, L"wb");
    if (!f) {
        log_msg("[Err] Failed to open file for writing: %ls", filename);
        return FALSE;
    }
    
    size_t len = strlen(buffer);
    size_t written = fwrite(buffer, 1, len, f);
    
    fclose(f);
    log_msg("[FileIO] Wrote %zu bytes.", written);
    return TRUE;
}

// --- 字符串处理 ---
void TrimString(char* str) {
    if (!str) return;
    char* p = str;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (p > str) memmove(str, p, strlen(p) + 1);
    char* pEnd = str + strlen(str) - 1;
    while (pEnd >= str && (*pEnd == ' ' || *pEnd == '\t' || *pEnd == '\r' || *pEnd == '\n')) *pEnd-- = 0;
}

void UrlDecode(char* dst, const char* src) {
    char a, b;
    while (*src) {
        if ((*src == '%') && ((a = src[1]) && (b = src[2])) && (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a') a -= 'a' - 10; else if (a >= 'A') a -= 'A' - 10; else a -= '0';
            if (b >= 'a') b -= 'a' - 10; else if (b >= 'A') b -= 'A' - 10; else b -= '0';
            *dst++ = 16 * a + b; src += 3;
        } else if (*src == '+') { *dst++ = ' '; src++; } 
        else { *dst++ = *src++; }
    }
    *dst++ = '\0';
}

char* GetQueryParam(const char* query, const char* key) {
    if (!query || !key) return NULL;
    char search[128]; snprintf(search, sizeof(search), "%s=", key);
    const char* p = strstr(query, search);
    if (!p) return NULL;
    if (p != query && *(p-1) != '&' && *(p-1) != '?') return NULL; 
    p += strlen(search);
    const char* end_amp = strchr(p, '&');
    const char* end_hash = strchr(p, '#');
    const char* end = NULL;
    if (end_amp && end_hash) end = (end_amp < end_hash) ? end_amp : end_hash;
    else if (end_amp) end = end_amp;
    else if (end_hash) end = end_hash;
    int len = end ? (int)(end - p) : (int)strlen(p);
    if (len <= 0) return NULL;
    char* val = (char*)malloc(len + 1);
    if (!val) return NULL;
    strncpy(val, p, len); val[len] = 0;
    return val;
}

// --- Base64 ---
static const int b64_table[] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
};

unsigned char* Base64Decode(const char* input, size_t* out_len) {
    if (!input) return NULL;
    size_t len = strlen(input);
    size_t out_size = len / 4 * 3;
    unsigned char* out = (unsigned char*)malloc(out_size + 1);
    if (!out) return NULL;
    
    size_t i = 0, j = 0;
    while (i < len) {
        if (input[i] == '\r' || input[i] == '\n') { i++; continue; } 
        if (input[i] == '=') break; 
        
        unsigned char a = (unsigned char)input[i];
        if (a >= 128 || b64_table[a] == -1) { i++; continue; } 

        if (i+1 >= len) break;
        unsigned char b = (unsigned char)input[i+1];
        if (b >= 128 || b64_table[b] == -1) { i++; continue; }

        uint32_t n = (b64_table[a] << 18) | (b64_table[b] << 12);
        out[j++] = (n >> 16) & 0xFF;
        
        if (i + 2 < len) {
            unsigned char c = (unsigned char)input[i+2];
            if (c < 128 && c != '=' && b64_table[c] != -1) {
                n |= (b64_table[c] << 6);
                out[j++] = (n >> 8) & 0xFF;
                if (i + 3 < len) {
                    unsigned char d = (unsigned char)input[i+3];
                    if (d < 128 && d != '=' && b64_table[d] != -1) {
                        n |= b64_table[d];
                        out[j++] = n & 0xFF;
                    }
                }
            }
        }
        i += 4;
    }
    out[j] = 0;
    if (out_len) *out_len = j;
    return out;
}

// --- URL Parsing ---
typedef struct { 
    char host[256]; 
    int port; 
    char path[1024]; 
} URL_COMPONENTS_SIMPLE;

static BOOL ParseUrl(const char* url, URL_COMPONENTS_SIMPLE* out) {
    if (!url || !out) return FALSE;
    memset(out, 0, sizeof(URL_COMPONENTS_SIMPLE));
    const char* p = url;
    if (strncmp(p, "http://", 7) == 0) { p += 7; out->port = 80; }
    else if (strncmp(p, "https://", 8) == 0) { p += 8; out->port = 443; }
    else return FALSE;
    
    const char* slash = strchr(p, '/');
    int hostLen = slash ? (int)(slash - p) : (int)strlen(p);
    if (hostLen >= sizeof(out->host)) return FALSE;
    strncpy(out->host, p, hostLen); out->host[hostLen] = 0;
    
    char* colon = strchr(out->host, ':');
    if (colon) { *colon = 0; out->port = atoi(colon + 1); }
    
    if (slash) {
        if (strlen(slash) >= sizeof(out->path)) return FALSE;
        strcpy(out->path, slash);
    } else strcpy(out->path, "/");
    return TRUE;
}

// --- [CRITICAL FIX] 安全的 HTTPS GET 请求 ---
static char* InternalHttpsGet(const char* url) {
    log_msg("[HTTP] Fetching URL: %s", url);
    URL_COMPONENTS_SIMPLE u;
    if (!ParseUrl(url, &u)) {
        log_msg("[HTTP] Invalid URL format.");
        return NULL;
    }

    log_msg("[HTTP] Creating SSL Context...");
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        log_msg("[HTTP] SSL_CTX_new failed. Check OpenSSL libs.");
        return NULL;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    SOCKET s = INVALID_SOCKET;
    SSL *ssl = NULL;
    char* result = NULL;
    char* buf = NULL;
    struct addrinfo hints, *res = NULL;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; 
    hints.ai_socktype = SOCK_STREAM;
    char portStr[16]; snprintf(portStr, 16, "%d", u.port);
    
    log_msg("[HTTP] Resolving DNS for %s...", u.host);
    if (getaddrinfo(u.host, portStr, &hints, &res) != 0) {
        log_msg("[HTTP] getaddrinfo failed for %s", u.host);
        SSL_CTX_free(ctx); 
        return NULL;
    }
    
    s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) { 
        log_msg("[HTTP] Socket creation failed.");
        freeaddrinfo(res); 
        SSL_CTX_free(ctx);
        return NULL; 
    }
    
    DWORD timeout = 8000; 
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    log_msg("[HTTP] Connecting to %s:%d...", u.host, u.port);
    if (connect(s, res->ai_addr, (int)res->ai_addrlen) != 0) {
        log_msg("[HTTP] TCP connect failed.");
        closesocket(s); freeaddrinfo(res); 
        SSL_CTX_free(ctx);
        return NULL;
    }
    log_msg("[HTTP] TCP Connected. Freeing addrinfo...");
    freeaddrinfo(res);

    log_msg("[HTTP] Creating SSL structure...");
    ssl = SSL_new(ctx);
    if (!ssl) { 
        log_msg("[HTTP] SSL_new failed.");
        closesocket(s); 
        SSL_CTX_free(ctx);
        return NULL; 
    }
    
    // [CRITICAL] 使用 BIO_new_socket 替代 SSL_set_fd
    // 这种方式在 Windows x64 下更安全，避免了 (int)SOCKET 的截断风险
    log_msg("[HTTP] Setting up SSL BIO...");
    BIO* bio = BIO_new_socket((int)(intptr_t)s, BIO_NOCLOSE);
    if (!bio) {
        log_msg("[HTTP] BIO_new_socket failed.");
        SSL_free(ssl);
        closesocket(s);
        SSL_CTX_free(ctx);
        return NULL;
    }
    SSL_set_bio(ssl, bio, bio);
    
    SSL_set_tlsext_host_name(ssl, u.host);

    log_msg("[HTTP] Performing SSL handshake...");
    if (SSL_connect(ssl) != 1) {
        long err = ERR_get_error();
        log_msg("[HTTP] SSL_connect failed. ERR: %lx (%s)", err, ERR_error_string(err, NULL));
        // 注意：不要在此处 free(bio)，SSL_free 会处理它
        goto cleanup;
    }
    log_msg("[HTTP] SSL Handshake success.");

    char req[2048];
    snprintf(req, sizeof(req), 
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: Mandala-Client/1.0\r\n"
        "Accept: application/dns-json\r\n" 
        "Connection: close\r\n\r\n", 
        u.path, u.host);
        
    log_msg("[HTTP] Sending Request...");
    if (SSL_write(ssl, req, (int)strlen(req)) <= 0) {
        log_msg("[HTTP] Failed to send request header.");
        goto cleanup;
    }

    int total_cap = 65536; 
    int total_len = 0;
    log_msg("[HTTP] Allocating buffer (%d bytes)...", total_cap);
    buf = (char*)malloc(total_cap);
    if (!buf) {
        log_msg("[HTTP] OOM allocating receive buffer.");
        goto cleanup;
    }

    log_msg("[HTTP] Receiving data...");
    while (1) {
        if (total_len >= total_cap - 1024) {
            int new_cap = total_cap * 2;
            log_msg("[HTTP] Expanding buffer to %d...", new_cap);
            char* new_buf = (char*)realloc(buf, new_cap);
            if (!new_buf) { 
                log_msg("[HTTP] OOM reallocating buffer.");
                free(buf); buf = NULL; goto cleanup; 
            }
            buf = new_buf;
            total_cap = new_cap;
        }
        
        int n = SSL_read(ssl, buf + total_len, total_cap - total_len - 1);
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL) break; 
            log_msg("[HTTP] SSL_read error: %d", err);
            break; 
        }
        total_len += n;
    }
    buf[total_len] = 0;

    log_msg("[HTTP] Received %d bytes. Parsing body...", total_len);
    char* body = strstr(buf, "\r\n\r\n");
    if (body) { 
        body += 4; 
        result = _strdup(body); 
        free(buf); buf = NULL; 
    } else { 
        result = buf; 
        buf = NULL; 
    }

cleanup:
    if (buf) free(buf);
    if (ssl) { 
        SSL_shutdown(ssl); 
        SSL_free(ssl); // 这也会释放 BIO
    }
    if (s != INVALID_SOCKET) closesocket(s);
    if (ctx) SSL_CTX_free(ctx); 
    log_msg("[HTTP] Cleanup finished.");
    return result;
}

char* Utils_HttpGet(const char* url) {
    if (!url || strncmp(url, "http", 4) != 0) return NULL;
    return InternalHttpsGet(url);
}

// --- 剪贴板 ---
char* GetClipboardText() {
    if (!OpenClipboard(NULL)) return NULL;
    HANDLE hData = GetClipboardData(CF_TEXT);
    if (!hData) { CloseClipboard(); return NULL; }
    char* pszText = (char*)GlobalLock(hData);
    if (!pszText) { CloseClipboard(); return NULL; }
    char* text = _strdup(pszText);
    GlobalUnlock(hData);
    CloseClipboard();
    log_msg("[Clipboard] Read text (len=%d)", strlen(text));
    return text;
}

// --- 系统代理 ---
void SetSystemProxy(BOOL enable) {
    extern int g_localPort;
    log_msg("[System] SetSystemProxy: %d, Port: %d", enable, g_localPort);
    if (g_localPort <= 0) g_localPort = 1080; 

    wchar_t proxyServerString[256] = {0};
    wchar_t proxyBypassString[64] = L"<local>";
    if (enable) swprintf_s(proxyServerString, 256, L"127.0.0.1:%d", g_localPort);

    if (IsWindows8OrGreater()) {
        HKEY hKey;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, REG_PATH_PROXY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            if (enable) {
                DWORD dwEnable = 1;
                RegSetValueExW(hKey, L"ProxyEnable", 0, REG_DWORD, (const BYTE*)&dwEnable, sizeof(dwEnable));
                RegSetValueExW(hKey, L"ProxyOverride", 0, REG_SZ, (const BYTE*)proxyBypassString, (wcslen(proxyBypassString)+1)*sizeof(wchar_t));
                RegSetValueExW(hKey, L"ProxyServer", 0, REG_SZ, (const BYTE*)proxyServerString, (wcslen(proxyServerString)+1)*sizeof(wchar_t));
            } else {
                DWORD dwEnable = 0;
                RegSetValueExW(hKey, L"ProxyEnable", 0, REG_DWORD, (const BYTE*)&dwEnable, sizeof(dwEnable));
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
        list.dwOptionCount = 3;
        list.dwOptionError = 0;
        list.pOptions = options;
        InternetSetOptionW(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, dwBufSize);
    }
    InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
    InternetSetOptionW(NULL, INTERNET_OPTION_REFRESH, NULL, 0);
}

BOOL IsSystemProxyEnabled() {
    extern int g_localPort;
    BOOL isEnabled = FALSE;
    HKEY hKey;
    DWORD dwEnable = 0;
    DWORD dwSize = sizeof(dwEnable);
    wchar_t proxyServer[1024] = {0};
    DWORD dwProxySize = sizeof(proxyServer);
    
    if (RegOpenKeyExW(HKEY_CURRENT_USER, REG_PATH_PROXY, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, L"ProxyEnable", NULL, NULL, (LPBYTE)&dwEnable, &dwSize) == ERROR_SUCCESS) {
            if (dwEnable == 1) {
                if (RegQueryValueExW(hKey, L"ProxyServer", NULL, NULL, (LPBYTE)proxyServer, &dwProxySize) == ERROR_SUCCESS) {
                    wchar_t expected[64];
                    swprintf_s(expected, 64, L"127.0.0.1:%d", g_localPort);
                    if (wcsstr(proxyServer, expected) != NULL) isEnabled = TRUE;
                }
            }
        }
        RegCloseKey(hKey);
    }
    return isEnabled;
}

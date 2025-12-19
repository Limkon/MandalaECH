#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    // [Fix] 使用 _wfopen 替代 _wfopen_s 以兼容 MinGW
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
        // [Safety] snprintf
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
            closesocket(s);
            return NULL;
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
    // [Safety] snprintf
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

// ... (Proxy settings) ...
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
        // [Fix] 使用 _snwprintf 替代 wsprintfW
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

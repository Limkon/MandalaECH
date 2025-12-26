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

// 引入 BoringSSL/OpenSSL 头文件
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "crypto.h"
#include "common.h"
#include "gui.h" 
#include "cJSON.h" 

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wininet.lib")

// 全局 SSL 上下文与原子锁
static SSL_CTX* g_utils_ctx = NULL;
static volatile LONG g_ctx_init_state = 0; 

// --------------------------------------------------------------------------
// 基础工具函数
// --------------------------------------------------------------------------

BOOL IsWindows8OrGreater() {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32 == NULL) return FALSE;
    FARPROC pFunc = GetProcAddress(hKernel32, "SetProcessMitigationPolicy");
    return (pFunc != NULL);
}

static char* SafeStrDup(const char* s, int len) {
    if (!s || len < 0) return NULL;
    char* d = (char*)malloc(len + 1);
    if (d) {
        memcpy(d, s, len);
        d[len] = 0;
    }
    return d;
}

void log_msg(const char *format, ...) {
    if (!g_enableLog && strstr(format, "[Fatal]") == NULL) return;
    char buf[2048]; char time_buf[64]; SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(time_buf, sizeof(time_buf), "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
    va_list args; va_start(args, format);
    vsnprintf(buf, sizeof(buf) - 64, format, args);
    va_end(args);
    char final_msg[2200];
    snprintf(final_msg, sizeof(final_msg), "%s%s\r\n", time_buf, buf);
    OutputDebugStringA(final_msg);
    extern HWND hLogViewerWnd; 
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

// --------------------------------------------------------------------------
// 文件 IO 操作
// --------------------------------------------------------------------------

BOOL ReadFileToBuffer(const wchar_t* filename, char** buffer, long* size) {
    FILE* f = _wfopen(filename, L"rb");
    if (!f) return FALSE;
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    *buffer = (char*)malloc(fsize + 1);
    if (!*buffer) { fclose(f); return FALSE; }
    fread(*buffer, 1, fsize, f);
    (*buffer)[fsize] = 0;
    if (size) *size = fsize;
    fclose(f);
    return TRUE;
}

BOOL WriteBufferToFile(const wchar_t* filename, const char* buffer) {
    FILE* f = _wfopen(filename, L"wb");
    if (!f) return FALSE;
    size_t len = strlen(buffer);
    fwrite(buffer, 1, len, f);
    fclose(f);
    return TRUE;
}

// --------------------------------------------------------------------------
// 字符串处理工具
// --------------------------------------------------------------------------

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
    const char* end = strpbrk(p, "&#");
    int len = end ? (int)(end - p) : (int)strlen(p);
    if (len <= 0) return NULL;
    char* val = (char*)malloc(len + 1);
    if (val) { strncpy(val, p, len); val[len] = 0; }
    return val;
}

// --------------------------------------------------------------------------
// ECH / Base64 / Hex 核心工具
// --------------------------------------------------------------------------

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
    size_t len = strlen(input);
    size_t out_size = len / 4 * 3;
    unsigned char* out = (unsigned char*)malloc(out_size + 1);
    if (!out) return NULL;
    size_t i = 0, j = 0;
    while (i < len) {
        if (input[i] == '\r' || input[i] == '\n' || input[i] == ' ') { i++; continue; } 
        if (input[i] == '=') break; 
        unsigned char a = (unsigned char)input[i];
        unsigned char b = (unsigned char)input[i+1];
        unsigned char c = (unsigned char)input[i+2];
        unsigned char d = (unsigned char)input[i+3];
        if (i + 1 >= len) break;
        if (a > 127 || b64_table[a] == -1 || b > 127 || b64_table[b] == -1) break;
        uint32_t n = (b64_table[a] << 18) | (b64_table[b] << 12);
        out[j++] = (n >> 16) & 0xFF;
        if (i + 2 < len && c != '=' && c < 128 && b64_table[c] != -1) {
            n |= (b64_table[c] << 6); out[j++] = (n >> 8) & 0xFF;
            if (i + 3 < len && d != '=' && d < 128 && b64_table[d] != -1) {
                n |= b64_table[d]; out[j++] = n & 0xFF;
            }
        }
        i += 4;
    }
    out[j] = 0; if (out_len) *out_len = j;
    return out;
}

static int HexToBin(const char* hex, unsigned char* out, int max_len) {
    int len = 0;
    while (*hex && len < max_len) {
        if (!isxdigit(*hex)) { hex++; continue; }
        int v1 = isdigit(*hex) ? *hex - '0' : tolower(*hex) - 'a' + 10;
        hex++; if (!*hex) break;
        int v2 = isdigit(*hex) ? *hex - '0' : tolower(*hex) - 'a' + 10;
        out[len++] = (v1 << 4) | v2; hex++;
    }
    return len;
}

unsigned char* FetchECHConfig(const char* domain, const char* doh_server, size_t* out_len) {
    if (!domain || !doh_server) return NULL;
    char url[2048]; snprintf(url, sizeof(url), "%s?name=%s&type=65", doh_server, domain);
    char* json_str = Utils_HttpGet(url);
    if (!json_str) return NULL;
    cJSON* root = cJSON_Parse(json_str); free(json_str);
    if (!root) return NULL;
    unsigned char* ech_config = NULL; *out_len = 0;
    cJSON* answer = cJSON_GetObjectItem(root, "Answer");
    if (answer && cJSON_IsArray(answer)) {
        int array_size = cJSON_GetArraySize(answer);
        for (int i = 0; i < array_size; i++) {
            cJSON* record = cJSON_GetArrayItem(answer, i);
            if (!record) continue;
            cJSON* type = cJSON_GetObjectItem(record, "type");
            if (type && type->valueint == 65) { 
                cJSON* data = cJSON_GetObjectItem(record, "data");
                if (data && data->valuestring) {
                    const char* data_str = data->valuestring;
                    const char* ech_pos = strstr(data_str, "ech=\"");
                    if (ech_pos) {
                        ech_pos += 5; const char* end_quote = strchr(ech_pos, '\"');
                        if (end_quote) {
                            size_t b64_len = end_quote - ech_pos;
                            char* b64_str = (char*)malloc(b64_len + 1);
                            if (b64_str) {
                                strncpy(b64_str, ech_pos, b64_len); b64_str[b64_len] = 0;
                                ech_config = Base64Decode(b64_str, out_len); free(b64_str);
                                if (ech_config) break; 
                            }
                        }
                    }
                }
            }
            if (ech_config) break; 
        }
    }
    cJSON_Delete(root); return ech_config;
}

// --------------------------------------------------------------------------
// 双网络引擎实现 (核心全兼容方案)
// --------------------------------------------------------------------------

typedef struct { char host[256]; int port; char path[1024]; } URL_COMPONENTS_SIMPLE;

static BOOL ParseUrl(const char* url, URL_COMPONENTS_SIMPLE* out) {
    if (!url || !out) return FALSE;
    memset(out, 0, sizeof(URL_COMPONENTS_SIMPLE));
    const char* p = url;
    if (strncmp(p, "http://", 7) == 0) { p += 7; out->port = 80; }
    else if (strncmp(p, "https://", 8) == 0) { p += 8; out->port = 443; }
    else return FALSE;
    const char* slash = strchr(p, '/');
    int hostLen = slash ? (int)(slash - p) : (int)strlen(p);
    if (hostLen >= (int)sizeof(out->host)) return FALSE;
    strncpy(out->host, p, hostLen); out->host[hostLen] = 0;
    char* colon = strchr(out->host, ':');
    if (colon) { *colon = 0; out->port = atoi(colon + 1); }
    if (slash) strncpy(out->path, slash, sizeof(out->path)-1); else strcpy(out->path, "/");
    return TRUE;
}

// 引擎 A: WinInet - 针对 Win7 优化，强制开启 TLS 1.2
static char* InternalWinInetGet(const char* url) {
    char* result = NULL;
    HINTERNET hInternet = InternetOpenW(L"Mandala/1.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) return NULL;

    // [核心修复] 强制 Windows 7 开启 TLS 1.1 和 TLS 1.2 支持
    DWORD protocols = 0x00000080 | 0x00000200 | 0x00000800; 
    InternetSetOptionW(hInternet, INTERNET_OPTION_SECURITY_PROTOCOLS, &protocols, sizeof(protocols));

    DWORD timeout = 10000;
    InternetSetOptionW(hInternet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(DWORD));

    HINTERNET hFile = InternetOpenUrlA(hInternet, url, NULL, 0, 
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0);
    
    if (hFile) {
        int capacity = 512 * 1024; // 512KB 初始缓冲
        char* buf = (char*)malloc(capacity);
        DWORD bytesRead = 0, totalRead = 0;
        
        while (InternetReadFile(hFile, buf + totalRead, capacity - totalRead - 1, &bytesRead) && bytesRead > 0) {
            totalRead += bytesRead;
            if (totalRead >= (DWORD)capacity - 2048) {
                capacity *= 2;
                char* newBuf = (char*)realloc(buf, capacity);
                if (!newBuf) { free(buf); buf = NULL; break; }
                buf = newBuf;
            }
        }
        if (buf && totalRead > 0) { buf[totalRead] = 0; result = SafeStrDup(buf, totalRead); }
        if (buf) free(buf);
        InternetCloseHandle(hFile);
    }
    InternetCloseHandle(hInternet);
    return result;
}

// 引擎 B: BoringSSL - 仅用于获取 ECH Config
static char* InternalBoringSSLGet(const char* url) {
    URL_COMPONENTS_SIMPLE u;
    if (!ParseUrl(url, &u)) return NULL;

    if (g_utils_ctx == NULL) {
        if (InterlockedCompareExchange(&g_ctx_init_state, 1, 0) == 0) {
            g_utils_ctx = SSL_CTX_new(TLS_client_method());
            if (g_utils_ctx) SSL_CTX_set_verify(g_utils_ctx, SSL_VERIFY_NONE, NULL);
            InterlockedExchange(&g_ctx_init_state, 2);
        } else { while (g_ctx_init_state != 2) Sleep(10); }
    }
    if (!g_utils_ctx) return NULL;

    SOCKET s = INVALID_SOCKET; SSL *ssl = NULL; char* result = NULL;
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints)); hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    char portStr[16]; snprintf(portStr, 16, "%d", u.port);
    if (getaddrinfo(u.host, portStr, &hints, &res) != 0) return NULL;
    s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (connect(s, res->ai_addr, (int)res->ai_addrlen) != 0) { closesocket(s); freeaddrinfo(res); return NULL; }
    freeaddrinfo(res);

    ssl = SSL_new(g_utils_ctx);
    SSL_set_fd(ssl, (int)s); SSL_set_tlsext_host_name(ssl, u.host);
    if (SSL_connect(ssl) != 1) { SSL_free(ssl); closesocket(s); return NULL; }

    char* req = (char*)malloc(4096);
    int req_len = snprintf(req, 4096, "GET %s HTTP/1.1\r\nHost: %s\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n", u.path, u.host);
    SSL_write(ssl, req, req_len); free(req);

    int t_cap = 65536, t_len = 0; char* buf = (char*)malloc(t_cap);
    while (1) {
        int n = SSL_read(ssl, buf + t_len, t_cap - t_len - 1);
        if (n <= 0) break;
        t_len += n;
    }
    if (buf) {
        buf[t_len] = 0; char* body = strstr(buf, "\r\n\r\n");
        if (body) result = SafeStrDup(body + 4, t_len - (int)(body + 4 - buf));
        free(buf);
    }
    SSL_shutdown(ssl); SSL_free(ssl); closesocket(s);
    return result;
}

// 统一入口：修正判定逻辑，防止订阅链接误入 BoringSSL
char* Utils_HttpGet(const char* url) {
    if (!url || strncmp(url, "http", 4) != 0) return NULL;
    // 仅当明确是 DoH 请求时才用 BoringSSL
    if (strstr(url, "/dns-query")) return InternalBoringSSLGet(url);
    // 其余一律走稳定引擎
    return InternalWinInetGet(url);
}

// --------------------------------------------------------------------------
// 其它工具函数保持不变
// --------------------------------------------------------------------------
char* GetClipboardText() {
    if (!OpenClipboard(NULL)) return NULL;
    HANDLE hData = GetClipboardData(CF_TEXT);
    if (!hData) { CloseClipboard(); return NULL; }
    char* pszText = (char*)GlobalLock(hData);
    char* text = pszText ? SafeStrDup(pszText, (int)strlen(pszText)) : NULL;
    GlobalUnlock(hData); CloseClipboard();
    return text;
}

void SetSystemProxy(BOOL enable) {
    extern int g_localPort; if (g_localPort <= 0) g_localPort = 1080;
    wchar_t proxyServer[256]; swprintf_s(proxyServer, 256, L"127.0.0.1:%d", g_localPort);
    if (IsWindows8OrGreater()) {
        HKEY hKey; if (RegCreateKeyExW(HKEY_CURRENT_USER, REG_PATH_PROXY, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            DWORD dwEn = enable ? 1 : 0; RegSetValueExW(hKey, L"ProxyEnable", 0, REG_DWORD, (BYTE*)&dwEn, sizeof(dwEn));
            if (enable) {
                RegSetValueExW(hKey, L"ProxyServer", 0, REG_SZ, (BYTE*)proxyServer, (DWORD)(wcslen(proxyServer)+1)*2);
                RegSetValueExW(hKey, L"ProxyOverride", 0, REG_SZ, (BYTE*)L"<local>", 16);
            }
            RegCloseKey(hKey);
        }
    } else {
        INTERNET_PER_CONN_OPTION_LISTW list; INTERNET_PER_CONN_OPTIONW opts[3];
        opts[0].dwOption = INTERNET_PER_CONN_FLAGS; opts[0].Value.dwValue = enable ? PROXY_TYPE_PROXY : PROXY_TYPE_DIRECT;
        opts[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER; opts[1].Value.pszValue = enable ? proxyServer : L"";
        opts[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS; opts[2].Value.pszValue = L"<local>";
        list.dwSize = sizeof(list); list.pszConnection = NULL; list.dwOptionCount = 3; list.pOptions = opts;
        InternetSetOptionW(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, sizeof(list));
    }
    InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
    InternetSetOptionW(NULL, INTERNET_OPTION_REFRESH, NULL, 0);
}

BOOL IsSystemProxyEnabled() {
    BOOL en = FALSE; HKEY hKey; DWORD dwEn = 0, dwSz = 4;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, REG_PATH_PROXY, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, L"ProxyEnable", NULL, NULL, (BYTE*)&dwEn, &dwSz) == ERROR_SUCCESS && dwEn == 1) en = TRUE;
        RegCloseKey(hKey);
    }
    return en;
}

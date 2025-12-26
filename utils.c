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

// 引入 OpenSSL/BoringSSL 头文件
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "crypto.h"
#include "common.h"
#include "gui.h" 
#include "cJSON.h" 

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wininet.lib")

// 全局 SSL_CTX 复用
static SSL_CTX* g_utils_ctx = NULL;
// 用于线程安全初始化的原子变量
static volatile LONG g_ctx_init_flag = 0;

// --------------------------------------------------------------------------
// 基础工具函数
// --------------------------------------------------------------------------
BOOL IsWindows8OrGreater() {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32 == NULL) return FALSE;
    FARPROC pFunc = GetProcAddress(hKernel32, "SetProcessMitigationPolicy");
    return (pFunc != NULL);
}

// 安全字符串克隆，确保 Windows 7 上的健壮性
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

    char buf[2048]; 
    char time_buf[64]; 
    SYSTEMTIME st; 
    
    GetLocalTime(&st);
    snprintf(time_buf, sizeof(time_buf), "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
    
    va_list args; 
    va_start(args, format); 
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
    if (!*buffer) { 
        fclose(f); 
        return FALSE; 
    }
    
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
    char search[128];
    snprintf(search, sizeof(search), "%s=", key);
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
    strncpy(val, p, len);
    val[len] = 0;
    return val;
}

// --------------------------------------------------------------------------
// Base64 处理
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

// --------------------------------------------------------------------------
// ECH (Encrypted Client Hello) 解析实现
// --------------------------------------------------------------------------
unsigned char* FetchECHConfig(const char* domain, const char* doh_server, size_t* out_len) {
    if (!domain || !doh_server) return NULL;
    char url[1024]; snprintf(url, sizeof(url), "%s?name=%s&type=65", doh_server, domain);

    char* json_str = Utils_HttpGet(url);
    if (!json_str) return NULL;
    cJSON* root = cJSON_Parse(json_str);
    free(json_str);
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
                    if (!ech_config) {
                        unsigned char rdata[4096];
                        int rdata_len = HexToBin(data_str, rdata, sizeof(rdata));
                        if (rdata_len > 5) { 
                            int p = 2; // Priority
                            while (p < rdata_len) { // Skip TargetName
                                int label_len = rdata[p++];
                                if (label_len == 0 || p + label_len > rdata_len) break; 
                                p += label_len;
                            }
                            while (p + 4 <= rdata_len) {
                                int key = (rdata[p] << 8) | rdata[p+1];
                                int len = (rdata[p+2] << 8) | rdata[p+3];
                                p += 4;
                                if (key == 5 && p + len <= rdata_len) { 
                                    ech_config = (unsigned char*)malloc(len);
                                    if (ech_config) { memcpy(ech_config, rdata + p, len); *out_len = len; }
                                    break; 
                                }
                                p += len;
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
// 网络请求与 HTTPS 实现 (针对 Windows 7 深度加固)
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

static char* InternalHttpsGet(const char* url) {
    URL_COMPONENTS_SIMPLE u;
    if (!ParseUrl(url, &u)) return NULL;

    // [修复] 使用 Interlocked 原子操作进行线程安全初始化，彻底解决 Win7 的内存竞争
    if (g_utils_ctx == NULL) {
        if (InterlockedCompareExchange(&g_ctx_init_flag, 1, 0) == 0) {
            g_utils_ctx = SSL_CTX_new(TLS_client_method());
            if (g_utils_ctx) SSL_CTX_set_verify(g_utils_ctx, SSL_VERIFY_NONE, NULL);
            InterlockedExchange(&g_ctx_init_flag, 2);
        } else {
            while (g_ctx_init_flag != 2) Sleep(10);
        }
    }
    if (!g_utils_ctx) return NULL;

    SOCKET s = INVALID_SOCKET; SSL *ssl = NULL; char* result = NULL;
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    char portStr[16]; snprintf(portStr, 16, "%d", u.port);
    if (getaddrinfo(u.host, portStr, &hints, &res) != 0) return NULL;
    s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) { freeaddrinfo(res); return NULL; }
    
    DWORD timeout = 8000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
    if (connect(s, res->ai_addr, (int)res->ai_addrlen) != 0) { closesocket(s); freeaddrinfo(res); return NULL; }
    freeaddrinfo(res);

    ssl = SSL_new(g_utils_ctx);
    if (!ssl) { closesocket(s); return NULL; }
    SSL_set_fd(ssl, (int)s); SSL_set_tlsext_host_name(ssl, u.host);
    if (SSL_connect(ssl) != 1) { SSL_free(ssl); closesocket(s); return NULL; }

    // [修复] 仅对 DoH 请求发送特定的 Accept 头部，防止订阅服务器返回 406 错误导致崩溃
    const char* accept_header = (strstr(u.path, "dns-query") || strstr(u.path, "name=")) ? 
                                 "Accept: application/dns-json\r\n" : "Accept: */*\r\n";

    // [关键修复] 将缓冲区改为堆分配 (malloc)，彻底解决 0x40000015 栈溢出崩溃
    char* req = (char*)malloc(8192);
    if (!req) goto cleanup;
    
    // 强制 Null 终止，解决 Win7 下 _snprintf 不自动添加终止符的问题
    int req_len = snprintf(req, 8192, 
        "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mandala-Client/1.0\r\n%sConnection: close\r\n\r\n", 
        u.path, u.host, accept_header);
    
    if (req_len > 0 && req_len < 8192) {
        SSL_write(ssl, req, req_len);
    }
    free(req);

    int total_cap = 131072; int total_len = 0;
    char* buf = (char*)malloc(total_cap);
    if (!buf) goto cleanup;

    while (1) {
        if (total_len >= total_cap - 2048) {
            total_cap *= 2; char* new_buf = (char*)realloc(buf, total_cap);
            if (!new_buf) { free(buf); buf = NULL; goto cleanup; }
            buf = new_buf;
        }
        int n = SSL_read(ssl, buf + total_len, total_cap - total_len - 1);
        if (n <= 0) break;
        total_len += n;
    }

    if (buf) {
        buf[total_len] = 0; char* body_pos = strstr(buf, "\r\n\r\n");
        if (body_pos) { 
            body_pos += 4;
            int body_len = total_len - (int)(body_pos - buf);
            result = SafeStrDup(body_pos, body_len);
            free(buf); 
        } else { 
            result = buf; 
        }
    }
cleanup:
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    if (s != INVALID_SOCKET) closesocket(s);
    return result;
}

char* Utils_HttpGet(const char* url) {
    if (!url || strncmp(url, "http", 4) != 0) return NULL;
    return InternalHttpsGet(url);
}

// --------------------------------------------------------------------------
// 剪贴板操作
// --------------------------------------------------------------------------
char* GetClipboardText() {
    if (!OpenClipboard(NULL)) return NULL;
    HANDLE hData = GetClipboardData(CF_TEXT);
    if (!hData) { CloseClipboard(); return NULL; }
    char* pszText = (char*)GlobalLock(hData);
    char* text = NULL;
    if (pszText) text = SafeStrDup(pszText, (int)strlen(pszText));
    GlobalUnlock(hData); CloseClipboard();
    return text;
}

// --------------------------------------------------------------------------
// 系统代理设置
// --------------------------------------------------------------------------
void SetSystemProxy(BOOL enable) {
    extern int g_localPort;
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
                RegSetValueExW(hKey, L"ProxyOverride", 0, REG_SZ, (const BYTE*)proxyBypassString, (DWORD)(wcslen(proxyBypassString) + 1) * sizeof(wchar_t));
                RegSetValueExW(hKey, L"ProxyServer", 0, REG_SZ, (const BYTE*)proxyServerString, (DWORD)(wcslen(proxyServerString) + 1) * sizeof(wchar_t));
                RegDeleteValueW(hKey, L"SocksProxyServer"); 
            } else {
                DWORD dwEnable = 0;
                RegSetValueExW(hKey, L"ProxyEnable", 0, REG_DWORD, (const BYTE*)&dwEnable, sizeof(dwEnable));
                RegSetValueExW(hKey, L"ProxyServer", 0, REG_SZ, (const BYTE*)L"", sizeof(wchar_t));
                RegDeleteValueW(hKey, L"SocksProxyServer");
            }
            RegCloseKey(hKey);
        }
    } else {
        INTERNET_PER_CONN_OPTION_LISTW list; INTERNET_PER_CONN_OPTIONW options[3];
        options[0].dwOption = INTERNET_PER_CONN_FLAGS;
        options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
        options[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
        if (enable) {
            options[0].Value.dwValue = PROXY_TYPE_PROXY;
            options[1].Value.pszValue = proxyServerString; options[2].Value.pszValue = proxyBypassString;
        } else {
            options[0].Value.dwValue = PROXY_TYPE_DIRECT;
            options[1].Value.pszValue = L""; options[2].Value.pszValue = L"";
        }
        list.dwSize = sizeof(list); list.pszConnection = NULL; list.dwOptionCount = 3;
        list.dwOptionError = 0; list.pOptions = options;
        InternetSetOptionW(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, sizeof(list));
    }
    InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
    InternetSetOptionW(NULL, INTERNET_OPTION_REFRESH, NULL, 0);
}

BOOL IsSystemProxyEnabled() {
    extern int g_localPort; BOOL isEnabled = FALSE; HKEY hKey;
    DWORD dwEnable = 0, dwSize = sizeof(dwEnable);
    wchar_t proxyServer[1024] = {0}; DWORD dwProxySize = sizeof(proxyServer);
    if (RegOpenKeyExW(HKEY_CURRENT_USER, REG_PATH_PROXY, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, L"ProxyEnable", NULL, NULL, (LPBYTE)&dwEnable, &dwSize) == ERROR_SUCCESS && dwEnable == 1) {
            if (RegQueryValueExW(hKey, L"ProxyServer", NULL, NULL, (LPBYTE)proxyServer, &dwProxySize) == ERROR_SUCCESS) {
                wchar_t expected[64]; swprintf_s(expected, 64, L"127.0.0.1:%d", g_localPort);
                if (wcsstr(proxyServer, expected) != NULL) isEnabled = TRUE;
            }
        }
        RegCloseKey(hKey);
    }
    return isEnabled;
}

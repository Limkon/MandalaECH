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

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "crypto.h"
#include "common.h"
#include "gui.h" 
#include "cJSON.h" 

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wininet.lib")

// 工具类专用 SSL_CTX，单例模式
static SSL_CTX* g_utils_ctx = NULL;

BOOL IsWindows8OrGreater() {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32 == NULL) return FALSE;
    FARPROC pFunc = GetProcAddress(hKernel32, "SetProcessMitigationPolicy");
    return (pFunc != NULL);
}

// [Robustness] 改进日志函数，防止过长消息溢出
void log_msg(const char *format, ...) {
    if (!g_enableLog && strstr(format, "[Fatal]") == NULL) return;

    char buf[2048]; 
    char time_buf[64]; 
    SYSTEMTIME st; 
    
    GetLocalTime(&st);
    snprintf(time_buf, sizeof(time_buf), "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
    
    va_list args; 
    va_start(args, format); 
    // 使用 vsnprintf 保证不越界
    vsnprintf(buf, sizeof(buf) - 2, format, args); 
    va_end(args);
    buf[sizeof(buf) - 1] = 0; // 确保截断
    
    // 拼接时间戳
    char final_msg[2200]; 
    snprintf(final_msg, sizeof(final_msg), "%s%s\r\n", time_buf, buf);
    
    OutputDebugStringA(final_msg);
    
    extern HWND hLogViewerWnd; 
    if (hLogViewerWnd && IsWindow(hLogViewerWnd)) {
        int wLen = MultiByteToWideChar(CP_UTF8, 0, final_msg, -1, NULL, 0);
        if (wLen > 0) {
            wchar_t* wBuf = (wchar_t*)malloc((wLen + 1) * sizeof(wchar_t));
            if (wBuf) {
                MultiByteToWideChar(CP_UTF8, 0, final_msg, -1, wBuf, wLen);
                wBuf[wLen] = 0;
                PostMessageW(hLogViewerWnd, WM_LOG_UPDATE, 0, (LPARAM)wBuf);
            }
        }
    }
}

// --- 文件 IO ---
BOOL ReadFileToBuffer(const wchar_t* filename, char** buffer, long* size) {
    FILE* f = _wfopen(filename, L"rb");
    if (!f) return FALSE;
    
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (fsize < 0) { fclose(f); return FALSE; }

    *buffer = (char*)malloc(fsize + 1);
    if (!*buffer) { fclose(f); return FALSE; }
    
    size_t read_bytes = fread(*buffer, 1, fsize, f);
    (*buffer)[read_bytes] = 0; 
    
    if (size) *size = (long)read_bytes;
    
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
        unsigned char b = (unsigned char)input[i+1];
        if (i+1 >= len || b64_table[a] == -1 || b64_table[b] == -1) break;
        
        uint32_t n = (b64_table[a] << 18) | (b64_table[b] << 12);
        out[j++] = (n >> 16) & 0xFF;
        
        if (i + 2 < len) {
            unsigned char c = (unsigned char)input[i+2];
            if (c != '=' && b64_table[c] != -1) {
                n |= (b64_table[c] << 6);
                out[j++] = (n >> 8) & 0xFF;
                if (i + 3 < len) {
                    unsigned char d = (unsigned char)input[i+3];
                    if (d != '=' && b64_table[d] != -1) {
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

// --- ECH Helper ---
static int HexToBin(const char* hex, unsigned char* out, int max_len) {
    int len = 0;
    while (*hex && len < max_len) {
        char c = *hex;
        int val = 0;
        if (!isxdigit(c)) { hex++; continue; }
        if (c >= '0' && c <= '9') val = c - '0';
        else if (c >= 'a' && c <= 'f') val = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') val = c - 'A' + 10;
        hex++; if (!*hex) break; 
        char c2 = *hex; int val2 = 0;
        if (c2 >= '0' && c2 <= '9') val2 = c2 - '0';
        else if (c2 >= 'a' && c2 <= 'f') val2 = c2 - 'a' + 10;
        else if (c2 >= 'A' && c2 <= 'F') val2 = c2 - 'A' + 10;
        out[len++] = (val << 4) | val2; hex++;
    }
    return len;
}

// [Security] FetchECHConfig 实现
unsigned char* FetchECHConfig(const char* domain, const char* doh_server, size_t* out_len) {
    if (!domain || !doh_server) return NULL;
    char url[1024];
    snprintf(url, sizeof(url), "%s?name=%s&type=65", doh_server, domain);

    log_msg("[ECH] Querying %s for %s", doh_server, domain);
    char* json_str = Utils_HttpGet(url);
    if (!json_str) {
        log_msg("[ECH] DoH request failed.");
        return NULL;
    }

    cJSON* root = cJSON_Parse(json_str);
    free(json_str);
    if (!root) return NULL;

    unsigned char* ech_config = NULL;
    *out_len = 0;

    cJSON* answer = cJSON_GetObjectItem(root, "Answer");
    if (cJSON_IsArray(answer)) {
        cJSON* record = NULL;
        cJSON_ArrayForEach(record, answer) {
            cJSON* type = cJSON_GetObjectItem(record, "type");
            if (type && type->valueint == 65) { 
                cJSON* data = cJSON_GetObjectItem(record, "data");
                if (data && data->valuestring) {
                    const char* data_str = data->valuestring;
                    const char* ech_pos = strstr(data_str, "ech=\"");
                    if (ech_pos) {
                        ech_pos += 5; 
                        const char* end_quote = strchr(ech_pos, '\"');
                        if (end_quote) {
                            size_t b64_len = end_quote - ech_pos;
                            char* b64_str = (char*)malloc(b64_len + 1);
                            if (b64_str) {
                                strncpy(b64_str, ech_pos, b64_len); b64_str[b64_len] = 0;
                                ech_config = Base64Decode(b64_str, out_len);
                                free(b64_str);
                                if (ech_config) break; 
                            }
                        }
                    }
                    if (!ech_config) {
                        unsigned char rdata[4096];
                        int rdata_len = HexToBin(data_str, rdata, sizeof(rdata));
                        if (rdata_len > 5) { 
                            int p = 2; // Priority
                            while (p < rdata_len) {
                                int label_len = rdata[p++];
                                if (label_len == 0) break; 
                                p += label_len;
                            }
                            while (p + 4 <= rdata_len) {
                                int key = (rdata[p] << 8) | rdata[p+1];
                                int len = (rdata[p+2] << 8) | rdata[p+3];
                                p += 4;
                                if (key == 5) { 
                                    if (p + len <= rdata_len) {
                                        ech_config = (unsigned char*)malloc(len);
                                        if (ech_config) {
                                            memcpy(ech_config, rdata + p, len);
                                            *out_len = len;
                                        }
                                    }
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
    cJSON_Delete(root);
    return ech_config;
}

// --- HTTPS Request ---
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

static char* InternalHttpsGet(const char* url) {
    URL_COMPONENTS_SIMPLE u;
    if (!ParseUrl(url, &u)) return NULL;

    if (!g_utils_ctx) {
        g_utils_ctx = SSL_CTX_new(TLS_client_method());
        if (!g_utils_ctx) return NULL;
        SSL_CTX_set_verify(g_utils_ctx, SSL_VERIFY_NONE, NULL);
    }

    SOCKET s = INVALID_SOCKET;
    SSL *ssl = NULL;
    char* result = NULL;
    char* buf = NULL;
    struct addrinfo hints, *res = NULL;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; 
    hints.ai_socktype = SOCK_STREAM;
    char portStr[16]; snprintf(portStr, 16, "%d", u.port);
    
    if (getaddrinfo(u.host, portStr, &hints, &res) != 0) return NULL;
    
    s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) { freeaddrinfo(res); return NULL; }
    
    DWORD timeout = 5000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    if (connect(s, res->ai_addr, (int)res->ai_addrlen) != 0) {
        closesocket(s); freeaddrinfo(res); return NULL;
    }
    freeaddrinfo(res);

    ssl = SSL_new(g_utils_ctx);
    if (!ssl) { closesocket(s); return NULL; }
    SSL_set_fd(ssl, (int)s);
    SSL_set_tlsext_host_name(ssl, u.host);

    if (SSL_connect(ssl) != 1) goto cleanup;

    char req[2048];
    snprintf(req, sizeof(req), 
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: Mandala-Client/1.0\r\n"
        "Accept: application/dns-json\r\n" 
        "Connection: close\r\n\r\n", 
        u.path, u.host);
        
    if (SSL_write(ssl, req, strlen(req)) <= 0) goto cleanup;

    int total_cap = 65536; 
    int total_len = 0;
    buf = (char*)malloc(total_cap);
    if (!buf) goto cleanup;

    while (1) {
        if (total_len >= total_cap - 1024) {
            total_cap *= 2;
            char* new_buf = (char*)realloc(buf, total_cap);
            if (!new_buf) { free(buf); buf = NULL; goto cleanup; }
            buf = new_buf;
        }
        int n = SSL_read(ssl, buf + total_len, total_cap - total_len - 1);
        if (n <= 0) break;
        total_len += n;
    }
    buf[total_len] = 0;

    char* body = strstr(buf, "\r\n\r\n");
    if (body) { body += 4; result = _strdup(body); free(buf); buf = NULL; } 
    else { result = buf; buf = NULL; }

cleanup:
    if (buf) free(buf);
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    if (s != INVALID_SOCKET) closesocket(s);
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
    return text;
}

// --- 系统代理 ---
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

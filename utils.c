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

// 全局 SSL 上下文
static SSL_CTX* g_utils_ctx = NULL;

// --------------------------------------------------------------------------
// 日志与辅助
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
    if (d) { memcpy(d, s, len); d[len] = 0; }
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
// Base64 / Hex (Robust Implementation)
// --------------------------------------------------------------------------

static const int b64_table[] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,62,-1,63, // + and -
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1, // 0-9
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14, // A-O
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,63, // P-Z and _
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40, // a-o
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1  // p-z
};

// 健壮的 Base64 解码：忽略所有非 Base64 字符（空格、换行等），只处理有效字符
unsigned char* Base64Decode(const char* input, size_t* out_len) {
    if(!input) return NULL;
    size_t len = strlen(input);
    if (len == 0) return NULL;

    size_t out_capacity = len * 3 / 4 + 4;
    unsigned char* out = (unsigned char*)malloc(out_capacity);
    if (!out) return NULL;

    size_t i = 0;
    size_t j = 0;
    int value_buf = 0;
    int bits_collected = 0;

    while (i < len) {
        unsigned char c = (unsigned char)input[i++];
        if (c == '=') break; // Padding end
        if (c > 127) continue; // Skip non-ascii

        int val = b64_table[c];
        if (val == -1) continue; // Skip invalid chars (whitespace etc)

        value_buf = (value_buf << 6) | val;
        bits_collected += 6;

        if (bits_collected >= 8) {
            bits_collected -= 8;
            out[j++] = (unsigned char)((value_buf >> bits_collected) & 0xFF);
        }
    }
    
    out[j] = 0;
    if (out_len) *out_len = j;
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
// 网络请求实现
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
    if (!ParseUrl(url, &u)) { log_msg("[Net] Invalid URL: %s", url); return NULL; }

    if (!g_utils_ctx) {
        g_utils_ctx = SSL_CTX_new(TLS_client_method());
        if (!g_utils_ctx) return NULL;
        SSL_CTX_set_verify(g_utils_ctx, SSL_VERIFY_NONE, NULL);
    }

    SOCKET s = INVALID_SOCKET;
    SSL *ssl = NULL;
    char* result = NULL;
    struct addrinfo hints, *res = NULL, *ptr = NULL;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; 
    hints.ai_socktype = SOCK_STREAM;
    
    char portStr[16]; snprintf(portStr, 16, "%d", u.port);
    if (getaddrinfo(u.host, portStr, &hints, &res) != 0) {
        log_msg("[Net] DNS failed: %s", u.host);
        return NULL;
    }
    
    // [Fix] 遍历所有解析出的地址 (IPv4/IPv6)，直到连接成功
    for (ptr = res; ptr != NULL; ptr = ptr->ai_next) {
        s = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (s == INVALID_SOCKET) continue;

        DWORD timeout = 8000; 
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

        if (connect(s, ptr->ai_addr, (int)ptr->ai_addrlen) == 0) {
            break; // 连接成功
        }
        
        closesocket(s);
        s = INVALID_SOCKET;
    }
    
    freeaddrinfo(res);

    if (s == INVALID_SOCKET) {
        log_msg("[Net] Connect failed (all addresses): %s", u.host);
        return NULL;
    }

    ssl = SSL_new(g_utils_ctx);
    if (!ssl) { closesocket(s); return NULL; }
    SSL_set_fd(ssl, (int)s);
    
    SSL_set_tlsext_host_name(ssl, u.host);

    if (SSL_connect(ssl) != 1) {
        log_msg("[Net] SSL Handshake failed: %s", u.host);
        SSL_free(ssl); closesocket(s); return NULL;
    }

    char req[2048];
    snprintf(req, sizeof(req), 
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: Mandala-Client/1.0\r\n"
        "Connection: close\r\n\r\n", 
        u.path, u.host);
        
    SSL_write(ssl, req, strlen(req));

    int total_cap = 65536, total_len = 0;
    char* buf = (char*)malloc(total_cap);
    
    while (buf) {
        if (total_len >= total_cap - 1024) {
            total_cap *= 2;
            char* new_buf = (char*)realloc(buf, total_cap);
            if (!new_buf) { free(buf); buf = NULL; break; }
            buf = new_buf;
        }
        int n = SSL_read(ssl, buf + total_len, total_cap - total_len - 1);
        if (n <= 0) break;
        total_len += n;
    }
    
    if (buf) {
        buf[total_len] = 0;
        char* body = strstr(buf, "\r\n\r\n");
        if (body) {
            body += 4;
            result = SafeStrDup(body, total_len - (int)(body - buf));
            free(buf);
        } else {
            result = buf; 
        }
    }

    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    if (s != INVALID_SOCKET) closesocket(s);
    
    return result;
}

char* Utils_HttpGet(const char* url) {
    if (!url) return NULL;
    return InternalHttpsGet(url);
}

// ECH 配置获取 (Debug Enhanced)
unsigned char* FetchECHConfig(const char* domain, const char* doh_server, size_t* out_len) {
    if (!domain || !doh_server) return NULL;
    char url[2048]; snprintf(url, sizeof(url), "%s?name=%s&type=65", doh_server, domain);
    
    char* json_str = Utils_HttpGet(url);
    if (!json_str) {
        log_msg("[ECH] JSON fetch failed");
        return NULL;
    }
    
    cJSON* root = cJSON_Parse(json_str); free(json_str);
    if (!root) {
        log_msg("[ECH] JSON parse failed");
        return NULL;
    }
    
    unsigned char* ech_config = NULL; *out_len = 0;
    cJSON* answer = cJSON_GetObjectItem(root, "Answer");
    
    if (answer && cJSON_IsArray(answer)) {
        int array_size = cJSON_GetArraySize(answer);
        for (int i = 0; i < array_size; i++) {
            cJSON* record = cJSON_GetArrayItem(answer, i);
            if (!record) continue;
            cJSON* type = cJSON_GetObjectItem(record, "type");
            
            // Type 65 = HTTPS
            if (type && type->valueint == 65) { 
                cJSON* data = cJSON_GetObjectItem(record, "data");
                if (data && data->valuestring) {
                    const char* data_str = data->valuestring;
                    log_msg("[ECH] Raw RR: %s", data_str); 

                    // ----------------------------------------------------
                    // Strategy A: Check for ech="Base64"
                    // ----------------------------------------------------
                    const char* tag = "ech=\"";
                    char* p_start = strstr(data_str, tag);
                    if (p_start) {
                        p_start += strlen(tag);
                        char* p_end = strchr(p_start, '"');
                        
                        // 防御性：处理转义引号，虽然在 Raw RR 中通常不需要
                        while (p_end && *(p_end - 1) == '\\') {
                            p_end = strchr(p_end + 1, '"');
                        }

                        if (p_end) {
                            int b64_len = (int)(p_end - p_start);
                            if (b64_len > 0) {
                                char* b64_str = (char*)malloc(b64_len + 1);
                                if (b64_str) {
                                    memcpy(b64_str, p_start, b64_len);
                                    b64_str[b64_len] = 0;
                                    
                                    log_msg("[ECH] Found tag, extracting %d chars: %.20s...", b64_len, b64_str);

                                    size_t decoded_len = 0;
                                    unsigned char* decoded = Base64Decode(b64_str, &decoded_len);
                                    free(b64_str);
                                    
                                    if (decoded && decoded_len > 0) {
                                        ech_config = decoded;
                                        *out_len = decoded_len;
                                        log_msg("[ECH] Base64 success, len=%d", decoded_len);
                                        break; // Success!
                                    } else {
                                        log_msg("[ECH] Base64 decode failed or empty");
                                        if(decoded) free(decoded);
                                    }
                                }
                            }
                        } else {
                            log_msg("[ECH] Malformed ech param (missing end quote)");
                        }
                    }

                    // ----------------------------------------------------
                    // Strategy B: RFC 3597 Hex Format (\# <len> <hex>)
                    // ----------------------------------------------------
                    if (!ech_config) {
                        const char* p_hex = data_str;
                        if (strncmp(p_hex, "\\#", 2) == 0) {
                            p_hex += 2;
                            while (*p_hex && isspace((unsigned char)*p_hex)) p_hex++;
                            while (*p_hex && isdigit((unsigned char)*p_hex)) p_hex++;
                            while (*p_hex && isspace((unsigned char)*p_hex)) p_hex++;
                            
                            unsigned char rdata[4096];
                            int rdata_len = HexToBin(p_hex, rdata, sizeof(rdata));
                            
                            if (rdata_len > 2) {
                                unsigned char* ptr = rdata;
                                unsigned char* end = rdata + rdata_len;
                                if (ptr + 2 <= end) {
                                    int priority = (ptr[0] << 8) | ptr[1];
                                    ptr += 2;
                                    if (priority != 0) {
                                        // Skip Target Name
                                        while (ptr < end && *ptr != 0) {
                                            int label_len = *ptr; ptr++;
                                            if (ptr + label_len > end) { ptr = end; break; }
                                            ptr += label_len;
                                        }
                                        if (ptr < end) ptr++; // Skip null terminator
                                        
                                        // Scan Params
                                        while (ptr + 4 <= end) {
                                            int key = (ptr[0] << 8) | ptr[1];
                                            int val_len = (ptr[2] << 8) | ptr[3];
                                            ptr += 4;
                                            if (ptr + val_len > end) break;
                                            
                                            if (key == 0x0005) { // ECH Config
                                                ech_config = (unsigned char*)malloc(val_len);
                                                if (ech_config) {
                                                    memcpy(ech_config, ptr, val_len);
                                                    *out_len = val_len;
                                                    log_msg("[ECH] Hex wire format success, len=%d", val_len);
                                                }
                                                break;
                                            }
                                            ptr += val_len;
                                        }
                                    }
                                }
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

// --------------------------------------------------------------------------
// 其他工具函数
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
    const char* end = (end_amp && end_hash) ? (end_amp < end_hash ? end_amp : end_hash) : (end_amp ? end_amp : end_hash);
    int len = end ? (int)(end - p) : (int)strlen(p);
    if (len <= 0) return NULL;
    char* val = (char*)malloc(len + 1);
    if (val) { strncpy(val, p, len); val[len] = 0; }
    return val;
}

char* GetClipboardText() {
    if (!OpenClipboard(NULL)) return NULL;
    HANDLE hData = GetClipboardData(CF_TEXT);
    if (!hData) { CloseClipboard(); return NULL; }
    char* pszText = (char*)GlobalLock(hData);
    char* text = pszText ? SafeStrDup(pszText, (int)strlen(pszText)) : NULL;
    GlobalUnlock(hData); CloseClipboard();
    return text;
}

// --------------------------------------------------------------------------
// 代理设置
// --------------------------------------------------------------------------

void SetSystemProxy(BOOL enable) {
    extern int g_localPort; if (g_localPort <= 0) g_localPort = 10809;
    wchar_t proxyServer[256]; swprintf_s(proxyServer, 256, L"127.0.0.1:%d", g_localPort);
    
    if (IsWindows8OrGreater()) {
        HKEY hKey; 
        if (RegCreateKeyExW(HKEY_CURRENT_USER, REG_PATH_PROXY, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            DWORD dwEn = enable ? 1 : 0; 
            RegSetValueExW(hKey, L"ProxyEnable", 0, REG_DWORD, (BYTE*)&dwEn, sizeof(dwEn));
            if (enable) {
                RegSetValueExW(hKey, L"ProxyServer", 0, REG_SZ, (BYTE*)proxyServer, (DWORD)(wcslen(proxyServer)+1)*2);
                RegSetValueExW(hKey, L"ProxyOverride", 0, REG_SZ, (BYTE*)L"<local>", 16);
            }
            RegCloseKey(hKey);
        }
    } else {
        INTERNET_PER_CONN_OPTION_LISTW list; INTERNET_PER_CONN_OPTIONW opts[3];
        opts[0].dwOption = INTERNET_PER_CONN_FLAGS; 
        opts[0].Value.dwValue = enable ? PROXY_TYPE_PROXY : PROXY_TYPE_DIRECT;
        opts[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER; 
        opts[1].Value.pszValue = enable ? proxyServer : L"";
        opts[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS; 
        opts[2].Value.pszValue = L"<local>";
        
        list.dwSize = sizeof(list); 
        list.pszConnection = NULL; 
        list.dwOptionCount = 3; 
        list.pOptions = opts;
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

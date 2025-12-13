#include "utils.h"
#include <stdio.h>
#include <wininet.h>

// 链接 wininet 库
#ifdef _MSC_VER
#pragma comment(lib, "wininet.lib")
#endif

// --- 宏定义补充 ---
#ifndef INTERNET_OPTION_SECURE_PROTOCOLS
#define INTERNET_OPTION_SECURE_PROTOCOLS 136
#endif
#ifndef SP_PROT_TLS1_2_CLIENT
#define SP_PROT_TLS1_2_CLIENT 0x00000800
#endif
#ifndef SP_PROT_TLS1_3_CLIENT
#define SP_PROT_TLS1_3_CLIENT 0x00002000
#endif
#ifndef INTERNET_FLAG_IGNORE_CERT_CN_INVALID
#define INTERNET_FLAG_IGNORE_CERT_CN_INVALID 0x00001000
#endif
#ifndef INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
#define INTERNET_FLAG_IGNORE_CERT_DATE_INVALID 0x00002000
#endif

extern int g_localPort; // 引用全局端口变量

void log_msg(const char *format, ...) {
    char buf[2048]; char time_buf[64]; SYSTEMTIME st; GetLocalTime(&st);
    sprintf(time_buf, "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
    va_list args; va_start(args, format); vsnprintf(buf, sizeof(buf)-64, format, args); va_end(args);
    char final_msg[2200]; snprintf(final_msg, sizeof(final_msg), "%s%s\r\n", time_buf, buf);
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

BOOL ReadFileToBuffer(const wchar_t* filename, char** buffer, long* fileSize) {
    FILE* f = NULL;
    if (_wfopen_s(&f, filename, L"rb") != 0 || !f) { *fileSize=0; return FALSE; }
    fseek(f, 0, SEEK_END); *fileSize = ftell(f); fseek(f, 0, SEEK_SET);
    *buffer = (char*)malloc(*fileSize + 1);
    if (*buffer) {
        fread(*buffer, 1, *fileSize, f); 
        (*buffer)[*fileSize] = 0;
    }
    fclose(f); return (*buffer != NULL);
}

BOOL WriteBufferToFile(const wchar_t* filename, const char* buffer) {
    FILE* f = NULL;
    if (_wfopen_s(&f, filename, L"wb") != 0 || !f) return FALSE;
    fwrite(buffer, 1, strlen(buffer), f);
    fclose(f); return TRUE;
}

// Base64 辅助
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
    while (len > 0 && (src[len-1] == '\n' || src[len-1] == '\r' || src[len-1] == ' ' || src[len-1] == '=')) len--;
    if (len == 0) { *out_len = 0; return NULL; }
    *out_len = (len * 3) / 4;
    unsigned char* out = (unsigned char*)malloc(*out_len + 4); 
    if (!out) return NULL;
    size_t i = 0, j = 0;
    while (i < len) {
        if (src[i] == '\r' || src[i] == '\n' || src[i] == ' ') { i++; continue; }
        int vals[4]; int val_cnt = 0;
        while (i < len && val_cnt < 4) {
            char c = src[i];
            if (c == '\r' || c == '\n' || c == ' ') { i++; continue; }
            if (c == '=') { i++; break; }
            int v = GetBase64Val(c);
            if (v == -1) { free(out); return NULL; } // 非法字符，返回 NULL
            vals[val_cnt++] = v; i++;
        }
        if (val_cnt > 0) {
            uint32_t triple = (vals[0] << 18) | ((val_cnt>1?vals[1]:0) << 12) | ((val_cnt>2?vals[2]:0) << 6) | ((val_cnt>3?vals[3]:0));
            if (j < *out_len) out[j++] = (triple >> 16) & 0xFF;
            if (val_cnt > 2 && j < *out_len) out[j++] = (triple >> 8) & 0xFF;
            if (val_cnt > 3 && j < *out_len) out[j++] = triple & 0xFF;
        }
    }
    out[j] = '\0'; *out_len = j; return out;
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

void TrimString(char* str) {
    if(!str) return;
    char* p = str; while(isspace((unsigned char)*p)) p++;
    if(p != str) memmove(str, p, strlen(p)+1);
    size_t len = strlen(str); while(len > 0 && isspace((unsigned char)str[len-1])) str[--len] = 0;
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

char* GetQueryParam(const char* query, const char* key) {
    if (!query || !key) return NULL;
    char keyEq[128]; snprintf(keyEq, sizeof(keyEq), "%s=", key);
    const char* start = strstr(query, keyEq);
    if (!start) return NULL;
    if (start != query && *(start - 1) != '&' && *(start - 1) != '?') return GetQueryParam(start + 1, key); 
    start += strlen(keyEq);
    const char* end = strchr(start, '&');
    size_t len = end ? (size_t)(end - start) : strlen(start);
    if (len == 0) return NULL;
    char* value = (char*)malloc(len + 1); strncpy(value, start, len); value[len] = '\0';
    char* decoded = (char*)malloc(len + 1); UrlDecode(decoded, value); free(value);
    return decoded;
}

// --- 内部下载实现 ---
static char* InternalDownload(const char* url, BOOL useProxy) {
    const char* ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    HINTERNET hInternet = NULL;

    if (useProxy && g_localPort > 0) {
        char proxyStr[64];
        sprintf(proxyStr, "127.0.0.1:%d", g_localPort);
        // 使用本地代理
        hInternet = InternetOpenA(ua, INTERNET_OPEN_TYPE_PROXY, proxyStr, NULL, 0);
        log_msg("[Utils] Downloading via PROXY: %s", proxyStr);
    } else {
        // 直连
        hInternet = InternetOpenA(ua, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        log_msg("[Utils] Downloading via DIRECT connection.");
    }

    if (!hInternet) return NULL;

    DWORD secure_protocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT | 0x00000080;
    InternetSetOption(hInternet, INTERNET_OPTION_SECURE_PROTOCOLS, &secure_protocols, sizeof(secure_protocols));

    DWORD timeout = 15000; // 15秒超时
    InternetSetOption(hInternet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOption(hInternet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOption(hInternet, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));

    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE | INTERNET_FLAG_PRAGMA_NOCACHE | 
                  INTERNET_FLAG_SECURE | 
                  INTERNET_FLAG_IGNORE_CERT_CN_INVALID | 
                  INTERNET_FLAG_IGNORE_CERT_DATE_INVALID |
                  0x00002000;

    HINTERNET hConnect = InternetOpenUrlA(hInternet, url, NULL, 0, flags, 0);
    if (!hConnect) {
        log_msg("[Utils] Connection failed. Error: %d", GetLastError());
        InternetCloseHandle(hInternet);
        return NULL;
    }

    DWORD bufferSize = 32768; char* buffer = (char*)malloc(bufferSize);
    if (!buffer) { InternetCloseHandle(hConnect); InternetCloseHandle(hInternet); return NULL; }
    buffer[0] = '\0';
    
    DWORD totalRead = 0; DWORD bytesRead = 0;
    while (InternetReadFile(hConnect, buffer + totalRead, 8192, &bytesRead) && bytesRead > 0) {
        totalRead += bytesRead;
        if (totalRead + 8192 >= bufferSize) {
            bufferSize *= 2; char* newBuf = (char*)realloc(buffer, bufferSize);
            if (!newBuf) { free(buffer); InternetCloseHandle(hConnect); InternetCloseHandle(hInternet); return NULL; }
            buffer = newBuf;
        }
    }
    buffer[totalRead] = '\0';
    InternetCloseHandle(hConnect); InternetCloseHandle(hInternet);
    return buffer;
}

// --- 公开下载接口 (混合模式) ---
char* Utils_HttpGet(const char* url) {
    if (!url) return NULL;
    
    // 1. 优先尝试走本地代理 (前提是端口已设置)
    // 这样可以翻墙下载 GitHub 等被墙资源
    if (g_localPort > 0) {
        char* res = InternalDownload(url, TRUE);
        if (res) return res;
        log_msg("[Utils] Proxy download failed, falling back to DIRECT mode...");
    }

    // 2. 如果代理失败（或未设置），尝试直连
    return InternalDownload(url, FALSE);
}

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
        wsprintfW(proxyServerString, L"127.0.0.1:%d", g_localPort);
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
                    wsprintfW(expectedPart, L"127.0.0.1:%d", g_localPort);
                    if (wcsstr(proxyServer, expectedPart) != NULL) return TRUE;
                }
            }
        }
        RegCloseKey(hKey);
    }
    return FALSE;
}

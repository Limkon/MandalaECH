#include "utils.h"
#include <stdio.h>
#include <wininet.h>

// 链接 wininet 库
#ifdef _MSC_VER
#pragma comment(lib, "wininet.lib")
#endif

// Base64 解码表
static const unsigned char base64_table[256] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,62,0,0,0,63,52,53,54,55,56,57,58,59,60,61,0,0,0,0,0,0,
    0,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,0,0,0,0,0,
    0,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51
};

void log_msg(const char *format, ...) {
    char buf[2048]; char time_buf[64]; SYSTEMTIME st; GetLocalTime(&st);
    sprintf(time_buf, "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
    va_list args; va_start(args, format); vsnprintf(buf, sizeof(buf)-64, format, args); va_end(args);
    char final_msg[2200]; snprintf(final_msg, sizeof(final_msg), "%s%s\r\n", time_buf, buf);
    OutputDebugStringA(final_msg);
    // 如果日志窗口存在，发送消息更新
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

unsigned char* Base64Decode(const char* src, size_t* out_len) {
    if (!src) return NULL;
    size_t len = strlen(src);
    while (len > 0 && (src[len-1] == '\n' || src[len-1] == '\r' || src[len-1] == ' ')) len--;
    if (len > 0 && src[len-1] == '=') len--;
    if (len > 0 && src[len-1] == '=') len--;
    *out_len = (len * 3) / 4;
    unsigned char* out = (unsigned char*)malloc(*out_len + 1);
    if (!out) return NULL;
    for (size_t i = 0, j = 0; i < len;) {
        unsigned char c = (unsigned char)src[i++];
        if (c == '\n' || c == '\r' || c == ' ') continue;
        uint32_t a = base64_table[c];
        uint32_t b = (i < len) ? base64_table[(unsigned char)src[i++]] : 0;
        uint32_t c_val = (i < len) ? base64_table[(unsigned char)src[i++]] : 0;
        uint32_t d = (i < len) ? base64_table[(unsigned char)src[i++]] : 0;
        uint32_t triple = (a << 18) | (b << 12) | (c_val << 6) | d;
        if (j < *out_len) out[j++] = (triple >> 16) & 0xFF;
        if (j < *out_len) out[j++] = (triple >> 8) & 0xFF;
        if (j < *out_len) out[j++] = triple & 0xFF;
    }
    out[*out_len] = '\0'; return out;
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

// --- 新增：HTTP 下载功能 (WinINet) 带 10秒超时 ---
char* Utils_HttpGet(const char* url) {
    if (!url) return NULL;
    
    // 初始化 WinINet
    HINTERNET hInternet = InternetOpenA("MandalaClient/1.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) {
        log_msg("[Utils] InternetOpen failed: %d", GetLastError());
        return NULL;
    }

    // 设置 10 秒超时 (10000 毫秒)
    DWORD timeout = 10000;
    InternetSetOption(hInternet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOption(hInternet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOption(hInternet, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));

    // 打开 URL (启用重载，不缓存)
    HINTERNET hConnect = InternetOpenUrlA(hInternet, url, NULL, 0, 
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE | INTERNET_FLAG_PRAGMA_NOCACHE, 0);
    
    if (!hConnect) {
        log_msg("[Utils] Download failed or timed out: %s", url);
        InternetCloseHandle(hInternet);
        return NULL;
    }

    // 读取数据
    DWORD bufferSize = 8192; // 初始 8KB
    char* buffer = (char*)malloc(bufferSize);
    if (!buffer) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return NULL;
    }
    buffer[0] = '\0';
    
    DWORD totalRead = 0;
    DWORD bytesRead = 0;
    
    // 循环读取直到结束
    while (InternetReadFile(hConnect, buffer + totalRead, 4096, &bytesRead) && bytesRead > 0) {
        totalRead += bytesRead;
        // 动态扩容
        if (totalRead + 4096 >= bufferSize) {
            bufferSize *= 2;
            char* newBuf = (char*)realloc(buffer, bufferSize);
            if (!newBuf) {
                free(buffer);
                InternetCloseHandle(hConnect);
                InternetCloseHandle(hInternet);
                return NULL;
            }
            buffer = newBuf;
        }
    }
    buffer[totalRead] = '\0';

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return buffer;
}

// --- 系统代理功能 ---
// 注意：g_localPort 是 config.c 中的全局变量，这里为了解耦，
// 我们假设调用者会确保端口正确，或者在此处通过外部声明引用。
// 为避免链接错误，此处使用 extern。
extern int g_localPort; 

BOOL IsWindows8OrGreater() {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32 == NULL) return FALSE;
    FARPROC pFunc = GetProcAddress(hKernel32, "SetProcessMitigationPolicy");
    return (pFunc != NULL);
}

void SetSystemProxy(BOOL enable) {
    if (enable && g_localPort <= 0) {
        // 如果端口无效，暂时不处理或记录日志
        return; 
    }

    wchar_t proxyServerString[256] = {0};
    wchar_t proxyBypassString[64] = {0};
    if (enable) {
        wsprintfW(proxyServerString, L"http=127.0.0.1:%d;socks=127.0.0.1:%d", g_localPort, g_localPort);
        wcscpy(proxyBypassString, L"<local>");
    }

    if (IsWindows8OrGreater()) {
        HKEY hKey;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, REG_PATH_PROXY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            if (enable) {
                DWORD dwEnable = 1;
                RegSetValueExW(hKey, L"ProxyEnable", 0, REG_DWORD, (const BYTE*)&dwEnable, sizeof(dwEnable));
                RegSetValueExW(hKey, L"ProxyOverride", 0, REG_SZ, (const BYTE*)proxyBypassString, (wcslen(proxyBypassString) + 1) * sizeof(wchar_t));
                RegSetValueExW(hKey, L"ProxyServer", 0, REG_SZ, (const BYTE*)proxyServerString, (wcslen(proxyServerString) + 1) * sizeof(wchar_t));
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

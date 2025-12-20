#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wininet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "crypto.h"
#include "common.h"
#include "gui.h" // 引用 GUI 头文件以获取日志窗口句柄

// 链接必要的系统库
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")

// [优化] 全局复用 SSL_CTX，避免每次请求都初始化，显著降低 CPU 占用
// 这是一个生产级优化，避免频繁分配和释放 SSL 上下文
static SSL_CTX* g_utils_ctx = NULL;

// --------------------------------------------------------------------------
// 日志系统实现
// --------------------------------------------------------------------------

void log_msg(const char *format, ...) {
    // 如果未开启日志且不是致命错误，则直接返回
    if (!g_enableLog && strstr(format, "[Fatal]") == NULL) {
        return;
    }

    char buf[2048]; 
    char time_buf[64]; 
    SYSTEMTIME st; 
    
    // 获取本地时间
    GetLocalTime(&st);
    
    // 格式化时间字符串
    snprintf(time_buf, sizeof(time_buf), "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
    
    // 格式化日志内容
    va_list args; 
    va_start(args, format); 
    vsnprintf(buf, sizeof(buf) - 64, format, args); 
    va_end(args);
    
    // 拼接最终日志
    char final_msg[2200]; 
    snprintf(final_msg, sizeof(final_msg), "%s%s\r\n", time_buf, buf);
    
    // 输出到调试器 (DebugView 等工具可见)
    OutputDebugStringA(final_msg);
    
    // 输出到 GUI 日志窗口 (异步发送消息，防止界面卡顿)
    // 需要获取 gui.c 中定义的全局窗口句柄
    extern HWND hLogViewerWnd; 
    
    if (hLogViewerWnd && IsWindow(hLogViewerWnd)) {
        // 转换为宽字符以发送给 Unicode 窗口
        int wLen = MultiByteToWideChar(CP_UTF8, 0, final_msg, -1, NULL, 0);
        wchar_t* wBuf = (wchar_t*)malloc((wLen + 1) * sizeof(wchar_t));
        
        if (wBuf) {
            MultiByteToWideChar(CP_UTF8, 0, final_msg, -1, wBuf, wLen);
            wBuf[wLen] = 0;
            // 发送自定义消息更新 UI，接收方负责 free(wBuf)
            PostMessageW(hLogViewerWnd, WM_LOG_UPDATE, 0, (LPARAM)wBuf);
        }
    }
}

// --------------------------------------------------------------------------
// 文件 IO 操作
// --------------------------------------------------------------------------

BOOL ReadFileToBuffer(const wchar_t* filename, char** buffer, long* size) {
    FILE* f = _wfopen(filename, L"rb");
    if (!f) {
        return FALSE;
    }
    
    // 获取文件大小
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    // 分配内存
    *buffer = (char*)malloc(fsize + 1);
    if (!*buffer) { 
        fclose(f); 
        return FALSE; 
    }
    
    // 读取内容
    fread(*buffer, 1, fsize, f);
    (*buffer)[fsize] = 0; // 确保字符串结束符
    
    if (size) {
        *size = fsize;
    }
    
    fclose(f);
    return TRUE;
}

BOOL WriteBufferToFile(const wchar_t* filename, const char* buffer) {
    FILE* f = _wfopen(filename, L"wb");
    if (!f) {
        return FALSE;
    }
    
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
    char* pEnd;
    
    // 去除头部空白
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
        p++;
    }
    
    if (p > str) {
        memmove(str, p, strlen(p) + 1);
    }
    
    // 去除尾部空白
    pEnd = str + strlen(str) - 1;
    while (pEnd >= str && (*pEnd == ' ' || *pEnd == '\t' || *pEnd == '\r' || *pEnd == '\n')) {
        *pEnd-- = 0;
    }
}

// URL 解码 (%xx -> char)
void UrlDecode(char* dst, const char* src) {
    char a, b;
    while (*src) {
        if ((*src == '%') &&
            ((a = src[1]) && (b = src[2])) &&
            (isxdigit(a) && isxdigit(b))) {
            
            if (a >= 'a') a -= 'a' - 10;
            else if (a >= 'A') a -= 'A' - 10;
            else a -= '0';
            
            if (b >= 'a') b -= 'a' - 10;
            else if (b >= 'A') b -= 'A' - 10;
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

// 简单的查询参数获取 (key=value)
char* GetQueryParam(const char* query, const char* key) {
    if (!query || !key) return NULL;
    
    char search[128];
    snprintf(search, sizeof(search), "%s=", key);
    
    const char* p = strstr(query, search);
    if (!p) return NULL;
    
    // 防止匹配到类似 "abckey=" 的情况，确保是完整单词或开头
    if (p != query && *(p-1) != '&' && *(p-1) != '?') {
        return NULL; 
    }
    
    p += strlen(search);
    const char* end = strchr(p, '&');
    int len = end ? (int)(end - p) : (int)strlen(p);
    
    char* val = (char*)malloc(len + 1);
    if (!val) return NULL;
    
    strncpy(val, p, len);
    val[len] = 0;
    
    return val;
}

// --------------------------------------------------------------------------
// Base64 解码实现
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
    
    // 估算输出大小 (Base64 大约是原数据的 4/3)
    size_t out_size = len / 4 * 3;
    unsigned char* out = (unsigned char*)malloc(out_size + 1);
    
    if (!out) {
        return NULL;
    }
    
    size_t i = 0, j = 0;
    while (i < len) {
        // 跳过换行符
        if (input[i] == '\r' || input[i] == '\n') { 
            i++; 
            continue; 
        } 
        
        // 结束标志
        if (input[i] == '=') break; 
        
        unsigned char a = (unsigned char)input[i];
        unsigned char b = (unsigned char)input[i+1];
        unsigned char c = (unsigned char)input[i+2];
        unsigned char d = (unsigned char)input[i+3];
        
        // 边界检查与非法字符检查
        if (i + 1 >= len) break;
        if (a > 127 || b64_table[a] == -1) break;
        if (b > 127 || b64_table[b] == -1) break;
        
        uint32_t n = (b64_table[a] << 18) | (b64_table[b] << 12);
        out[j++] = (n >> 16) & 0xFF;
        
        if (i + 2 < len && c != '=' && c < 128 && b64_table[c] != -1) {
            n |= (b64_table[c] << 6);
            out[j++] = (n >> 8) & 0xFF;
            
            if (i + 3 < len && d != '=' && d < 128 && b64_table[d] != -1) {
                n |= b64_table[d];
                out[j++] = n & 0xFF;
            }
        }
        i += 4;
    }
    
    out[j] = 0;
    if (out_len) {
        *out_len = j;
    }
    return out;
}

// --------------------------------------------------------------------------
// 网络请求与 HTTPS 实现
// --------------------------------------------------------------------------

typedef struct {
    char host[256];
    int port;
    char path[1024];
} URL_COMPONENTS_SIMPLE;

static BOOL ParseUrl(const char* url, URL_COMPONENTS_SIMPLE* out) {
    if (!url || !out) return FALSE;
    memset(out, 0, sizeof(URL_COMPONENTS_SIMPLE));
    
    const char* p = url;
    if (strncmp(p, "http://", 7) == 0) { 
        p += 7; 
        out->port = 80; 
    }
    else if (strncmp(p, "https://", 8) == 0) { 
        p += 8; 
        out->port = 443; 
    }
    else {
        return FALSE; // 暂不支持其他协议
    }
    
    const char* slash = strchr(p, '/');
    int hostLen = slash ? (int)(slash - p) : (int)strlen(p);
    
    if (hostLen >= sizeof(out->host)) {
        return FALSE;
    }
    
    strncpy(out->host, p, hostLen);
    out->host[hostLen] = 0;
    
    char* colon = strchr(out->host, ':');
    if (colon) {
        *colon = 0;
        out->port = atoi(colon + 1);
    }
    
    if (slash) {
        if (strlen(slash) >= sizeof(out->path)) {
            return FALSE;
        }
        strcpy(out->path, slash);
    } else {
        strcpy(out->path, "/");
    }
    return TRUE;
}

// [优化] 内部 HTTPS GET 实现 (使用全局 CTX + SNI)
// 包含完整的 DNS 解析、Socket 连接、SSL 握手和 HTTP 协议处理
static char* InternalHttpsGet(const char* url) {
    URL_COMPONENTS_SIMPLE u;
    if (!ParseUrl(url, &u)) {
        log_msg("[Utils] Invalid URL format: %s", url);
        return NULL;
    }

    // [优化点] 惰性初始化全局工具 CTX
    if (!g_utils_ctx) {
        g_utils_ctx = SSL_CTX_new(TLS_client_method());
        if (!g_utils_ctx) {
             log_msg("[Utils] SSL_CTX init failed");
             return NULL;
        }
        // 订阅下载通常不进行严格的证书校验 (兼容自签名或 CDN)
        SSL_CTX_set_verify(g_utils_ctx, SSL_VERIFY_NONE, NULL);
    }

    SOCKET s = INVALID_SOCKET;
    SSL *ssl = NULL;
    char* result = NULL;
    struct addrinfo hints, *res = NULL;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // 支持 IPv4/IPv6
    hints.ai_socktype = SOCK_STREAM;
    
    char portStr[16]; 
    snprintf(portStr, 16, "%d", u.port);
    
    // 1. DNS 解析
    if (getaddrinfo(u.host, portStr, &hints, &res) != 0) {
        log_msg("[Utils] DNS resolution failed: %s", u.host);
        return NULL;
    }
    
    // 2. 创建 Socket
    s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) {
        freeaddrinfo(res);
        log_msg("[Utils] Socket creation failed");
        return NULL;
    }
    
    // 设置超时 (5秒)，防止网络卡死
    DWORD timeout = 5000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    // 3. 建立 TCP 连接
    if (connect(s, res->ai_addr, (int)res->ai_addrlen) != 0) {
        log_msg("[Utils] Connection failed: %s", u.host);
        closesocket(s);
        freeaddrinfo(res);
        return NULL;
    }
    freeaddrinfo(res);

    // 4. 初始化 SSL 对象
    ssl = SSL_new(g_utils_ctx);
    if (!ssl) { 
        closesocket(s); 
        return NULL; 
    }
    
    SSL_set_fd(ssl, (int)s);
    
    // [关键修复] 设置 SNI (Server Name Indication)
    // 这是访问 Cloudflare 等 CDN 后端服务的必要条件
    SSL_set_tlsext_host_name(ssl, u.host);

    // 5. 执行 SSL 握手
    if (SSL_connect(ssl) != 1) {
        log_msg("[Utils] SSL Handshake failed: %s", u.host);
        goto cleanup;
    }

    // 6. 发送 HTTP GET 请求
    char req[2048];
    snprintf(req, sizeof(req), 
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: Mandala-Client/1.0\r\n"
        "Connection: close\r\n\r\n", 
        u.path, u.host);
        
    if (SSL_write(ssl, req, strlen(req)) <= 0) {
        log_msg("[Utils] Failed to send request");
        goto cleanup;
    }

    // 7. 读取响应数据
    int total_cap = 65536; // 初始分配 64KB
    int total_len = 0;
    char* buf = (char*)malloc(total_cap);
    
    if (!buf) {
        goto cleanup;
    }

    while (1) {
        // 检查缓冲区是否需要扩容
        if (total_len >= total_cap - 1024) {
            total_cap *= 2;
            char* new_buf = (char*)realloc(buf, total_cap);
            if (!new_buf) { 
                free(buf); 
                buf = NULL; 
                goto cleanup; 
            }
            buf = new_buf;
        }
        
        int n = SSL_read(ssl, buf + total_len, total_cap - total_len - 1);
        if (n <= 0) {
            break; // 读取完毕或出错
        }
        total_len += n;
    }
    
    if (buf) {
        buf[total_len] = 0; // 确保以 Null 结尾
    }

    // 8. 解析 HTTP Body (跳过 Header)
    char* body = strstr(buf, "\r\n\r\n");
    if (body) {
        body += 4;
        result = strdup(body);
        free(buf);
    } else {
        // 如果没找到头分隔符，可能只有 body 或者数据异常，这里选择返回全部数据
        result = buf; 
    }

cleanup:
    // 清理资源
    if (ssl) { 
        SSL_shutdown(ssl); 
        SSL_free(ssl); 
    }
    if (s != INVALID_SOCKET) {
        closesocket(s);
    }
    // [注意] g_utils_ctx 不释放，留给下次复用
    
    return result;
}

char* Utils_HttpGet(const char* url) {
    if (!url || strncmp(url, "http", 4) != 0) {
        return NULL;
    }
    return InternalHttpsGet(url);
}

// --------------------------------------------------------------------------
// 剪贴板操作
// --------------------------------------------------------------------------

char* GetClipboardText() {
    if (!OpenClipboard(NULL)) {
        return NULL;
    }
    
    HANDLE hData = GetClipboardData(CF_TEXT);
    if (!hData) { 
        CloseClipboard(); 
        return NULL; 
    }
    
    char* pszText = (char*)GlobalLock(hData);
    if (!pszText) { 
        CloseClipboard(); 
        return NULL; 
    }
    
    char* text = strdup(pszText);
    
    GlobalUnlock(hData);
    CloseClipboard();
    
    return text;
}

// --------------------------------------------------------------------------
// 系统代理设置 (注册表操作)
// --------------------------------------------------------------------------

void SetSystemProxy(BOOL enable) {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 
        0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        
        DWORD dwEnable = enable ? 1 : 0;
        RegSetValueExW(hKey, L"ProxyEnable", 0, REG_DWORD, (BYTE*)&dwEnable, sizeof(DWORD));
        
        if (enable) {
            // 从 common.h 或 globals.c 获取 g_localPort
            extern int g_localPort; 
            wchar_t server[64];
            swprintf_s(server, 64, L"127.0.0.1:%d", g_localPort);
            RegSetValueExW(hKey, L"ProxyServer", 0, REG_SZ, (BYTE*)server, (wcslen(server)+1)*sizeof(wchar_t));
        }
        
        RegCloseKey(hKey);
        
        // 通知系统设置已更改，使其立即生效
        InternetSetOption(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
        InternetSetOption(NULL, INTERNET_OPTION_REFRESH, NULL, 0);
    }
}

BOOL IsSystemProxyEnabled() {
    BOOL enabled = FALSE;
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        DWORD dwValue = 0;
        DWORD dwSize = sizeof(DWORD);
        
        if (RegQueryValueExW(hKey, L"ProxyEnable", NULL, NULL, (BYTE*)&dwValue, &dwSize) == ERROR_SUCCESS) {
            enabled = (dwValue == 1);
        }
        
        RegCloseKey(hKey);
    }
    return enabled;
}

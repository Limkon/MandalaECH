// 强制定义 Unicode
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#define _WIN32_IE 0x0601
#define _WIN32_WINNT 0x0601
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <shellapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <commctrl.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <time.h>
#include <ctype.h>

// --- OpenSSL ---
#include <openssl/ssl.h>
#include <openssl/err.h>

// --- cJSON ---
#include "cJSON.c" 

// =================================================================================
//  1. 结构体定义 (必须置顶)
// =================================================================================

typedef struct { 
    SOCKET sock; 
    SSL *ssl; 
} TLSContext;

typedef struct {
    char host[256];
    int port;
    char path[256];
    char sni[256];
    char user[128];
    char pass[128];
} ProxyConfig;

// =================================================================================
//  2. 宏与全局变量
// =================================================================================

#define WM_TRAY (WM_USER + 1)
#define WM_LOG_UPDATE (WM_USER + 2)

#define ID_TRAY_EXIT 1001
#define ID_TRAY_AUTORUN 1002
#define ID_TRAY_SYSTEM_PROXY 1003
#define ID_TRAY_MANAGE_NODES 1006
#define ID_TRAY_SHOW_CONSOLE 1007
#define ID_TRAY_IMPORT_CLIPBOARD 1008
#define ID_TRAY_HIDE_ICON 1009
#define ID_TRAY_SETTINGS 1010
#define ID_GLOBAL_HOTKEY 9001
#define ID_TRAY_NODE_BASE 2000

#define ID_LOGVIEWER_EDIT 6001
#define ID_NODEMGR_LIST 3001
#define ID_NODEMGR_DEL 3002

// 设置窗口控件
#define ID_HOTKEY_CTRL 7001 
#define ID_PORT_EDIT   7002

#define BUFFER_SIZE 131072 
#define CONFIG_FILE L"config.json"

// 全局状态
ProxyConfig g_proxyConfig;
volatile BOOL g_proxyRunning = FALSE;
SOCKET g_listen_sock = INVALID_SOCKET;
SSL_CTX *g_ssl_ctx = NULL;
HANDLE hProxyThread = NULL;

// GUI 句柄
NOTIFYICONDATAW nid;
HWND hwnd;
HMENU hMenu, hNodeSubMenu;
HWND hLogViewerWnd = NULL;
HFONT hLogFont = NULL;
wchar_t** nodeTags = NULL;
int nodeCount = 0;
wchar_t currentNode[64] = L"";
BOOL g_isIconVisible = TRUE;

// 配置项
wchar_t g_iniFilePath[MAX_PATH] = {0};
UINT g_hotkeyModifiers = MOD_CONTROL | MOD_ALT; 
UINT g_hotkeyVk = 'H';                          
int g_localPort = 1080; // 本地代理端口

// Base64 表
static const unsigned char base64_table[256] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,62,0,0,0,63,52,53,54,55,56,57,58,59,60,61,0,0,0,0,0,0,
    0,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,0,0,0,0,0,
    0,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51
};

// =================================================================================
//  3. 函数前置声明
// =================================================================================

void log_msg(const char *format, ...);
char* GetClipboardText(); 
void TrimString(char* str);
void init_openssl_global();
int tls_init_connect(TLSContext *ctx);
int tls_write(TLSContext *ctx, const char *data, int len);
int tls_read(TLSContext *ctx, char *out, int max);
void tls_close(TLSContext *ctx);
void StartProxyCore();
void StopProxyCore();
void ParseTags();
void SwitchNode(const wchar_t* tag);
BOOL AddNodeToConfig(cJSON* newNode);
BOOL ImportFromClipboard();
void OpenLogViewer();
void OpenNodeManager();
void OpenSettingsWindow();
void ToggleTrayIcon();
void SetAutorun(BOOL enable);
BOOL IsAutorun();
void LoadSettings();
void SaveSettings();
unsigned char* Base64Decode(const char* src, size_t* out_len);
void UrlDecode(char* dst, const char* src);
char* GetQueryParam(const char* query, const char* key);

// =================================================================================
//  4. 工具函数
// =================================================================================

void log_msg(const char *format, ...) {
    char buf[2048];
    char time_buf[64];
    SYSTEMTIME st; GetLocalTime(&st);
    sprintf(time_buf, "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
    
    va_list args; va_start(args, format);
    vsnprintf(buf, sizeof(buf) - 64, format, args);
    va_end(args);
    
    char final_msg[2200];
    snprintf(final_msg, sizeof(final_msg), "%s%s\r\n", time_buf, buf);
    OutputDebugStringA(final_msg);

    if (hLogViewerWnd != NULL && IsWindow(hLogViewerWnd)) {
        int wideLen = MultiByteToWideChar(CP_UTF8, 0, final_msg, -1, NULL, 0);
        if (wideLen > 0) {
            wchar_t* pWideBuf = (wchar_t*)malloc(wideLen * sizeof(wchar_t));
            if (pWideBuf) {
                MultiByteToWideChar(CP_UTF8, 0, final_msg, -1, pWideBuf, wideLen);
                PostMessageW(hLogViewerWnd, WM_LOG_UPDATE, 0, (LPARAM)pWideBuf);
            }
        }
    }
}

UINT HotkeyfToMod(UINT flags) {
    UINT mods = 0;
    if (flags & HOTKEYF_ALT) mods |= MOD_ALT;
    if (flags & HOTKEYF_CONTROL) mods |= MOD_CONTROL;
    if (flags & HOTKEYF_SHIFT) mods |= MOD_SHIFT;
    if (flags & HOTKEYF_EXT) mods |= MOD_WIN;
    return mods;
}

void LoadSettings() {
    g_hotkeyModifiers = GetPrivateProfileIntW(L"Settings", L"Modifiers", MOD_CONTROL | MOD_ALT, g_iniFilePath);
    g_hotkeyVk = GetPrivateProfileIntW(L"Settings", L"VK", 'H', g_iniFilePath);
    g_localPort = GetPrivateProfileIntW(L"Settings", L"LocalPort", 1080, g_iniFilePath);
}

void SaveSettings() {
    wchar_t buffer[16];
    wsprintfW(buffer, L"%u", g_hotkeyModifiers);
    WritePrivateProfileStringW(L"Settings", L"Modifiers", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%u", g_hotkeyVk);
    WritePrivateProfileStringW(L"Settings", L"VK", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_localPort);
    WritePrivateProfileStringW(L"Settings", L"LocalPort", buffer, g_iniFilePath);
}

unsigned char* Base64Decode(const char* src, size_t* out_len) {
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
    out[*out_len] = '\0';
    return out;
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
    char* p = str;
    while(isspace((unsigned char)*p)) p++;
    if(p != str) memmove(str, p, strlen(p)+1);
    size_t len = strlen(str);
    while(len > 0 && isspace((unsigned char)str[len-1])) str[--len] = 0;
}

char* GetClipboardText() {
    if (!OpenClipboard(NULL)) return NULL;
    HANDLE hData = GetClipboardData(CF_UNICODETEXT);
    if (hData != NULL) {
        wchar_t* pszTextW = (wchar_t*)GlobalLock(hData);
        if (pszTextW != NULL) {
            int utf8Len = WideCharToMultiByte(CP_UTF8, 0, pszTextW, -1, NULL, 0, NULL, NULL);
            char* text = (char*)malloc(utf8Len);
            WideCharToMultiByte(CP_UTF8, 0, pszTextW, -1, text, utf8Len, NULL, NULL);
            GlobalUnlock(hData); CloseClipboard(); TrimString(text);
            return text;
        }
    }
    hData = GetClipboardData(CF_TEXT);
    if (hData != NULL) {
        char* pszText = (char*)GlobalLock(hData);
        if (pszText != NULL) {
            char* text = strdup(pszText);
            GlobalUnlock(hData); CloseClipboard(); TrimString(text);
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

void ToggleTrayIcon() {
    if (g_isIconVisible) {
        Shell_NotifyIconW(NIM_DELETE, &nid);
        g_isIconVisible = FALSE;
    } else {
        Shell_NotifyIconW(NIM_ADD, &nid);
        g_isIconVisible = TRUE;
    }
}

// =================================================================================
//  5. 文件与配置
// =================================================================================

BOOL ReadFileToBuffer(const wchar_t* filename, char** buffer, long* fileSize) {
    FILE* f = NULL;
    if (_wfopen_s(&f, filename, L"rb") != 0 || !f) { *fileSize=0; return FALSE; }
    fseek(f, 0, SEEK_END); *fileSize = ftell(f); fseek(f, 0, SEEK_SET);
    *buffer = (char*)malloc(*fileSize + 1);
    fread(*buffer, 1, *fileSize, f); (*buffer)[*fileSize] = 0;
    fclose(f); return TRUE;
}

BOOL WriteBufferToFile(const wchar_t* filename, const char* buffer) {
    FILE* f = NULL;
    if (_wfopen_s(&f, filename, L"wb") != 0 || !f) return FALSE;
    fwrite(buffer, 1, strlen(buffer), f);
    fclose(f); return TRUE;
}

BOOL AddNodeToConfig(cJSON* newNode) {
    char* buffer = NULL; long size = 0;
    cJSON* root = NULL;
    if (ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) { root = cJSON_Parse(buffer); free(buffer); }
    if (!root) { root = cJSON_CreateObject(); cJSON_AddItemToObject(root, "outbounds", cJSON_CreateArray()); }
    
    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    if (!outbounds) { outbounds = cJSON_CreateArray(); cJSON_AddItemToObject(root, "outbounds", outbounds); }
    
    cJSON *item = NULL; cJSON *newTag = cJSON_GetObjectItem(newNode, "tag");
    BOOL dup = FALSE;
    if(newTag) {
        cJSON_ArrayForEach(item, outbounds) {
            cJSON *t = cJSON_GetObjectItem(item, "tag");
            if(t && strcmp(t->valuestring, newTag->valuestring) == 0) { dup=TRUE; break; }
        }
    }
    if(!dup) cJSON_AddItemToArray(outbounds, newNode);
    else cJSON_Delete(newNode);
    
    char* out = cJSON_Print(root);
    BOOL ret = WriteBufferToFile(CONFIG_FILE, out);
    free(out); cJSON_Delete(root);
    return ret;
}

void SetAutorun(BOOL enable) {
    HKEY hKey;
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        if (enable) RegSetValueExW(hKey, L"MyProxyClient", 0, REG_SZ, (BYTE*)path, (wcslen(path)+1)*sizeof(wchar_t));
        else RegDeleteValueW(hKey, L"MyProxyClient");
        RegCloseKey(hKey);
    }
}

BOOL IsAutorun() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, L"MyProxyClient", NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            RegCloseKey(hKey); return TRUE;
        }
        RegCloseKey(hKey);
    }
    return FALSE;
}

// =================================================================================
//  6. 解析逻辑
// =================================================================================

cJSON* ParseSocks(const char* link) {
    if (strncmp(link, "socks://", 8) != 0) return NULL;
    const char* p = link + 8;
    const char* at = strchr(p, '@'); if (!at) return NULL; 

    int authLen = (int)(at - p);
    char* authBase64 = (char*)malloc(authLen + 1); strncpy(authBase64, p, authLen); authBase64[authLen] = 0;
    size_t decLen; unsigned char* decoded = Base64Decode(authBase64, &decLen); free(authBase64);
    if (!decoded) return NULL;
    char* user = (char*)decoded; char* pass = strchr(user, ':');
    if (pass) { *pass = 0; pass++; } else { pass = ""; }

    p = at + 1;
    const char* colon = strchr(p, ':'); const char* qMark = strchr(p, '?'); const char* hash = strchr(p, '#');
    const char* portStart = colon ? colon + 1 : NULL;
    const char* hostEnd = colon ? colon : (qMark ? qMark : (hash ? hash : p + strlen(p)));
    
    int hostLen = (int)(hostEnd - p); char* host = (char*)malloc(hostLen + 1); strncpy(host, p, hostLen); host[hostLen] = 0;
    int portNum = portStart ? atoi(portStart) : 443;

    char* tag = NULL;
    if (hash) { tag = (char*)malloc(strlen(hash+1)+1); UrlDecode(tag, hash+1); } 
    else tag = strdup("Socks-Import");

    const char* query = qMark ? qMark + 1 : NULL;
    char* sni = GetQueryParam(query, "sni");
    char* path = GetQueryParam(query, "path"); 
    char* transport = GetQueryParam(query, "transport");

    cJSON* outbound = cJSON_CreateObject();
    cJSON_AddStringToObject(outbound, "type", "socks_tls");
    cJSON_AddStringToObject(outbound, "tag", tag);
    cJSON_AddStringToObject(outbound, "server", host);
    cJSON_AddNumberToObject(outbound, "server_port", portNum);
    cJSON_AddStringToObject(outbound, "username", user);
    cJSON_AddStringToObject(outbound, "password", pass);

    if (sni) {
        cJSON* tls = cJSON_CreateObject();
        cJSON_AddStringToObject(tls, "server_name", sni);
        cJSON_AddItemToObject(outbound, "tls", tls);
        free(sni);
    }
    
    if (transport && strcmp(transport, "ws") == 0) {
        cJSON* trans = cJSON_CreateObject();
        cJSON_AddStringToObject(trans, "type", "ws");
        if (path) cJSON_AddStringToObject(trans, "path", path);
        if (sni) { 
             cJSON* headers = cJSON_CreateObject(); cJSON_AddStringToObject(headers, "Host", host); 
             cJSON_AddItemToObject(trans, "headers", headers);
        }
        cJSON_AddItemToObject(outbound, "transport", trans);
    }
    if (path) free(path); if (transport) free(transport);
    free(host); free(tag); free(decoded);
    return outbound;
}

cJSON* ParseVmess(const char* link) {
    if (strncmp(link, "vmess://", 8) != 0) return NULL;
    size_t len; unsigned char* decoded = Base64Decode(link + 8, &len);
    if (!decoded) return NULL;
    cJSON* vmessJson = cJSON_Parse((const char*)decoded); free(decoded);
    if (!vmessJson) return NULL;

    cJSON* outbound = cJSON_CreateObject();
    cJSON_AddStringToObject(outbound, "type", "vmess");
    cJSON* ps = cJSON_GetObjectItem(vmessJson, "ps");
    cJSON* add = cJSON_GetObjectItem(vmessJson, "add");
    cJSON* port = cJSON_GetObjectItem(vmessJson, "port");
    cJSON* id = cJSON_GetObjectItem(vmessJson, "id");
    cJSON* net = cJSON_GetObjectItem(vmessJson, "net");
    cJSON* host = cJSON_GetObjectItem(vmessJson, "host");
    cJSON* path = cJSON_GetObjectItem(vmessJson, "path");
    cJSON* tls = cJSON_GetObjectItem(vmessJson, "tls");
    cJSON* sni = cJSON_GetObjectItem(vmessJson, "sni");

    cJSON_AddStringToObject(outbound, "tag", cJSON_IsString(ps) ? ps->valuestring : "VMess");
    cJSON_AddStringToObject(outbound, "server", cJSON_IsString(add) ? add->valuestring : "");
    cJSON_AddNumberToObject(outbound, "server_port", cJSON_IsNumber(port)?port->valueint:atoi(port->valuestring));
    cJSON_AddStringToObject(outbound, "uuid", cJSON_IsString(id) ? id->valuestring : "");

    if (cJSON_IsString(net) && strcmp(net->valuestring, "ws") == 0) {
        cJSON* t = cJSON_CreateObject();
        cJSON_AddStringToObject(t, "type", "ws");
        if(cJSON_IsString(path)) cJSON_AddStringToObject(t, "path", path->valuestring);
        cJSON_AddItemToObject(outbound, "transport", t);
    } 
    if ((cJSON_IsString(tls) && strcmp(tls->valuestring, "tls") == 0)) {
        cJSON* t = cJSON_CreateObject();
        cJSON_AddBoolToObject(t, "enabled", cJSON_True);
        cJSON_AddStringToObject(t, "server_name", cJSON_IsString(sni)&&strlen(sni->valuestring)>0 ? sni->valuestring : (cJSON_IsString(host)?host->valuestring:""));
        cJSON_AddItemToObject(outbound, "tls", t);
    }
    cJSON_Delete(vmessJson); return outbound;
}

cJSON* ParseVlessOrTrojan(const char* link) { return NULL; } 
cJSON* ParseShadowsocks(const char* link) { return NULL; }

BOOL ImportFromClipboard() {
    char* text = GetClipboardText();
    if (!text) return FALSE;
    cJSON* node = NULL;
    if (strncmp(text, "socks://", 8) == 0) node = ParseSocks(text);
    else if (strncmp(text, "vmess://", 8) == 0) node = ParseVmess(text);
    free(text);
    if (node) { return AddNodeToConfig(node); }
    return FALSE;
}

// =================================================================================
//  7. OpenSSL Core
// =================================================================================

void init_openssl_global() {
    if (g_ssl_ctx) return;
    SSL_library_init(); OpenSSL_add_all_algorithms(); SSL_load_error_strings();
    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_ssl_ctx) return;
    SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_1_VERSION);
    SSL_CTX_set_max_proto_version(g_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);
}

int tls_init_connect(TLSContext *ctx) {
    if (!ctx || !g_ssl_ctx) return -1;
    ctx->ssl = SSL_new(g_ssl_ctx);
    if (!ctx->ssl) return -1;
    SSL_set_fd(ctx->ssl, ctx->sock);
    const char *sni_name = (strlen(g_proxyConfig.sni) ? g_proxyConfig.sni : g_proxyConfig.host);
    SSL_set_tlsext_host_name(ctx->ssl, sni_name);
    return (SSL_connect(ctx->ssl) == 1) ? 0 : -1;
}

int tls_write(TLSContext *ctx, const char *data, int len) {
    if (!ctx->ssl) return -1;
    return (SSL_write(ctx->ssl, data, len) <= 0) ? -1 : len;
}

int tls_read(TLSContext *ctx, char *out, int max) {
    if (!ctx->ssl) return -1;
    int ret = SSL_read(ctx->ssl, out, max);
    if (ret <= 0) {
        int err = SSL_get_error(ctx->ssl, ret);
        if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return 0;
        return -1;
    }
    return ret;
}

void tls_close(TLSContext *ctx) {
    if (ctx->ssl) { SSL_shutdown(ctx->ssl); SSL_free(ctx->ssl); ctx->ssl = NULL; }
}

int build_ws_frame(const char *in, int len, char *out) {
    out[0] = 0x82; uint8_t mask[4]; *(uint32_t*)mask = GetTickCount(); 
    if (len < 126) { out[1] = 0x80 | len; memcpy(out+2, mask, 4); for(int i=0;i<len;i++) out[6+i] = in[i]^mask[i%4]; return 6+len; } 
    else if (len <= 65535) { out[1] = 0x80 | 126; out[2] = (len>>8)&0xFF; out[3] = len&0xFF; memcpy(out+4, mask, 4); for(int i=0;i<len;i++) out[8+i] = in[i]^mask[i%4]; return 8+len; }
    return -1; 
}

int check_ws_frame(unsigned char *in, int len, int *head_len, int *payload_len) {
    if(len < 2) return 0;
    int hl = 2; int pl = in[1] & 0x7F;
    if (pl == 126) { if (len < 4) return 0; hl = 4; pl = (in[2] << 8) | in[3]; } 
    else if (pl == 127) { if (len < 10) return 0; hl = 10; pl = 65536; }
    if (len < hl + pl) return 0;
    *head_len = hl; *payload_len = pl;
    return hl + pl; 
}

int recv_timeout(SOCKET s, char *buf, int len, int timeout_sec) {
    fd_set fds; FD_ZERO(&fds); FD_SET(s, &fds);
    struct timeval tv = { timeout_sec, 0 };
    int n = select(0, &fds, NULL, NULL, &tv);
    if (n == 0) return -2; if (n < 0) return -1;  
    return recv(s, buf, len, 0);
}

DWORD WINAPI client_handler(LPVOID p) {
    SOCKET c = (SOCKET)(UINT_PTR)p;
    TLSContext tls; memset(&tls, 0, sizeof(tls));
    SOCKET r = INVALID_SOCKET;
    char *c_buf = (char*)malloc(BUFFER_SIZE); 
    char *ws_read_buf = (char*)malloc(BUFFER_SIZE); 
    char *ws_send_buf = (char*)malloc(BUFFER_SIZE);
    
    if (!c_buf || !ws_read_buf || !ws_send_buf) { goto cl_end; }

    int ws_buf_len = 0; 
    int flag = 1; 
    setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

    r = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(r, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
    struct hostent *h = gethostbyname(g_proxyConfig.host);
    if(!h) { log_msg("DNS Fail: %s", g_proxyConfig.host); goto cl_end; }
    
    struct sockaddr_in a; memset(&a, 0, sizeof(a)); a.sin_family = AF_INET; a.sin_port = htons((unsigned short)g_proxyConfig.port);
    a.sin_addr = *(struct in_addr*)h->h_addr;

    if (connect(r, (struct sockaddr*)&a, sizeof(a)) != 0) { log_msg("Connect Fail"); goto cl_end; }

    tls.sock = r;
    if (tls_init_connect(&tls) != 0) goto cl_end;

    const char* request_host = (strlen(g_proxyConfig.sni) > 0) ? g_proxyConfig.sni : g_proxyConfig.host;
    snprintf(c_buf, BUFFER_SIZE, 
        "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "User-Agent: Mozilla/5.0\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", 
        g_proxyConfig.path, request_host);
    if (tls_write(&tls, c_buf, (int)strlen(c_buf)) < 0) goto cl_end;

    int len = tls_read(&tls, c_buf, BUFFER_SIZE-1);
    if (len <= 0) goto cl_end;
    c_buf[len] = 0;
    if (!strstr(c_buf, "101 Switching Protocols")) goto cl_end;

    char auth[] = {0x05, 0x01, 0x02}; 
    int flen = build_ws_frame(auth, 3, ws_send_buf);
    tls_write(&tls, ws_send_buf, flen);
    len = tls_read(&tls, ws_read_buf, BUFFER_SIZE);
    if (len <= 0) goto cl_end;
    ws_buf_len = len;

    int hl, pl;
    int frame_total = check_ws_frame((unsigned char*)ws_read_buf, ws_buf_len, &hl, &pl);
    if (frame_total > 0) {
        memmove(ws_read_buf, ws_read_buf + frame_total, ws_buf_len - frame_total);
        ws_buf_len -= frame_total;
    }

    char up[512]; int idx = 0;
    up[idx++] = 1; up[idx++] = (char)strlen(g_proxyConfig.user); memcpy(up+idx, g_proxyConfig.user, strlen(g_proxyConfig.user)); idx += (int)strlen(g_proxyConfig.user);
    up[idx++] = (char)strlen(g_proxyConfig.pass); memcpy(up+idx, g_proxyConfig.pass, strlen(g_proxyConfig.pass)); idx += (int)strlen(g_proxyConfig.pass);
    flen = build_ws_frame(up, idx, ws_send_buf);
    tls_write(&tls, ws_send_buf, flen);

    while (1) {
        frame_total = check_ws_frame((unsigned char*)ws_read_buf, ws_buf_len, &hl, &pl);
        if (frame_total > 0) {
            memmove(ws_read_buf, ws_read_buf + frame_total, ws_buf_len - frame_total);
            ws_buf_len -= frame_total;
            break; 
        }
        len = tls_read(&tls, ws_read_buf + ws_buf_len, BUFFER_SIZE - ws_buf_len);
        if (len <= 0) goto cl_end;
        ws_buf_len += len;
    }

    len = recv_timeout(c, c_buf, BUFFER_SIZE, 10); 
    if (len > 0) {
        if (c_buf[0] == 0x05) { 
            send(c, "\x05\x00", 2, 0); 
            len = recv_timeout(c, c_buf, BUFFER_SIZE, 10);
            if (len > 0) {
                flen = build_ws_frame(c_buf, len, ws_send_buf);
                tls_write(&tls, ws_send_buf, flen);
            } else goto cl_end;
        } 
        else if (c_buf[0] == 'C' || c_buf[0] == 'G' || c_buf[0] == 'P') { 
            c_buf[len] = 0;
            char method[16], host[256]; int port = 80;
            if (sscanf(c_buf, "%15s %255s", method, host) == 2) {
                char *p = strchr(host, ':');
                if (p) { *p = 0; port = atoi(p+1); }
                else if(stricmp(method, "CONNECT")==0) port = 443;

                unsigned char socks_req[512]; int slen = 0;
                socks_req[slen++] = 0x05; socks_req[slen++] = 0x01; socks_req[slen++] = 0x00; socks_req[slen++] = 0x03;
                socks_req[slen++] = (unsigned char)strlen(host);
                memcpy(socks_req + slen, host, strlen(host)); slen += (int)strlen(host);
                socks_req[slen++] = (port >> 8) & 0xFF; socks_req[slen++] = port & 0xFF;

                flen = build_ws_frame((char*)socks_req, slen, ws_send_buf);
                tls_write(&tls, ws_send_buf, flen);

                if (stricmp(method, "CONNECT") == 0) {
                    const char *ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
                    send(c, ok, strlen(ok), 0);
                }
            } else goto cl_end;
        } else goto cl_end;

        while (1) {
            frame_total = check_ws_frame((unsigned char*)ws_read_buf, ws_buf_len, &hl, &pl);
            if (frame_total > 0) {
                if (c_buf[0] == 0x05) send(c, ws_read_buf + hl, pl, 0); 
                memmove(ws_read_buf, ws_read_buf + frame_total, ws_buf_len - frame_total);
                ws_buf_len -= frame_total;
                break; 
            }
            len = tls_read(&tls, ws_read_buf + ws_buf_len, BUFFER_SIZE - ws_buf_len);
            if (len <= 0) goto cl_end;
            ws_buf_len += len;
        }
    } else goto cl_end;

    fd_set fds; struct timeval tv;
    u_long mode = 1;
    ioctlsocket(c, FIONBIO, &mode);
    ioctlsocket(r, FIONBIO, &mode);

    while(1) {
        FD_ZERO(&fds); FD_SET(c, &fds); FD_SET(r, &fds);
        int pending = SSL_pending(tls.ssl);
        tv.tv_sec = 1; tv.tv_usec = 0;
        if (pending > 0) { tv.tv_sec = 0; tv.tv_usec = 0; }

        int n = select(0, &fds, NULL, NULL, &tv);
        if (n < 0) break;

        if (FD_ISSET(c, &fds)) {
            len = recv(c, c_buf, BUFFER_SIZE, 0);
            if (len > 0) {
                flen = build_ws_frame(c_buf, len, ws_send_buf);
                if (tls_write(&tls, ws_send_buf, flen) < 0) break;
            } else if (WSAGetLastError() != WSAEWOULDBLOCK) break;
        }

        if (FD_ISSET(r, &fds) || pending > 0) {
            if (ws_buf_len < BUFFER_SIZE) {
                len = tls_read(&tls, ws_read_buf + ws_buf_len, BUFFER_SIZE - ws_buf_len);
                if (len > 0) ws_buf_len += len;
            }
        }
        
        while (ws_buf_len > 0) {
            frame_total = check_ws_frame((unsigned char*)ws_read_buf, ws_buf_len, &hl, &pl);
            if (frame_total > 0) {
                int opcode = ws_read_buf[0] & 0x0F;
                if (opcode == 0x8) goto cl_end; 
                if (opcode == 0x1 || opcode == 0x2) { 
                   if (pl > 0) send(c, ws_read_buf + hl, pl, 0);
                }
                memmove(ws_read_buf, ws_read_buf + frame_total, ws_buf_len - frame_total);
                ws_buf_len -= frame_total;
            } else {
                if (ws_buf_len >= BUFFER_SIZE) goto cl_end;
                break;
            }
        }
    }

cl_end:
    free(c_buf); free(ws_read_buf); free(ws_send_buf);
    tls_close(&tls);
    if (r != INVALID_SOCKET) closesocket(r);
    if (c != INVALID_SOCKET) closesocket(c);
    return 0;
}

DWORD WINAPI server_thread(LPVOID p) {
    init_openssl_global();
    g_listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; addr.sin_port = htons(g_localPort);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    
    int opt = 1;
    setsockopt(g_listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    if (bind(g_listen_sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        log_msg("Port %d bind fail", g_localPort);
        g_proxyRunning = FALSE;
        return 0;
    }
    listen(g_listen_sock, 100);
    log_msg("Proxy Started: 127.0.0.1:%d", g_localPort);
    
    while(g_proxyRunning) {
        SOCKET c = accept(g_listen_sock, NULL, NULL);
        if (c != INVALID_SOCKET) {
            CloseHandle(CreateThread(NULL, 0, client_handler, (LPVOID)(UINT_PTR)c, 0, NULL));
        } else break;
    }
    return 0;
}

void StartProxyCore() {
    if (g_proxyRunning) return;
    g_proxyRunning = TRUE;
    hProxyThread = CreateThread(NULL, 0, server_thread, NULL, 0, NULL);
}

void StopProxyCore() {
    g_proxyRunning = FALSE;
    if (g_listen_sock != INVALID_SOCKET) {
        closesocket(g_listen_sock); 
        g_listen_sock = INVALID_SOCKET;
    }
    if (hProxyThread) {
        WaitForSingleObject(hProxyThread, 2000); 
        CloseHandle(hProxyThread);
        hProxyThread = NULL;
    }
    log_msg("Proxy Stopped");
}

// =================================================================================
//  8. GUI 逻辑
// =================================================================================

void ParseNodeConfigToGlobal(cJSON *node) {
    if (!node) return;
    memset(&g_proxyConfig, 0, sizeof(g_proxyConfig));
    strcpy(g_proxyConfig.path, "/"); 

    cJSON *server = cJSON_GetObjectItem(node, "server");
    cJSON *port = cJSON_GetObjectItem(node, "server_port");
    cJSON *uuid = cJSON_GetObjectItem(node, "uuid");
    if (!uuid) uuid = cJSON_GetObjectItem(node, "password"); 
    
    if (server && server->valuestring) strcpy(g_proxyConfig.host, server->valuestring);
    if (port) g_proxyConfig.port = port->valueint;
    if (uuid && uuid->valuestring) {
        strcpy(g_proxyConfig.user, uuid->valuestring); 
        strcpy(g_proxyConfig.pass, uuid->valuestring); 
    }
    
    cJSON *user = cJSON_GetObjectItem(node, "username");
    cJSON *pass = cJSON_GetObjectItem(node, "password");
    if(user && user->valuestring) strcpy(g_proxyConfig.user, user->valuestring);
    if(pass && pass->valuestring) strcpy(g_proxyConfig.pass, pass->valuestring);

    cJSON *tls = cJSON_GetObjectItem(node, "tls");
    if (tls) {
        cJSON *sni = cJSON_GetObjectItem(tls, "server_name");
        if (sni && sni->valuestring) strcpy(g_proxyConfig.sni, sni->valuestring);
    }
    
    cJSON *trans = cJSON_GetObjectItem(node, "transport");
    if(trans) {
        cJSON *path = cJSON_GetObjectItem(trans, "path");
        if(path && path->valuestring) strcpy(g_proxyConfig.path, path->valuestring);
    }
    
    if (strlen(g_proxyConfig.sni) == 0) strcpy(g_proxyConfig.sni, g_proxyConfig.host);
}

void ParseTags() {
    if (nodeTags) { for(int i=0; i<nodeCount; i++) free(nodeTags[i]); free(nodeTags); }
    nodeCount = 0; nodeTags = NULL;

    char* buffer = NULL; long size = 0;
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) return;
    cJSON* root = cJSON_Parse(buffer); free(buffer);
    if (!root) return;

    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    cJSON* node;
    cJSON_ArrayForEach(node, outbounds) {
        cJSON* tag = cJSON_GetObjectItem(node, "tag");
        if (tag && tag->valuestring) {
            nodeCount++;
            nodeTags = (wchar_t**)realloc(nodeTags, nodeCount * sizeof(wchar_t*));
            int wlen = MultiByteToWideChar(CP_UTF8, 0, tag->valuestring, -1, NULL, 0);
            nodeTags[nodeCount-1] = (wchar_t*)malloc((wlen+1)*sizeof(wchar_t));
            MultiByteToWideChar(CP_UTF8, 0, tag->valuestring, -1, nodeTags[nodeCount-1], wlen+1);
        }
    }
    cJSON_Delete(root);
}

void SwitchNode(const wchar_t* tag) {
    wcsncpy(currentNode, tag, 63);
    char* buffer = NULL; long size = 0;
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) return;
    cJSON* root = cJSON_Parse(buffer); free(buffer);
    if (!root) return;

    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    cJSON* targetNode = NULL;
    char tagUtf8[256];
    WideCharToMultiByte(CP_UTF8, 0, tag, -1, tagUtf8, 256, NULL, NULL);

    cJSON* node;
    cJSON_ArrayForEach(node, outbounds) {
        cJSON* t = cJSON_GetObjectItem(node, "tag");
        if (t && strcmp(t->valuestring, tagUtf8) == 0) {
            targetNode = node; break;
        }
    }

    if (targetNode) {
        StopProxyCore();
        ParseNodeConfigToGlobal(targetNode);
        StartProxyCore();
        
        wchar_t tip[128]; wsprintfW(tip, L"已切换至节点: %s", tag);
        wcsncpy(nid.szInfo, tip, 127);
        wcsncpy(nid.szInfoTitle, L"SOCKS5 Proxy", 63);
        nid.uFlags |= NIF_INFO;
        Shell_NotifyIconW(NIM_MODIFY, &nid);
    }
    cJSON_Delete(root);
}

void DeleteNode(const wchar_t* tag) {
    char* buffer = NULL; long size = 0;
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) return;
    cJSON* root = cJSON_Parse(buffer); free(buffer);
    if (!root) return;

    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    char tagUtf8[256];
    WideCharToMultiByte(CP_UTF8, 0, tag, -1, tagUtf8, 256, NULL, NULL);

    int idx = 0;
    cJSON* node;
    cJSON_ArrayForEach(node, outbounds) {
        cJSON* t = cJSON_GetObjectItem(node, "tag");
        if (t && strcmp(t->valuestring, tagUtf8) == 0) {
            cJSON_DeleteItemFromArray(outbounds, idx);
            break;
        }
        idx++;
    }
    
    char* out = cJSON_Print(root);
    WriteBufferToFile(CONFIG_FILE, out);
    free(out); cJSON_Delete(root);
    ParseTags(); 
}

// 快捷键设置窗口
LRESULT CALLBACK SettingsWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hHotkey, hPortEdit;
    switch(msg) {
        case WM_CREATE:
            CreateWindowW(L"STATIC", L"全局快捷键:", WS_CHILD|WS_VISIBLE, 20,20,150,20, hWnd, NULL,NULL,NULL);
            hHotkey = CreateWindowExW(0, HOTKEY_CLASSW, NULL, WS_CHILD|WS_VISIBLE|WS_BORDER, 20,45,240,25, hWnd, (HMENU)ID_HOTKEY_CTRL, NULL,NULL);
            
            UINT hkMod = 0;
            if (g_hotkeyModifiers & MOD_SHIFT) hkMod |= HOTKEYF_SHIFT;
            if (g_hotkeyModifiers & MOD_CONTROL) hkMod |= HOTKEYF_CONTROL;
            if (g_hotkeyModifiers & MOD_ALT) hkMod |= HOTKEYF_ALT;
            SendMessage(hHotkey, HKM_SETHOTKEY, MAKEWORD(g_hotkeyVk, hkMod), 0);
            
            CreateWindowW(L"STATIC", L"本地代理端口:", WS_CHILD|WS_VISIBLE, 20,80,150,20, hWnd, NULL,NULL,NULL);
            hPortEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", NULL, WS_CHILD|WS_VISIBLE|ES_NUMBER, 20,105,100,25, hWnd, (HMENU)ID_PORT_EDIT, NULL,NULL);
            SetDlgItemInt(hWnd, ID_PORT_EDIT, g_localPort, FALSE);

            CreateWindowW(L"BUTTON", L"确定", WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON, 60,145,80,25, hWnd, (HMENU)IDOK, NULL,NULL);
            CreateWindowW(L"BUTTON", L"取消", WS_CHILD|WS_VISIBLE, 160,145,80,25, hWnd, (HMENU)IDCANCEL, NULL,NULL);
            break;
        case WM_COMMAND:
            if (LOWORD(wParam) == IDOK) {
                // 读取快捷键
                LRESULT res = SendMessage(hHotkey, HKM_GETHOTKEY, 0, 0);
                UINT vk = LOBYTE(res);
                UINT mod = HIBYTE(res);
                UINT newMod = 0;
                if (mod & HOTKEYF_SHIFT) newMod |= MOD_SHIFT;
                if (mod & HOTKEYF_CONTROL) newMod |= MOD_CONTROL;
                if (mod & HOTKEYF_ALT) newMod |= MOD_ALT;
                
                // 读取端口
                BOOL translated;
                int port = GetDlgItemInt(hWnd, ID_PORT_EDIT, &translated, FALSE);
                
                if (port > 0 && port < 65535) {
                    if (g_localPort != port) {
                        g_localPort = port;
                        if(g_proxyRunning) { StopProxyCore(); StartProxyCore(); }
                    }
                }

                if (vk != 0 && newMod != 0) {
                    UnregisterHotKey(hwnd, ID_GLOBAL_HOTKEY);
                    if (RegisterHotKey(hwnd, ID_GLOBAL_HOTKEY, newMod, vk)) {
                        g_hotkeyVk = vk; g_hotkeyModifiers = newMod;
                    }
                }
                SaveSettings();
                DestroyWindow(hWnd);
            } else if (LOWORD(wParam) == IDCANCEL) {
                DestroyWindow(hWnd);
            }
            break;
        case WM_CLOSE: DestroyWindow(hWnd); break;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

void OpenSettingsWindow() {
    WNDCLASSW wc = {0}; wc.lpfnWndProc=SettingsWndProc; wc.hInstance=GetModuleHandle(NULL); wc.lpszClassName=L"Settings"; wc.hbrBackground=(HBRUSH)(COLOR_BTNFACE+1);
    RegisterClassW(&wc);
    HWND hSettings = CreateWindowW(L"Settings", L"程序设置", WS_VISIBLE|WS_CAPTION|WS_SYSMENU, CW_USEDEFAULT,0,300,220, hwnd,NULL,wc.hInstance,NULL);
    ShowWindow(hSettings, SW_SHOW);
}

LRESULT CALLBACK NodeMgrWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hList;
    switch(msg) {
        case WM_CREATE:
            hList = CreateWindowW(L"LISTBOX", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL, 10, 10, 260, 200, hWnd, (HMENU)ID_NODEMGR_LIST, NULL, NULL);
            CreateWindowW(L"BUTTON", L"删除选中", WS_CHILD|WS_VISIBLE, 280, 10, 80, 30, hWnd, (HMENU)ID_NODEMGR_DEL, NULL, NULL);
            ParseTags();
            for(int i=0; i<nodeCount; i++) SendMessageW(hList, LB_ADDSTRING, 0, (LPARAM)nodeTags[i]);
            break;
        case WM_COMMAND:
            if (LOWORD(wParam) == ID_NODEMGR_DEL) {
                int idx = SendMessage(hList, LB_GETCURSEL, 0, 0);
                if (idx != LB_ERR) {
                    wchar_t buf[256];
                    SendMessageW(hList, LB_GETTEXT, idx, (LPARAM)buf);
                    DeleteNode(buf);
                    SendMessage(hList, LB_DELETESTRING, idx, 0);
                }
            }
            break;
        case WM_CLOSE: ShowWindow(hWnd, SW_HIDE); return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

void OpenNodeManager() {
    static HWND hMgr = NULL;
    if (hMgr) { ShowWindow(hMgr, SW_SHOW); return; }
    WNDCLASSW wc = {0}; wc.lpfnWndProc=NodeMgrWndProc; wc.hInstance=GetModuleHandle(NULL); wc.lpszClassName=L"NodeMgr"; wc.hbrBackground=(HBRUSH)(COLOR_BTNFACE+1);
    RegisterClassW(&wc);
    hMgr = CreateWindowW(L"NodeMgr", L"节点管理", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT,0,400,260, NULL,NULL,wc.hInstance,NULL);
    ShowWindow(hMgr, SW_SHOW);
}

LRESULT CALLBACK LogWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hEdit;
    switch(msg) {
        case WM_CREATE:
            hEdit = CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|ES_READONLY, 0,0,0,0, hWnd, (HMENU)ID_LOGVIEWER_EDIT, NULL, NULL);
            SendMessage(hEdit, WM_SETFONT, (WPARAM)hLogFont, 0);
            break;
        case WM_SIZE:
            MoveWindow(hEdit, 0, 0, LOWORD(lParam), HIWORD(lParam), TRUE);
            break;
        case WM_LOG_UPDATE: {
            wchar_t* p = (wchar_t*)lParam;
            int len = GetWindowTextLength(hEdit);
            if (len > 30000) { SendMessage(hEdit, EM_SETSEL, 0, -1); SendMessage(hEdit, WM_CLEAR, 0, 0); }
            SendMessage(hEdit, EM_SETSEL, 0xffff, 0xffff);
            SendMessageW(hEdit, EM_REPLACESEL, 0, (LPARAM)p);
            free(p);
            break;
        }
        case WM_CLOSE: ShowWindow(hWnd, SW_HIDE); return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

void OpenLogViewer() {
    if (hLogViewerWnd) { ShowWindow(hLogViewerWnd, SW_SHOW); return; }
    WNDCLASSW wc = {0}; wc.lpfnWndProc=LogWndProc; wc.hInstance=GetModuleHandle(NULL); wc.lpszClassName=L"LogWnd";
    RegisterClassW(&wc);
    hLogViewerWnd = CreateWindowW(L"LogWnd", L"运行日志", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT,0,600,400, NULL,NULL,wc.hInstance,NULL);
    ShowWindow(hLogViewerWnd, SW_SHOW);
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_TRAY && LOWORD(lParam) == WM_RBUTTONUP) {
        POINT pt; GetCursorPos(&pt);
        SetForegroundWindow(hWnd);
        ParseTags();
        if (hMenu) DestroyMenu(hMenu);
        hMenu = CreatePopupMenu();
        hNodeSubMenu = CreatePopupMenu();
        for(int i=0; i<nodeCount; i++) {
            UINT f = MF_STRING;
            if(wcscmp(nodeTags[i], currentNode)==0) f|=MF_CHECKED;
            AppendMenuW(hNodeSubMenu, f, ID_TRAY_NODE_BASE+i, nodeTags[i]);
        }
        AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hNodeSubMenu, L"切换节点");
        AppendMenuW(hMenu, MF_STRING, ID_TRAY_MANAGE_NODES, L"节点管理");
        AppendMenuW(hMenu, MF_STRING, ID_TRAY_IMPORT_CLIPBOARD, L"剪贴板导入");
        AppendMenuW(hMenu, MF_STRING, ID_TRAY_SETTINGS, L"程序设置");
        AppendMenuW(hMenu, MF_STRING, ID_TRAY_HIDE_ICON, L"隐藏图标");
        AppendMenuW(hMenu, IsAutorun()?MF_CHECKED:MF_UNCHECKED, ID_TRAY_AUTORUN, L"开机自启");
        AppendMenuW(hMenu, MF_STRING, ID_TRAY_SHOW_CONSOLE, L"查看日志");
        AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
        AppendMenuW(hMenu, MF_STRING, ID_TRAY_EXIT, L"退出");
        TrackPopupMenu(hMenu, TPM_RIGHTALIGN|TPM_BOTTOMALIGN, pt.x, pt.y, 0, hWnd, NULL);
    }
    else if (msg == WM_COMMAND) {
        int id = LOWORD(wParam);
        if (id == ID_TRAY_EXIT) { Shell_NotifyIconW(NIM_DELETE, &nid); StopProxyCore(); ExitProcess(0); }
        else if (id == ID_TRAY_SHOW_CONSOLE) OpenLogViewer();
        else if (id == ID_TRAY_MANAGE_NODES) OpenNodeManager();
        else if (id == ID_TRAY_SETTINGS) OpenSettingsWindow();
        else if (id == ID_TRAY_HIDE_ICON) ToggleTrayIcon();
        else if (id == ID_TRAY_AUTORUN) SetAutorun(!IsAutorun());
        else if (id == ID_TRAY_IMPORT_CLIPBOARD) {
            if (ImportFromClipboard()) {
                ParseTags();
                MessageBoxW(hWnd, L"节点导入成功！\n请在“切换节点”中选择使用。", L"成功", MB_OK);
            } else {
                MessageBoxW(hWnd, L"剪贴板中未发现有效的代理链接。\n支持: socks://, vmess://, vless://, trojan://, ss://", L"导入失败", MB_OK|MB_ICONWARNING);
            }
        }
        else if (id >= ID_TRAY_NODE_BASE) SwitchNode(nodeTags[id-ID_TRAY_NODE_BASE]);
    }
    else if (msg == WM_HOTKEY && wParam == ID_GLOBAL_HOTKEY) {
        ToggleTrayIcon();
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, LPWSTR lpCmdLine, int nShow) {
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
    INITCOMMONCONTROLSEX ic = {sizeof(INITCOMMONCONTROLSEX), ICC_HOTKEY_CLASS};
    InitCommonControlsEx(&ic);

    GetModuleFileNameW(NULL, g_iniFilePath, MAX_PATH);
    wchar_t* p = wcsrchr(g_iniFilePath, L'\\');
    if (p) { *p = 0; wcscat(g_iniFilePath, L"\\set.ini"); } 
    else wcscpy(g_iniFilePath, L"set.ini");

    LoadSettings();
    hLogFont = CreateFontW(14,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,0,0,L"Consolas");
    
    WNDCLASSW wc = {0}; 
    wc.lpfnWndProc = WndProc; 
    wc.hInstance = hInst; 
    wc.lpszClassName = L"TrayProxyClass";
    
    // [修复] 加载自定义图标作为窗口图标
    wc.hIcon = LoadIcon(hInst, MAKEINTRESOURCE(1));
    if (!wc.hIcon) wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    
    RegisterClassW(&wc);
    hwnd = CreateWindowW(L"TrayProxyClass", L"App", 0, 0,0,0,0, NULL,NULL,hInst,NULL);
    
    RegisterHotKey(hwnd, ID_GLOBAL_HOTKEY, g_hotkeyModifiers, g_hotkeyVk);

    nid.cbSize = sizeof(nid); 
    nid.hWnd = hwnd; 
    nid.uID = 1;
    nid.uFlags = NIF_ICON|NIF_MESSAGE|NIF_TIP;
    nid.uCallbackMessage = WM_TRAY;
    
    // [修复] 加载自定义图标作为托盘图标
    nid.hIcon = LoadIcon(hInst, MAKEINTRESOURCE(1));
    if (!nid.hIcon) nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    
    wcscpy(nid.szTip, L"SOCKS5 Proxy Client");
    Shell_NotifyIconW(NIM_ADD, &nid);

    ParseTags();
    if (nodeCount > 0) SwitchNode(nodeTags[0]); 

    MSG msg;
    while(GetMessage(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    return 0;
}
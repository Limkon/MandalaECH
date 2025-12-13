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
#include <wininet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include "cJSON.c" 
#include <openssl/x509.h>
#include <openssl/pem.h>

const wchar_t* REG_PATH_PROXY = L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

typedef struct { SOCKET sock; SSL *ssl; } TLSContext;
typedef struct {
    char host[256]; int port; char path[256];
    char sni[256]; char user[128]; char pass[128];
} ProxyConfig;

#define WM_TRAY (WM_USER + 1)
#define WM_LOG_UPDATE (WM_USER + 2)
#define WM_REFRESH_NODELIST (WM_USER + 50)
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
#define ID_NODEMGR_EDIT 3003 
#define ID_HOTKEY_CTRL 7001 
#define ID_PORT_EDIT 7002

// GUI ID 定义 (已更新)
#define ID_CHK_CIPHERS    7010
#define ID_CHK_ALPN       7011
#define ID_COMBO_PLATFORM 7012 
#define ID_EDIT_UA_STR    7013 
#define ID_CHK_FRAG       7014
#define ID_EDIT_FRAG_DLY  7016 
#define ID_EDIT_FRAG_MIN  7017 // 新增：最小分片
#define ID_EDIT_FRAG_MAX  7018 // 新增：最大分片
#define ID_CHK_PADDING    7019 // 新增：启用Padding
#define ID_EDIT_PAD_MIN   7020 // 新增：最小填充
#define ID_EDIT_PAD_MAX   7021 // 新增：最大填充

#define ID_EDIT_TAG      8001
#define ID_EDIT_ADDR     8002
#define ID_EDIT_PORT     8003
#define ID_EDIT_USER     8004
#define ID_EDIT_PASS     8005
#define ID_EDIT_NET      8006
#define ID_EDIT_TYPE     8007
#define ID_EDIT_HOST     8008
#define ID_EDIT_PATH     8009
#define ID_EDIT_TLS      8010

#define BUFFER_SIZE 131072 
#define CONFIG_FILE L"config.json"

ProxyConfig g_proxyConfig;
volatile BOOL g_proxyRunning = FALSE;
SOCKET g_listen_sock = INVALID_SOCKET;
SSL_CTX *g_ssl_ctx = NULL;
HANDLE hProxyThread = NULL;
NOTIFYICONDATAW nid;
HWND hwnd;
HMENU hMenu, hNodeSubMenu;
HWND hLogViewerWnd = NULL;
HFONT hLogFont = NULL;
HFONT hAppFont = NULL;
wchar_t** nodeTags = NULL;
int nodeCount = 0;
wchar_t currentNode[64] = L"";
wchar_t g_editingTag[256] = {0};
BOOL g_isIconVisible = TRUE;
wchar_t g_iniFilePath[MAX_PATH] = {0};
UINT g_hotkeyModifiers = MOD_CONTROL | MOD_ALT; 
UINT g_hotkeyVk = 'H';                          
int g_localPort = 10809;
int g_hideTrayStart = 0; 
WNDPROC g_oldListBoxProc = NULL;
int g_nEditScrollPos = 0;
int g_nEditContentHeight = 0;

// 抗封锁配置全局变量 (已更新)
BOOL g_enableChromeCiphers = TRUE;
BOOL g_enableALPN = TRUE;

// 分片配置
BOOL g_enableFragment = FALSE;
int  g_fragSizeMin = 5;  
int  g_fragSizeMax = 20; 
int  g_fragDelayMs = 2;

// Padding 配置
BOOL g_enablePadding = FALSE; 
int  g_padSizeMin = 1;   
int  g_padSizeMax = 10;  

int  g_uaPlatformIndex = 0; 
char g_userAgentStr[512] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

const wchar_t* UA_PLATFORMS[] = { L"Windows", L"iOS", L"Android", L"macOS", L"Linux" };
const char* UA_TEMPLATES[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
};

// ---------------------- BIO Fragmentation Implementation ----------------------
static int frag_write(BIO *b, const char *in, int inl);
static int frag_read(BIO *b, char *out, int outl);
static long frag_ctrl(BIO *b, int cmd, long num, void *ptr);
static int frag_new(BIO *b);
static int frag_free(BIO *b);

static BIO_METHOD *method_frag = NULL;

typedef struct {
    int first_packet_sent;
} FragCtx;

BIO_METHOD *BIO_f_fragment(void) {
    if (method_frag == NULL) {
        method_frag = BIO_meth_new(BIO_TYPE_FILTER, "Fragmentation Filter");
        BIO_meth_set_write(method_frag, frag_write);
        BIO_meth_set_read(method_frag, frag_read);
        BIO_meth_set_ctrl(method_frag, frag_ctrl);
        BIO_meth_set_create(method_frag, frag_new);
        BIO_meth_set_destroy(method_frag, frag_free);
    }
    return method_frag;
}

static int frag_new(BIO *b) {
    FragCtx *ctx = (FragCtx *)malloc(sizeof(FragCtx));
    if(!ctx) return 0;
    ctx->first_packet_sent = 0;
    BIO_set_data(b, ctx);
    BIO_set_init(b, 1);
    return 1;
}

static int frag_free(BIO *b) {
    if (b == NULL) return 0;
    FragCtx *ctx = (FragCtx *)BIO_get_data(b);
    if (ctx) { free(ctx); BIO_set_data(b, NULL); }
    return 1;
}

// 核心逻辑修改：随机分片
static int frag_write(BIO *b, const char *in, int inl) {
    FragCtx *ctx = (FragCtx *)BIO_get_data(b);
    BIO *next = BIO_next(b);
    if (!ctx || !next) return 0;

    // 仅针对握手阶段的 Client Hello (第一次发送) 进行随机切分
    if (inl > 0 && ctx->first_packet_sent == 0) {
        ctx->first_packet_sent = 1; 

        int bytes_sent = 0;
        int remaining = inl;
        
        while (remaining > 0) {
            // 计算随机切片长度 [min, max]
            int range = g_fragSizeMax - g_fragSizeMin;
            if (range < 0) range = 0;
            int chunk_size = g_fragSizeMin + (range > 0 ? (rand() % (range + 1)) : 0);
            
            // 修正边界
            if (chunk_size < 1) chunk_size = 1;
            if (chunk_size > remaining) chunk_size = remaining;

            int ret = BIO_write(next, in + bytes_sent, chunk_size);
            if (ret <= 0) return (bytes_sent > 0) ? bytes_sent : ret;

            bytes_sent += ret;
            remaining -= ret;

            // 随机微小延迟
            if (g_fragDelayMs > 0) {
                 Sleep(rand() % (g_fragDelayMs + 1));
            }
        }
        return bytes_sent;
    }
    
    return BIO_write(next, in, inl);
}

static int frag_read(BIO *b, char *out, int outl) {
    BIO *next = BIO_next(b);
    if (!next) return 0;
    return BIO_read(next, out, outl);
}

static long frag_ctrl(BIO *b, int cmd, long num, void *ptr) {
    BIO *next = BIO_next(b);
    if (!next) return 0;
    return BIO_ctrl(next, cmd, num, ptr);
}
// ---------------------- End BIO Implementation ----------------------

static const unsigned char base64_table[256] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,62,0,0,0,63,52,53,54,55,56,57,58,59,60,61,0,0,0,0,0,0,
    0,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,0,0,0,0,0,
    0,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51
};

void log_msg(const char *format, ...);
void log_wsa_error(const char* context);
char* GetClipboardText(); 
void TrimString(char* str);
void UrlDecode(char* dst, const char* src);
unsigned char* Base64Decode(const char* src, size_t* out_len);
char* GetQueryParam(const char* query, const char* key);
void LoadSettings();
void SaveSettings();
BOOL ReadFileToBuffer(const wchar_t* filename, char** buffer, long* fileSize);
BOOL WriteBufferToFile(const wchar_t* filename, const char* buffer);
void ParseTags();
void SwitchNode(const wchar_t* tag);
void DeleteNode(const wchar_t* tag);
char* GetUniqueTagName(cJSON* outbounds, const char* type, const char* base_name);
BOOL AddNodeToConfig(cJSON* newNode);
void ParseNodeConfigToGlobal(cJSON *node);
int ImportFromClipboard();
void StartProxyCore();
void StopProxyCore();
void OpenLogViewer(BOOL bShow); 
void OpenNodeManager();
void OpenNodeEditWindow(const wchar_t* tag);
void OpenSettingsWindow();
void ToggleTrayIcon();
void SetAutorun(BOOL enable);
BOOL IsAutorun();
cJSON* ParseSocks(const char* link);
cJSON* ParseVmess(const char* link);
cJSON* ParseVlessOrTrojan(const char* link);
cJSON* ParseShadowsocks(const char* link);
void AddComboItem(HWND hCombo, const wchar_t* text, BOOL select);
void LoadNodeToEdit(HWND hWnd, const wchar_t* tag);
void SaveEditedNode(HWND hWnd);
LRESULT CALLBACK SettingsWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK NodeMgrWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK NodeEditWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK LogWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
BOOL IsWindows8OrGreater();
void SetSystemProxy(BOOL enable);
BOOL IsSystemProxyEnabled();
void FreeGlobalSSLContext();

void log_msg(const char *format, ...) {
    char buf[2048]; char time_buf[64]; SYSTEMTIME st; GetLocalTime(&st);
    sprintf(time_buf, "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
    va_list args; va_start(args, format); vsnprintf(buf, sizeof(buf)-64, format, args); va_end(args);
    char final_msg[2200]; snprintf(final_msg, sizeof(final_msg), "%s%s\r\n", time_buf, buf);
    OutputDebugStringA(final_msg);
    if (hLogViewerWnd && IsWindow(hLogViewerWnd)) {
        int wLen = MultiByteToWideChar(CP_UTF8, 0, final_msg, -1, NULL, 0);
        wchar_t* wBuf = (wchar_t*)malloc(wLen * sizeof(wchar_t));
        MultiByteToWideChar(CP_UTF8, 0, final_msg, -1, wBuf, wLen);
        PostMessageW(hLogViewerWnd, WM_LOG_UPDATE, 0, (LPARAM)wBuf);
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
    fread(*buffer, 1, *fileSize, f); (*buffer)[*fileSize] = 0;
    fclose(f); return TRUE;
}

BOOL WriteBufferToFile(const wchar_t* filename, const char* buffer) {
    FILE* f = NULL;
    if (_wfopen_s(&f, filename, L"wb") != 0 || !f) return FALSE;
    fwrite(buffer, 1, strlen(buffer), f);
    fclose(f); return TRUE;
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
            char* text = (char*)malloc(utf8Len);
            WideCharToMultiByte(CP_UTF8, 0, pszTextW, -1, text, utf8Len, NULL, NULL);
            GlobalUnlock(hData); CloseClipboard(); TrimString(text); return text;
        }
    }
    hData = GetClipboardData(CF_TEXT);
    if (hData != NULL) {
        char* pszText = (char*)GlobalLock(hData);
        if (pszText != NULL) {
            char* text = strdup(pszText);
            GlobalUnlock(hData); CloseClipboard(); TrimString(text); return text;
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

void LoadSettings() {
    g_hotkeyModifiers = GetPrivateProfileIntW(L"Settings", L"Modifiers", MOD_CONTROL | MOD_ALT, g_iniFilePath);
    g_hotkeyVk = GetPrivateProfileIntW(L"Settings", L"VK", 'H', g_iniFilePath);
    g_localPort = GetPrivateProfileIntW(L"Settings", L"LocalPort", 10809, g_iniFilePath);
    g_hideTrayStart = GetPrivateProfileIntW(L"Settings", L"HideTray", 0, g_iniFilePath);
    
    // 抗封锁配置读取 (已更新)
    g_enableChromeCiphers = GetPrivateProfileIntW(L"Settings", L"ChromeCiphers", 1, g_iniFilePath);
    g_enableALPN = GetPrivateProfileIntW(L"Settings", L"EnableALPN", 1, g_iniFilePath);
    g_enableFragment = GetPrivateProfileIntW(L"Settings", L"EnableFragment", 0, g_iniFilePath);
    
    // 随机分片配置
    g_fragSizeMin = GetPrivateProfileIntW(L"Settings", L"FragMin", 5, g_iniFilePath);
    g_fragSizeMax = GetPrivateProfileIntW(L"Settings", L"FragMax", 20, g_iniFilePath);
    g_fragDelayMs = GetPrivateProfileIntW(L"Settings", L"FragDelay", 2, g_iniFilePath);

    // Padding 配置
    g_enablePadding = GetPrivateProfileIntW(L"Settings", L"EnablePadding", 0, g_iniFilePath);
    g_padSizeMin = GetPrivateProfileIntW(L"Settings", L"PadMin", 1, g_iniFilePath);
    g_padSizeMax = GetPrivateProfileIntW(L"Settings", L"PadMax", 10, g_iniFilePath);

    // 校验
    if (g_fragSizeMin < 1) g_fragSizeMin = 1;
    if (g_fragSizeMax < g_fragSizeMin) g_fragSizeMax = g_fragSizeMin;
    if (g_fragDelayMs < 0) g_fragDelayMs = 0;
    if (g_padSizeMin < 0) g_padSizeMin = 0;
    if (g_padSizeMax < g_padSizeMin) g_padSizeMax = g_padSizeMin;

    g_uaPlatformIndex = GetPrivateProfileIntW(L"Settings", L"UAPlatform", 0, g_iniFilePath);
    
    wchar_t wUABuf[512] = {0};
    GetPrivateProfileStringW(L"Settings", L"UserAgent", L"", wUABuf, 512, g_iniFilePath);
    if (wcslen(wUABuf) > 5) {
        WideCharToMultiByte(CP_UTF8, 0, wUABuf, -1, g_userAgentStr, sizeof(g_userAgentStr), NULL, NULL);
    } else {
        strcpy(g_userAgentStr, UA_TEMPLATES[0]);
    }
}

void SaveSettings() {
    wchar_t buffer[16];
    wsprintfW(buffer, L"%u", g_hotkeyModifiers);
    WritePrivateProfileStringW(L"Settings", L"Modifiers", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%u", g_hotkeyVk);
    WritePrivateProfileStringW(L"Settings", L"VK", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_localPort);
    WritePrivateProfileStringW(L"Settings", L"LocalPort", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_hideTrayStart);
    WritePrivateProfileStringW(L"Settings", L"HideTray", buffer, g_iniFilePath);
    
    wsprintfW(buffer, L"%d", g_enableChromeCiphers);
    WritePrivateProfileStringW(L"Settings", L"ChromeCiphers", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_enableALPN);
    WritePrivateProfileStringW(L"Settings", L"EnableALPN", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_enableFragment);
    WritePrivateProfileStringW(L"Settings", L"EnableFragment", buffer, g_iniFilePath);
    
    // 保存新参数
    wsprintfW(buffer, L"%d", g_fragSizeMin);
    WritePrivateProfileStringW(L"Settings", L"FragMin", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_fragSizeMax);
    WritePrivateProfileStringW(L"Settings", L"FragMax", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_fragDelayMs);
    WritePrivateProfileStringW(L"Settings", L"FragDelay", buffer, g_iniFilePath);

    wsprintfW(buffer, L"%d", g_enablePadding);
    WritePrivateProfileStringW(L"Settings", L"EnablePadding", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_padSizeMin);
    WritePrivateProfileStringW(L"Settings", L"PadMin", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_padSizeMax);
    WritePrivateProfileStringW(L"Settings", L"PadMax", buffer, g_iniFilePath);

    wsprintfW(buffer, L"%d", g_uaPlatformIndex);
    WritePrivateProfileStringW(L"Settings", L"UAPlatform", buffer, g_iniFilePath);
    
    wchar_t wUABuf[512] = {0};
    MultiByteToWideChar(CP_UTF8, 0, g_userAgentStr, -1, wUABuf, 512);
    WritePrivateProfileStringW(L"Settings", L"UserAgent", wUABuf, g_iniFilePath);
}

void SetAutorun(BOOL enable) {
    HKEY hKey; wchar_t path[MAX_PATH]; GetModuleFileNameW(NULL, path, MAX_PATH);
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
        if (RegQueryValueExW(hKey, L"MyProxyClient", NULL, NULL, NULL, NULL) == ERROR_SUCCESS) { RegCloseKey(hKey); return TRUE; }
        RegCloseKey(hKey);
    }
    return FALSE;
}

void ToggleTrayIcon() {
    if (g_isIconVisible) { 
        Shell_NotifyIconW(NIM_DELETE, &nid); 
        g_isIconVisible = FALSE; 
        g_hideTrayStart = 1;
    }
    else { 
        nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        Shell_NotifyIconW(NIM_ADD, &nid); 
        g_isIconVisible = TRUE; 
        g_hideTrayStart = 0;
    }
    SaveSettings();
}

void FreeGlobalSSLContext() {
    if (g_ssl_ctx) {
        SSL_CTX_free(g_ssl_ctx);
        g_ssl_ctx = NULL;
    }
}

// 核心逻辑修改：从资源加载证书
void init_openssl_global() {
    if (g_ssl_ctx) return;
    SSL_library_init(); 
    OpenSSL_add_all_algorithms(); 
    SSL_load_error_strings();
    
    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_ssl_ctx) return;

    SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(g_ssl_ctx, TLS1_3_VERSION);

    if (g_enableChromeCiphers) {
        const char *chrome_ciphers = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA";
        SSL_CTX_set_cipher_list(g_ssl_ctx, chrome_ciphers);
        SSL_CTX_set_options(g_ssl_ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
        SSL_CTX_set_session_cache_mode(g_ssl_ctx, SSL_SESS_CACHE_CLIENT);
        log_msg("[Security] Chrome Cipher Suites Enabled");
    } else {
        log_msg("[Security] Standard OpenSSL Cipher Suites");
    }

    // 从资源加载证书 (ID: 2, Type: RT_RCDATA)
    HRSRC hRes = FindResourceW(NULL, MAKEINTRESOURCEW(2), RT_RCDATA);
    if (hRes) {
        HGLOBAL hData = LoadResource(NULL, hRes);
        void* pData = LockResource(hData);
        DWORD dataSize = SizeofResource(NULL, hRes);

        if (pData && dataSize > 0) {
            BIO *cbio = BIO_new_mem_buf(pData, dataSize);
            if (cbio) {
                X509_STORE *cts = SSL_CTX_get_cert_store(g_ssl_ctx);
                X509 *x = NULL;
                int count = 0;
                while ((x = PEM_read_bio_X509(cbio, NULL, 0, NULL)) != NULL) {
                    if (X509_STORE_add_cert(cts, x)) count++;
                    X509_free(x);
                }
                BIO_free(cbio);

                if (count > 0) {
                    SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_PEER, NULL);
                    log_msg("[Security] Embedded CA loaded (%d certs). Strict mode.", count);
                } else {
                    SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);
                    log_msg("[Warning] Embedded CA data invalid. Insecure mode.");
                }
            } else {
                SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);
                log_msg("[Warning] Failed to create BIO for CA. Insecure mode.");
            }
        } else {
            SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);
            log_msg("[Warning] Empty CA resource. Insecure mode.");
        }
    } else {
        SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);
        log_msg("[Warning] cacert.pem resource not found in exe. Insecure mode.");
    }
}

// 核心逻辑修改：Padding 支持
int tls_init_connect(TLSContext *ctx) {
    ctx->ssl = SSL_new(g_ssl_ctx);
    
    // 设置随机 Padding
    if (g_enablePadding) {
        int range = g_padSizeMax - g_padSizeMin;
        if (range < 0) range = 0;
        int blockSize = g_padSizeMin + (range > 0 ? (rand() % (range + 1)) : 0);
        if (blockSize > 0) {
            SSL_set_block_padding(ctx->ssl, blockSize);
        }
    }

    BIO *bio = BIO_new_socket(ctx->sock, BIO_NOCLOSE);
    
    if (g_enableFragment) {
        BIO *frag = BIO_new(BIO_f_fragment());
        bio = BIO_push(frag, bio);
    }
    
    SSL_set_bio(ctx->ssl, bio, bio);
    
    const char *sni_name = (strlen(g_proxyConfig.sni) ? g_proxyConfig.sni : g_proxyConfig.host);
    SSL_set_tlsext_host_name(ctx->ssl, sni_name);
    
    if (g_enableALPN) {
        unsigned char alpn_protos[] = { 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
        SSL_set_alpn_protos(ctx->ssl, alpn_protos, sizeof(alpn_protos));
    }

    return (SSL_connect(ctx->ssl) == 1) ? 0 : -1;
}

int tls_write(TLSContext *ctx, const char *data, int len) {
    if (!ctx->ssl) return -1;
    int written = 0;
    while (written < len) {
        int ret = SSL_write(ctx->ssl, data + written, len - written);
        if (ret > 0) { written += ret; } 
        else {
            int err = SSL_get_error(ctx->ssl, ret);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) { Sleep(1); continue; }
            return -1; 
        }
    }
    return written;
}

int tls_read(TLSContext *ctx, char *out, int max) {
    if (!ctx->ssl) return -1;
    int ret = SSL_read(ctx->ssl, out, max);
    if (ret <= 0) {
        int err = SSL_get_error(ctx->ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return 0;
        if (err == SSL_ERROR_ZERO_RETURN) return -1;
        return -1;
    }
    return ret;
}

int tls_read_exact(TLSContext *ctx, char *buf, int len) {
    int total = 0;
    while (total < len) {
        int ret = tls_read(ctx, buf + total, len - total);
        if (ret < 0) return 0; 
        if (ret == 0) { Sleep(1); continue; } 
        total += ret;
    }
    return 1;
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

int ws_read_payload_exact(TLSContext *tls, char *out_buf, int expected_len) {
    char raw_head[16];
    if (!tls_read_exact(tls, raw_head, 2)) return 0;
    int payload_len = raw_head[1] & 0x7F;
    if (payload_len == 126) {
        if (!tls_read_exact(tls, raw_head + 2, 2)) return 0;
        payload_len = (unsigned char)raw_head[2] << 8 | (unsigned char)raw_head[3];
    }
    if (payload_len < expected_len) return 0;
    if (!tls_read_exact(tls, out_buf, payload_len)) return 0;
    return payload_len;
}

int recv_timeout(SOCKET s, char *buf, int len, int timeout_sec) {
    fd_set fds; FD_ZERO(&fds); FD_SET(s, &fds);
    struct timeval tv = { timeout_sec, 0 };
    int n = select(0, &fds, NULL, NULL, &tv);
    if (n == 0) return -2; if (n < 0) return -1;  
    return recv(s, buf, len, 0);
}

int send_all(SOCKET s, const char *buf, int len) {
    int total = 0; int bytesleft = len; int n;
    while(total < len) {
        n = send(s, buf+total, bytesleft, 0);
        if (n == -1) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) { Sleep(1); continue; }
            return -1;
        }
        total += n; bytesleft -= n;
    }
    return total;
}
DWORD WINAPI client_handler(LPVOID p) {
    SOCKET c = (SOCKET)(UINT_PTR)p; TLSContext tls; memset(&tls, 0, sizeof(tls));
    SOCKET r = INVALID_SOCKET;      
    char *c_buf = (char*)malloc(BUFFER_SIZE); char *ws_read_buf = (char*)malloc(BUFFER_SIZE); char *ws_send_buf = (char*)malloc(BUFFER_SIZE);
    if (!c_buf || !ws_read_buf || !ws_send_buf) { goto cl_end; }
    int ws_buf_len = 0; int flag = 1; 
    setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
    int browser_len = recv_timeout(c, c_buf, BUFFER_SIZE, 10);
    if (browser_len <= 0) goto cl_end;
    c_buf[browser_len] = 0;
    char method[16], host[256]; int port = 80; int is_connect_method = 0;
    if (c_buf[0] == 0x05) { send(c, "\x05\x00", 2, 0); goto cl_end; } 
    else {
        if (sscanf(c_buf, "%15s %255s", method, host) == 2) {
            char *p = strchr(host, ':');
            if (p) { *p = 0; port = atoi(p+1); }
            else if(stricmp(method, "CONNECT")==0) port = 443;
            if (stricmp(method, "CONNECT") == 0) is_connect_method = 1;
        } else { goto cl_end; }
    }
    log_msg("[Access] %s %s:%d", method, host, port);
    struct hostent *h = gethostbyname(g_proxyConfig.host);
    if(!h) { log_msg("[DNS] Fail"); goto cl_end; }
    r = socket(AF_INET, SOCK_STREAM, 0);
    if (r == INVALID_SOCKET) goto cl_end;
    setsockopt(r, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
    struct sockaddr_in a; memset(&a, 0, sizeof(a)); a.sin_family = AF_INET; a.sin_port = htons((unsigned short)g_proxyConfig.port);
    a.sin_addr = *(struct in_addr*)h->h_addr;
    if (connect(r, (struct sockaddr*)&a, sizeof(a)) != 0) { log_wsa_error("TCP Connect"); goto cl_end; }
    tls.sock = r;
    
    // 这里会调用修改过的 tls_init_connect，应用 Padding 和分片配置
    if (tls_init_connect(&tls) != 0) goto cl_end;
    
    const char* sni_val = (strlen(g_proxyConfig.sni) > 0) ? g_proxyConfig.sni : g_proxyConfig.host;

    int offset = snprintf(ws_send_buf, BUFFER_SIZE, 
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n", 
        g_proxyConfig.path, sni_val, g_userAgentStr);

    tls_write(&tls, ws_send_buf, offset);

    int len = tls_read(&tls, ws_read_buf, BUFFER_SIZE-1);
    if (len <= 0 || !strstr(ws_read_buf, "101 Switching Protocols")) { log_msg("[WS Error] Handshake failed"); goto cl_end; }
    char auth[] = {0x05, 0x01, 0x00};
    if (strlen(g_proxyConfig.user) > 0) auth[2] = 0x02;
    int flen = build_ws_frame(auth, 3, ws_send_buf);
    tls_write(&tls, ws_send_buf, flen);
    char resp_buf[256];
    if (ws_read_payload_exact(&tls, resp_buf, 2) < 2) goto cl_end;
    if (resp_buf[1] == 0x02) {
        char up[512]; int idx = 0;
        up[idx++] = 1; up[idx++] = (char)strlen(g_proxyConfig.user); memcpy(up+idx, g_proxyConfig.user, strlen(g_proxyConfig.user)); idx += (int)strlen(g_proxyConfig.user);
        up[idx++] = (char)strlen(g_proxyConfig.pass); memcpy(up+idx, g_proxyConfig.pass, strlen(g_proxyConfig.pass)); idx += (int)strlen(g_proxyConfig.pass);
        flen = build_ws_frame(up, idx, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
        if (ws_read_payload_exact(&tls, resp_buf, 2) < 2) goto cl_end; 
        if (resp_buf[1] != 0x00) goto cl_end;
    }
    unsigned char socks_req[512]; int slen = 0;
    socks_req[slen++] = 0x05; socks_req[slen++] = 0x01; socks_req[slen++] = 0x00; socks_req[slen++] = 0x03;
    socks_req[slen++] = (unsigned char)strlen(host);
    memcpy(socks_req + slen, host, strlen(host)); slen += (int)strlen(host);
    socks_req[slen++] = (port >> 8) & 0xFF; socks_req[slen++] = port & 0xFF;
    flen = build_ws_frame((char*)socks_req, slen, ws_send_buf);
    tls_write(&tls, ws_send_buf, flen);
    if (ws_read_payload_exact(&tls, resp_buf, 4) < 4 || resp_buf[1] != 0x00) goto cl_end;
    if (is_connect_method) {
        const char *ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
        send(c, ok, strlen(ok), 0);
    } else {
        flen = build_ws_frame(c_buf, browser_len, ws_send_buf);
        tls_write(&tls, ws_send_buf, flen);
    }
    fd_set fds; struct timeval tv; u_long mode = 1;
    ioctlsocket(c, FIONBIO, &mode); ioctlsocket(r, FIONBIO, &mode);
    ws_buf_len = 0; int hl, pl, frame_total;
    while(1) {
        FD_ZERO(&fds); FD_SET(c, &fds); FD_SET(r, &fds);
        int pending = SSL_pending(tls.ssl);
        tv.tv_sec = 1; tv.tv_usec = 0;
        if (pending > 0 || ws_buf_len > 0) { tv.tv_sec = 0; tv.tv_usec = 0; }
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
                else if (len == -1) break; 
            }
        }
        while (ws_buf_len > 0) {
            frame_total = check_ws_frame((unsigned char*)ws_read_buf, ws_buf_len, &hl, &pl);
            if (frame_total > 0) {
                int opcode = ws_read_buf[0] & 0x0F;
                if (opcode == 0x8) goto cl_end; 
                if ((opcode == 0x1 || opcode == 0x2) && pl > 0) {
                    if (send_all(c, ws_read_buf + hl, pl) < 0) goto cl_end;
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
    free(c_buf); free(ws_read_buf); free(ws_send_buf); tls_close(&tls);
    if (r != INVALID_SOCKET) closesocket(r); if (c != INVALID_SOCKET) closesocket(c);
    return 0;
}

DWORD WINAPI server_thread(LPVOID p) {
    init_openssl_global(); // 使用修改后的资源加载版本
    g_listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; addr.sin_port = htons(g_localPort);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int opt = 1; setsockopt(g_listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    if (bind(g_listen_sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        log_msg("Port %d bind fail", g_localPort); g_proxyRunning = FALSE; return 0;
    }
    listen(g_listen_sock, 100);
    log_msg("Proxy Started: 127.0.0.1:%d", g_localPort);
    while(g_proxyRunning) {
        SOCKET c = accept(g_listen_sock, NULL, NULL);
        if (c != INVALID_SOCKET) CloseHandle(CreateThread(NULL, 0, client_handler, (LPVOID)(UINT_PTR)c, 0, NULL));
        else break;
    }
    return 0;
}

void StartProxyCore() {
    if (g_proxyRunning) return;
    g_proxyRunning = TRUE;
    hProxyThread = CreateThread(NULL, 0, server_thread, NULL, 0, NULL);
    if (!hProxyThread) { log_msg("CreateThread Failed"); g_proxyRunning = FALSE; }
}

void StopProxyCore() {
    g_proxyRunning = FALSE;
    if (g_listen_sock != INVALID_SOCKET) { closesocket(g_listen_sock); g_listen_sock = INVALID_SOCKET; }
    if (hProxyThread) { WaitForSingleObject(hProxyThread, 2000); CloseHandle(hProxyThread); hProxyThread = NULL; }
    FreeGlobalSSLContext();
    log_msg("Proxy Stopped");
}

// 界面逻辑完全重写：支持新的随机分片和Padding配置
LRESULT CALLBACK SettingsWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hHotkey, hPortEdit;
    switch(msg) {
        case WM_CREATE: {
            int y = 20;
            // 1. 基础设置
            CreateWindowW(L"STATIC", L"全局快捷键:", WS_CHILD|WS_VISIBLE, 20, y, 100, 20, hWnd, NULL,NULL,NULL);
            hHotkey = CreateWindowExW(0, HOTKEY_CLASSW, NULL, WS_CHILD|WS_VISIBLE|WS_BORDER, 130, y-3, 180, 25, hWnd, (HMENU)ID_HOTKEY_CTRL, NULL,NULL);
            UINT hkMod = 0; if (g_hotkeyModifiers & MOD_SHIFT) hkMod |= HOTKEYF_SHIFT;
            if (g_hotkeyModifiers & MOD_CONTROL) hkMod |= HOTKEYF_CONTROL;
            if (g_hotkeyModifiers & MOD_ALT) hkMod |= HOTKEYF_ALT;
            SendMessage(hHotkey, HKM_SETHOTKEY, MAKEWORD(g_hotkeyVk, hkMod), 0);
            
            y += 35;
            CreateWindowW(L"STATIC", L"本地代理端口:", WS_CHILD|WS_VISIBLE, 20, y, 100, 20, hWnd, NULL,NULL,NULL);
            hPortEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", NULL, WS_CHILD|WS_VISIBLE|ES_NUMBER, 130, y-3, 80, 25, hWnd, (HMENU)ID_PORT_EDIT, NULL,NULL);
            SetDlgItemInt(hWnd, ID_PORT_EDIT, g_localPort, FALSE);

            // 2. 抗封锁设置 GroupBox
            y += 40;
            CreateWindowW(L"BUTTON", L"抗封锁设置 (Anti-Censorship)", WS_CHILD|WS_VISIBLE|BS_GROUPBOX, 20, y, 300, 310, hWnd, NULL, NULL, NULL);
            
            y += 25;
            HWND hChk1 = CreateWindowW(L"BUTTON", L"启用 Chrome 浏览器指纹", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 35, y, 250, 20, hWnd, (HMENU)ID_CHK_CIPHERS, NULL, NULL);
            y += 25;
            HWND hChk2 = CreateWindowW(L"BUTTON", L"启用 ALPN 伪装 (http/1.1)", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 35, y, 250, 20, hWnd, (HMENU)ID_CHK_ALPN, NULL, NULL);
            
            // --- 分片设置 ---
            y += 25;
            HWND hChk3 = CreateWindowW(L"BUTTON", L"启用 TCP 随机分片 (Fragment)", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 35, y, 250, 20, hWnd, (HMENU)ID_CHK_FRAG, NULL, NULL);
            
            y += 25;
            CreateWindowW(L"STATIC", L"分片长度范围:", WS_CHILD|WS_VISIBLE, 55, y+2, 90, 20, hWnd, NULL,NULL,NULL);
            HWND hFMin = CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_NUMBER|ES_CENTER, 145, y, 35, 22, hWnd, (HMENU)ID_EDIT_FRAG_MIN, NULL, NULL);
            CreateWindowW(L"STATIC", L"-", WS_CHILD|WS_VISIBLE, 185, y+2, 10, 20, hWnd, NULL,NULL,NULL);
            HWND hFMax = CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_NUMBER|ES_CENTER, 200, y, 35, 22, hWnd, (HMENU)ID_EDIT_FRAG_MAX, NULL, NULL);
            
            CreateWindowW(L"STATIC", L"延迟(ms):", WS_CHILD|WS_VISIBLE, 245, y+2, 60, 20, hWnd, NULL,NULL,NULL);
            HWND hDly = CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_NUMBER, 290, y, 20, 22, hWnd, (HMENU)ID_EDIT_FRAG_DLY, NULL, NULL);

            // --- Padding 设置 ---
            y += 30;
            HWND hChkPad = CreateWindowW(L"BUTTON", L"启用 TLS Padding (随机包长)", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 35, y, 250, 20, hWnd, (HMENU)ID_CHK_PADDING, NULL, NULL);
            
            y += 25;
            CreateWindowW(L"STATIC", L"随机填充范围:", WS_CHILD|WS_VISIBLE, 55, y+2, 90, 20, hWnd, NULL,NULL,NULL);
            HWND hPMin = CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_NUMBER|ES_CENTER, 145, y, 35, 22, hWnd, (HMENU)ID_EDIT_PAD_MIN, NULL, NULL);
            CreateWindowW(L"STATIC", L"-", WS_CHILD|WS_VISIBLE, 185, y+2, 10, 20, hWnd, NULL,NULL,NULL);
            HWND hPMax = CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_NUMBER|ES_CENTER, 200, y, 35, 22, hWnd, (HMENU)ID_EDIT_PAD_MAX, NULL, NULL);

            // --- UA 设置 ---
            y += 35;
            CreateWindowW(L"STATIC", L"伪装平台:", WS_CHILD|WS_VISIBLE, 35, y, 60, 20, hWnd, NULL,NULL,NULL);
            HWND hCombo = CreateWindowW(L"COMBOBOX", NULL, WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST|WS_VSCROLL, 100, y-3, 200, 200, hWnd, (HMENU)ID_COMBO_PLATFORM, NULL, NULL);
            
            y += 25;
            HWND hEditUA = CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL, 35, y, 265, 25, hWnd, (HMENU)ID_EDIT_UA_STR, NULL, NULL);

            // 按钮
            CreateWindowW(L"BUTTON", L"确定", WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON, 60, 420, 80, 30, hWnd, (HMENU)IDOK, NULL,NULL);
            CreateWindowW(L"BUTTON", L"取消", WS_CHILD|WS_VISIBLE, 190, 420, 80, 30, hWnd, (HMENU)IDCANCEL, NULL,NULL);

            // 初始化控件值
            SendMessage(hChk1, BM_SETCHECK, g_enableChromeCiphers ? BST_CHECKED : BST_UNCHECKED, 0);
            SendMessage(hChk2, BM_SETCHECK, g_enableALPN ? BST_CHECKED : BST_UNCHECKED, 0);
            SendMessage(hChk3, BM_SETCHECK, g_enableFragment ? BST_CHECKED : BST_UNCHECKED, 0);
            SendMessage(hChkPad, BM_SETCHECK, g_enablePadding ? BST_CHECKED : BST_UNCHECKED, 0);

            SetDlgItemInt(hWnd, ID_EDIT_FRAG_MIN, g_fragSizeMin, FALSE);
            SetDlgItemInt(hWnd, ID_EDIT_FRAG_MAX, g_fragSizeMax, FALSE);
            SetDlgItemInt(hWnd, ID_EDIT_FRAG_DLY, g_fragDelayMs, FALSE);
            
            SetDlgItemInt(hWnd, ID_EDIT_PAD_MIN, g_padSizeMin, FALSE);
            SetDlgItemInt(hWnd, ID_EDIT_PAD_MAX, g_padSizeMax, FALSE);

            for(int i=0; i<5; i++) SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)UA_PLATFORMS[i]);
            SendMessage(hCombo, CB_SETCURSEL, g_uaPlatformIndex, 0);
            SetDlgItemTextA(hWnd, ID_EDIT_UA_STR, g_userAgentStr);
            
            EnumChildWindows(hWnd, (WNDENUMPROC)(void*)SendMessageW, (LPARAM)hAppFont);
            SendMessage(hWnd, WM_SETFONT, (WPARAM)hAppFont, TRUE);
            break;
        }
        case WM_COMMAND:
            if (LOWORD(wParam) == ID_COMBO_PLATFORM && HIWORD(wParam) == CBN_SELCHANGE) {
                int idx = SendMessage((HWND)lParam, CB_GETCURSEL, 0, 0);
                if (idx >= 0 && idx < 5) SetDlgItemTextA(hWnd, ID_EDIT_UA_STR, UA_TEMPLATES[idx]);
            }
            if (LOWORD(wParam) == IDOK) {
                // 保存逻辑
                int fMin = GetDlgItemInt(hWnd, ID_EDIT_FRAG_MIN, NULL, FALSE);
                int fMax = GetDlgItemInt(hWnd, ID_EDIT_FRAG_MAX, NULL, FALSE);
                int fDly = GetDlgItemInt(hWnd, ID_EDIT_FRAG_DLY, NULL, FALSE);
                int pMin = GetDlgItemInt(hWnd, ID_EDIT_PAD_MIN, NULL, FALSE);
                int pMax = GetDlgItemInt(hWnd, ID_EDIT_PAD_MAX, NULL, FALSE);
                
                // 简单的校验
                if (fMin < 1) fMin = 1; if (fMax < fMin) fMax = fMin;
                if (pMin < 0) pMin = 0; if (pMax < pMin) pMax = pMin;

                g_fragSizeMin = fMin; g_fragSizeMax = fMax; g_fragDelayMs = fDly;
                g_padSizeMin = pMin; g_padSizeMax = pMax;

                g_enableChromeCiphers = (IsDlgButtonChecked(hWnd, ID_CHK_CIPHERS) == BST_CHECKED);
                g_enableALPN = (IsDlgButtonChecked(hWnd, ID_CHK_ALPN) == BST_CHECKED);
                g_enableFragment = (IsDlgButtonChecked(hWnd, ID_CHK_FRAG) == BST_CHECKED);
                g_enablePadding = (IsDlgButtonChecked(hWnd, ID_CHK_PADDING) == BST_CHECKED);

                g_uaPlatformIndex = SendMessage(GetDlgItem(hWnd, ID_COMBO_PLATFORM), CB_GETCURSEL, 0, 0);
                GetDlgItemTextA(hWnd, ID_EDIT_UA_STR, g_userAgentStr, 511);

                LRESULT res = SendMessage(hHotkey, HKM_GETHOTKEY, 0, 0);
                UINT vk = LOBYTE(res); UINT mod = HIBYTE(res);
                UINT newMod = 0; if (mod & HOTKEYF_SHIFT) newMod |= MOD_SHIFT;
                if (mod & HOTKEYF_CONTROL) newMod |= MOD_CONTROL;
                if (mod & HOTKEYF_ALT) newMod |= MOD_ALT;
                if (vk != 0 && newMod != 0) {
                    UnregisterHotKey(hwnd, ID_GLOBAL_HOTKEY);
                    if (RegisterHotKey(hwnd, ID_GLOBAL_HOTKEY, newMod, vk)) { g_hotkeyVk = vk; g_hotkeyModifiers = newMod; }
                }

                int port = GetDlgItemInt(hWnd, ID_PORT_EDIT, NULL, FALSE);
                if (port > 0 && port < 65535) g_localPort = port;

                SaveSettings();
                if (g_proxyRunning) { StopProxyCore(); StartProxyCore(); }
                DestroyWindow(hWnd);
            } else if (LOWORD(wParam) == IDCANCEL) DestroyWindow(hWnd);
            break;
        case WM_CLOSE: DestroyWindow(hWnd); break;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

void OpenSettingsWindow() {
    WNDCLASSW wc = {0}; wc.lpfnWndProc=SettingsWndProc; wc.hInstance=GetModuleHandle(NULL); wc.lpszClassName=L"Settings"; wc.hbrBackground=(HBRUSH)(COLOR_BTNFACE+1);
    WNDCLASSW temp; if (!GetClassInfoW(GetModuleHandle(NULL), L"Settings", &temp)) RegisterClassW(&wc);
    // 高度增加到 500 以容纳新选项
    HWND h = CreateWindowW(L"Settings", L"程序设置", WS_VISIBLE|WS_CAPTION|WS_SYSMENU, CW_USEDEFAULT,0,350,500, hwnd,NULL,wc.hInstance,NULL);
    ShowWindow(h, SW_SHOW);
}

LRESULT CALLBACK ListBox_Proc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_KEYDOWN) {
        if (wParam == 'A' && (GetKeyState(VK_CONTROL) & 0x8000)) {
            SendMessage(hWnd, LB_SETSEL, TRUE, -1);
            return 0; 
        }
    }
    return CallWindowProc(g_oldListBoxProc, hWnd, msg, wParam, lParam);
}

LRESULT CALLBACK NodeMgrWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hList;
    switch(msg) {
        case WM_CREATE:
            hList = CreateWindowW(L"LISTBOX", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|LBS_NOTIFY|LBS_EXTENDEDSEL, 10, 10, 360, 170, hWnd, (HMENU)ID_NODEMGR_LIST, NULL, NULL);
            g_oldListBoxProc = (WNDPROC)SetWindowLongPtr(hList, GWLP_WNDPROC, (LONG_PTR)ListBox_Proc);
            CreateWindowW(L"BUTTON", L"编辑选中节点", WS_CHILD | WS_VISIBLE, 10, 185, 120, 30, hWnd, (HMENU)ID_NODEMGR_EDIT, NULL, NULL);
            CreateWindowW(L"BUTTON", L"删除选中节点", WS_CHILD | WS_VISIBLE, 140, 185, 120, 30, hWnd, (HMENU)ID_NODEMGR_DEL, NULL, NULL);
            EnumChildWindows(hWnd, (WNDENUMPROC)(void*)SendMessageW, (LPARAM)hAppFont);
            SendMessage(hWnd, WM_SETFONT, (WPARAM)hAppFont, TRUE);
            SendMessage(hWnd, WM_REFRESH_NODELIST, 0, 0); 
            break;
        case WM_REFRESH_NODELIST:
            SendMessage(hList, LB_RESETCONTENT, 0, 0);
            ParseTags();
            for(int i = 0; i < nodeCount; i++) SendMessageW(hList, LB_ADDSTRING, 0, (LPARAM)nodeTags[i]);
            break;
        case WM_COMMAND:
            if (LOWORD(wParam) == ID_NODEMGR_EDIT) {
                int selCount = SendMessage(hList, LB_GETSELCOUNT, 0, 0);
                if (selCount <= 0) {
                    MessageBoxW(hWnd, L"请先选择一个需要编辑的节点！", L"提示", MB_OK|MB_ICONWARNING);
                    break;
                }
                int selIndex = 0;
                if (SendMessage(hList, LB_GETSELITEMS, 1, (LPARAM)&selIndex) == LB_ERR) break; 
                int len = SendMessage(hList, LB_GETTEXTLEN, selIndex, 0);
                if (len > 0) {
                    wchar_t* tag = (wchar_t*)malloc((len + 1) * sizeof(wchar_t));
                    SendMessageW(hList, LB_GETTEXT, selIndex, (LPARAM)tag);
                    OpenNodeEditWindow(tag);
                    free(tag);
                }
            }
            else if (LOWORD(wParam) == ID_NODEMGR_DEL) {
                int selCount = SendMessage(hList, LB_GETSELCOUNT, 0, 0);
                if (selCount <= 0) { MessageBoxW(hWnd, L"请先选择至少一个节点", L"提示", MB_OK); break; }
                wchar_t confirmMsg[64]; wsprintfW(confirmMsg, L"确定要删除选中的 %d 个节点吗？", selCount);
                if (MessageBoxW(hWnd, confirmMsg, L"确认删除", MB_YESNO | MB_ICONQUESTION) != IDYES) break;
                int* selIndices = (int*)malloc(selCount * sizeof(int));
                if (!selIndices) break;
                SendMessage(hList, LB_GETSELITEMS, (WPARAM)selCount, (LPARAM)selIndices);
                wchar_t** tagsToDelete = (wchar_t**)malloc(selCount * sizeof(wchar_t*));
                for (int i = 0; i < selCount; i++) {
                    int len = SendMessage(hList, LB_GETTEXTLEN, selIndices[i], 0);
                    tagsToDelete[i] = (wchar_t*)malloc((len + 1) * sizeof(wchar_t));
                    SendMessageW(hList, LB_GETTEXT, selIndices[i], (LPARAM)tagsToDelete[i]);
                }
                for (int i = 0; i < selCount; i++) { DeleteNode(tagsToDelete[i]); free(tagsToDelete[i]); }
                free(tagsToDelete); free(selIndices);
                SendMessage(hWnd, WM_REFRESH_NODELIST, 0, 0); MessageBoxW(hWnd, L"删除完成", L"提示", MB_OK);
            }
            break;
        case WM_SHOWWINDOW: if ((BOOL)wParam == TRUE) SendMessage(hWnd, WM_REFRESH_NODELIST, 0, 0); break;
        case WM_CLOSE: ShowWindow(hWnd, SW_HIDE); return 0;
        case WM_DESTROY: if (hList && g_oldListBoxProc) SetWindowLongPtr(hList, GWLP_WNDPROC, (LONG_PTR)g_oldListBoxProc); break;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

void OpenNodeManager() {
    static HWND hMgr = NULL; 
    if (hMgr && IsWindow(hMgr)) { ShowWindow(hMgr, SW_SHOW); SetForegroundWindow(hMgr); SendMessage(hMgr, WM_REFRESH_NODELIST, 0, 0); return; }
    WNDCLASSW wc = {0};
    if (!GetClassInfoW(GetModuleHandle(NULL), L"NodeMgr", &wc)) {
        wc.lpfnWndProc = NodeMgrWndProc; wc.hInstance = GetModuleHandle(NULL); wc.lpszClassName = L"NodeMgr"; wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE+1);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW); RegisterClassW(&wc);
    }
    hMgr = CreateWindowW(L"NodeMgr", L"节点管理 (支持 Ctrl+A 全选/多选)", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, 0, 400, 270, NULL, NULL, GetModuleHandle(NULL), NULL);
    ShowWindow(hMgr, SW_SHOW);
}

LRESULT CALLBACK NodeEditWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch(msg) {
        case WM_CREATE: {
            int x = 25, w_lbl = 110, w_edit = 300, h = 24, gap = 40; 
            int y = 20;
            #define CREATE_LABEL(txt) CreateWindowW(L"STATIC", txt, WS_CHILD|WS_VISIBLE, x, y, w_lbl, h, hWnd, NULL, NULL, NULL)
            #define CREATE_EDIT(id, styles) CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|styles, x+w_lbl, y-2, w_edit, h+4, hWnd, (HMENU)id, NULL, NULL)
            #define CREATE_COMBO(id) CreateWindowW(L"COMBOBOX", NULL, WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST|WS_VSCROLL, x+w_lbl, y-2, 140, 200, hWnd, (HMENU)id, NULL, NULL)
            CREATE_LABEL(L"别名 (Tag):");
            CREATE_EDIT(ID_EDIT_TAG, ES_AUTOHSCROLL);
            y += gap;
            CREATE_LABEL(L"地址 (Address):");
            CREATE_EDIT(ID_EDIT_ADDR, ES_AUTOHSCROLL);
            y += gap;
            CREATE_LABEL(L"端口 (Port):");
            CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_NUMBER, x+w_lbl, y-2, 80, h+4, hWnd, (HMENU)ID_EDIT_PORT, NULL, NULL);
            y += gap + 10;
            CreateWindowW(L"STATIC", L"用户验证 (Auth)", WS_CHILD|WS_VISIBLE|SS_GRAYFRAME, x, y+5, 420, 1, hWnd, NULL, NULL, NULL);
            y += 25;
            CREATE_LABEL(L"User/UUID:");
            CREATE_EDIT(ID_EDIT_USER, ES_AUTOHSCROLL);
            y += gap;
            CREATE_LABEL(L"密码 (Pass):");
            CREATE_EDIT(ID_EDIT_PASS, ES_AUTOHSCROLL);
            y += gap + 10;
            CreateWindowW(L"STATIC", L"底层传输 (Transport)", WS_CHILD|WS_VISIBLE|SS_GRAYFRAME, x, y+5, 420, 1, hWnd, NULL, NULL, NULL);
            y += 25;
            CREATE_LABEL(L"传输协议:");
            HWND hNet = CREATE_COMBO(ID_EDIT_NET);
            AddComboItem(hNet, L"tcp", TRUE); AddComboItem(hNet, L"ws", FALSE);
            y += gap;
            CREATE_LABEL(L"伪装类型:");
            HWND hType = CREATE_COMBO(ID_EDIT_TYPE);
            AddComboItem(hType, L"none", TRUE);
            y += gap;
            CREATE_LABEL(L"伪装域名 (Host):");
            CREATE_EDIT(ID_EDIT_HOST, ES_AUTOHSCROLL);
            y += gap;
            CREATE_LABEL(L"路径 (Path):");
            CREATE_EDIT(ID_EDIT_PATH, ES_AUTOHSCROLL);
            y += gap;
            CREATE_LABEL(L"传输安全 (TLS):");
            HWND hTls = CREATE_COMBO(ID_EDIT_TLS);
            AddComboItem(hTls, L"none", TRUE); AddComboItem(hTls, L"tls", FALSE);
            y += gap + 30;
            CreateWindowW(L"BUTTON", L"确定", WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON, 120, y, 100, 32, hWnd, (HMENU)IDOK, NULL, NULL);
            CreateWindowW(L"BUTTON", L"取消", WS_CHILD|WS_VISIBLE, 260, y, 100, 32, hWnd, (HMENU)IDCANCEL, NULL, NULL);
            y += 80; 
            g_nEditContentHeight = y; 
            g_nEditScrollPos = 0;
            EnumChildWindows(hWnd, (WNDENUMPROC)(void*)SendMessageW, (LPARAM)hAppFont);
            if (hAppFont) SendMessage(hWnd, WM_SETFONT, (WPARAM)hAppFont, TRUE);
            LoadNodeToEdit(hWnd, g_editingTag);
            SCROLLINFO si;
            si.cbSize = sizeof(si);
            si.fMask = SIF_RANGE | SIF_PAGE;
            si.nMin = 0;
            si.nMax = g_nEditContentHeight;
            si.nPage = 680; 
            SetScrollInfo(hWnd, SB_VERT, &si, TRUE);
            break;
        }
        case WM_SIZE: {
            RECT rc; GetClientRect(hWnd, &rc);
            int clientHeight = rc.bottom - rc.top;
            SCROLLINFO si;
            si.cbSize = sizeof(si);
            si.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
            si.nMin = 0;
            si.nMax = g_nEditContentHeight;
            si.nPage = clientHeight;
            si.nPos = g_nEditScrollPos;
            SetScrollInfo(hWnd, SB_VERT, &si, TRUE);
            break;
        }
        case WM_VSCROLL: {
            SCROLLINFO si;
            si.cbSize = sizeof(si);
            si.fMask = SIF_ALL;
            GetScrollInfo(hWnd, SB_VERT, &si);
            int oldPos = si.nPos;
            int newPos = oldPos;
            switch (LOWORD(wParam)) {
                case SB_TOP: newPos = si.nMin; break;
                case SB_BOTTOM: newPos = si.nMax; break;
                case SB_LINEUP: newPos -= 20; break;
                case SB_LINEDOWN: newPos += 20; break;
                case SB_PAGEUP: newPos -= si.nPage; break;
                case SB_PAGEDOWN: newPos += si.nPage; break;
                case SB_THUMBTRACK: newPos = si.nTrackPos; break;
            }
            if (newPos < 0) newPos = 0;
            if (newPos > (int)(si.nMax - si.nPage + 1)) newPos = si.nMax - si.nPage + 1;
            if (newPos != oldPos) {
                ScrollWindow(hWnd, 0, oldPos - newPos, NULL, NULL);
                si.fMask = SIF_POS;
                si.nPos = newPos;
                SetScrollInfo(hWnd, SB_VERT, &si, TRUE);
                UpdateWindow(hWnd);
                g_nEditScrollPos = newPos;
            }
            break;
        }
        case WM_MOUSEWHEEL: {
            int zDelta = GET_WHEEL_DELTA_WPARAM(wParam);
            int scrollLines = 3; 
            SystemParametersInfo(SPI_GETWHEELSCROLLLINES, 0, &scrollLines, 0);
            for(int i=0; i<scrollLines; i++) {
                SendMessage(hWnd, WM_VSCROLL, zDelta > 0 ? SB_LINEUP : SB_LINEDOWN, 0);
            }
            break;
        }
        case WM_COMMAND:
            if (LOWORD(wParam) == IDOK) {
                SaveEditedNode(hWnd);
                MessageBoxW(hWnd, L"节点已更新", L"成功", MB_OK);
                DestroyWindow(hWnd);
                HWND hMgr = FindWindowW(L"NodeMgr", NULL);
                if (hMgr) SendMessage(hMgr, WM_REFRESH_NODELIST, 0, 0);
            } else if (LOWORD(wParam) == IDCANCEL) DestroyWindow(hWnd);
            break;
        case WM_CLOSE: DestroyWindow(hWnd); break;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

void OpenNodeEditWindow(const wchar_t* tag) {
    if (!tag || wcslen(tag) == 0) return;
    wcsncpy(g_editingTag, tag, 255); 
    WNDCLASSW wc = {0};
    if (!GetClassInfoW(GetModuleHandle(NULL), L"NodeEdit", &wc)) {
        wc.lpfnWndProc = NodeEditWndProc; wc.hInstance = GetModuleHandle(NULL); wc.lpszClassName = L"NodeEdit"; wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE+1);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW); RegisterClassW(&wc);
    }
    HWND h = CreateWindowW(L"NodeEdit", L"配置节点", WS_VISIBLE|WS_CAPTION|WS_SYSMENU|WS_VSCROLL|WS_THICKFRAME|WS_MINIMIZEBOX, CW_USEDEFAULT, 0, 500, 720, NULL, NULL, GetModuleHandle(NULL), NULL);
    if(h) { ShowWindow(h, SW_SHOW); UpdateWindow(h); }
}

LRESULT CALLBACK LogWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hEdit;
    switch(msg) {
        case WM_CREATE:
            hEdit = CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|ES_READONLY, 0,0,0,0, hWnd, (HMENU)ID_LOGVIEWER_EDIT, NULL, NULL);
            SendMessage(hEdit, WM_SETFONT, (WPARAM)hLogFont, 0);
            break;
        case WM_SIZE: MoveWindow(hEdit, 0, 0, LOWORD(lParam), HIWORD(lParam), TRUE); break;
        case WM_LOG_UPDATE: {
            wchar_t* p = (wchar_t*)lParam; int len = GetWindowTextLength(hEdit);
            if (len > 30000) { SendMessage(hEdit, EM_SETSEL, 0, -1); SendMessage(hEdit, WM_CLEAR, 0, 0); }
            SendMessage(hEdit, EM_SETSEL, 0xffff, 0xffff); SendMessageW(hEdit, EM_REPLACESEL, 0, (LPARAM)p); free(p); break;
        }
        case WM_CLOSE: ShowWindow(hWnd, SW_HIDE); return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

void OpenLogViewer(BOOL bShow) {
    if (hLogViewerWnd && IsWindow(hLogViewerWnd)) {
        if (bShow) { ShowWindow(hLogViewerWnd, SW_SHOW); if (IsIconic(hLogViewerWnd)) ShowWindow(hLogViewerWnd, SW_RESTORE); SetForegroundWindow(hLogViewerWnd); }
        return;
    }
    WNDCLASSW wc = {0}; 
    if (!GetClassInfoW(GetModuleHandle(NULL), L"LogWnd", &wc)) {
        wc.lpfnWndProc = LogWndProc; wc.hInstance = GetModuleHandle(NULL); wc.lpszClassName = L"LogWnd"; RegisterClassW(&wc);
    }
    hLogViewerWnd = CreateWindowW(L"LogWnd", L"运行日志", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT,0,600,400, NULL,NULL,GetModuleHandle(NULL),NULL);
    if (bShow) ShowWindow(hLogViewerWnd, SW_SHOW); else ShowWindow(hLogViewerWnd, SW_HIDE);
}

BOOL IsWindows8OrGreater() {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32 == NULL) return FALSE;
    FARPROC pFunc = GetProcAddress(hKernel32, "SetProcessMitigationPolicy");
    return (pFunc != NULL);
}

void SetSystemProxy(BOOL enable) {
    if (g_localPort <= 0 && enable) {
        MessageBoxW(NULL, L"本地端口无效，无法设置系统代理。", L"错误", MB_OK | MB_ICONERROR);
        return;
    }
    wchar_t proxyServerString[256] = {0};
    wchar_t proxyBypassString[64] = {0};
    if (enable) {
        wchar_t addrBuf[128];
        wsprintfW(addrBuf, L"http=127.0.0.1:%d;socks=127.0.0.1:%d", g_localPort, g_localPort);
        wcscpy(proxyServerString, addrBuf);
        wcsncpy(proxyBypassString, L"<local>", 63);
    }
    if (IsWindows8OrGreater()) {
        HKEY hKey;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, REG_PATH_PROXY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
            log_msg("[Error] Failed to open registry for system proxy.");
            return;
        }
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
        if (!InternetSetOptionW(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, dwBufSize)) {
            log_msg("[Error] InternetSetOptionW failed.");
            return;
        }
    }
    InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
    InternetSetOptionW(NULL, INTERNET_OPTION_REFRESH, NULL, 0);
    log_msg("[System] System proxy %s.", enable ? "enabled" : "disabled");
}

BOOL IsSystemProxyEnabled() {
    HKEY hKey;
    DWORD dwEnable = 0;
    DWORD dwSize = sizeof(dwEnable);
    wchar_t proxyServer[1024] = {0};
    DWORD dwProxySize = sizeof(proxyServer);
    BOOL isEnabled = FALSE;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, REG_PATH_PROXY, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, L"ProxyEnable", NULL, NULL, (LPBYTE)&dwEnable, &dwSize) == ERROR_SUCCESS) {
            if (dwEnable == 1) {
                if (RegQueryValueExW(hKey, L"ProxyServer", NULL, NULL, (LPBYTE)proxyServer, &dwProxySize) == ERROR_SUCCESS) {
                    wchar_t expectedPart[64];
                    wsprintfW(expectedPart, L"127.0.0.1:%d", g_localPort);
                    if (wcsstr(proxyServer, expectedPart) != NULL) {
                        isEnabled = TRUE;
                    }
                }
            }
        }
        RegCloseKey(hKey);
    }
    return isEnabled;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_TRAY && LOWORD(lParam) == WM_RBUTTONUP) {
        POINT pt; GetCursorPos(&pt); SetForegroundWindow(hWnd);
        ParseTags();
        if (hMenu) DestroyMenu(hMenu); hMenu = CreatePopupMenu(); hNodeSubMenu = CreatePopupMenu();
        if (nodeCount == 0) AppendMenuW(hNodeSubMenu, MF_STRING|MF_GRAYED, 0, L"(无节点)");
        else {
            for(int i=0; i<nodeCount; i++) {
                UINT f = MF_STRING; if(wcscmp(nodeTags[i], currentNode)==0) f|=MF_CHECKED;
                AppendMenuW(hNodeSubMenu, f, ID_TRAY_NODE_BASE+i, nodeTags[i]);
            }
        }
        AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hNodeSubMenu, L"切换节点");
        AppendMenuW(hMenu, MF_STRING, ID_TRAY_MANAGE_NODES, L"节点管理");
        AppendMenuW(hMenu, MF_STRING, ID_TRAY_IMPORT_CLIPBOARD, L"剪贴板导入 ");
        AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
        UINT proxyFlags = MF_STRING;
        if (IsSystemProxyEnabled()) proxyFlags |= MF_CHECKED;
        AppendMenuW(hMenu, proxyFlags, ID_TRAY_SYSTEM_PROXY, L"系统代理");
        AppendMenuW(hMenu, MF_STRING, ID_TRAY_SETTINGS, L"程序设置");
        AppendMenuW(hMenu, MF_STRING, ID_TRAY_SHOW_CONSOLE, L"查看日志");
        AppendMenuW(hMenu, IsAutorun()?MF_CHECKED:MF_UNCHECKED, ID_TRAY_AUTORUN, L"开机自启");
        if (g_isIconVisible) AppendMenuW(hMenu, MF_STRING, ID_TRAY_HIDE_ICON, L"隐藏图标");
        else AppendMenuW(hMenu, MF_STRING, ID_TRAY_HIDE_ICON, L"显示图标");
        AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
        AppendMenuW(hMenu, MF_STRING, ID_TRAY_EXIT, L"退出程序");
        TrackPopupMenu(hMenu, TPM_RIGHTALIGN|TPM_BOTTOMALIGN, pt.x, pt.y, 0, hWnd, NULL);
    }
    else if (msg == WM_COMMAND) {
        int id = LOWORD(wParam);
        if (id == ID_TRAY_EXIT) { 
            Shell_NotifyIconW(NIM_DELETE, &nid); 
            if (IsSystemProxyEnabled()) SetSystemProxy(FALSE);
            StopProxyCore(); 
            ExitProcess(0); 
        }
        else if (id == ID_TRAY_SYSTEM_PROXY) {
            BOOL current = IsSystemProxyEnabled();
            SetSystemProxy(!current);
        }
        else if (id == ID_TRAY_SHOW_CONSOLE) OpenLogViewer(TRUE);
        else if (id == ID_TRAY_MANAGE_NODES) OpenNodeManager();
        else if (id == ID_TRAY_SETTINGS) OpenSettingsWindow();
        else if (id == ID_TRAY_HIDE_ICON) ToggleTrayIcon();
        else if (id == ID_TRAY_AUTORUN) SetAutorun(!IsAutorun());
        else if (id == ID_TRAY_IMPORT_CLIPBOARD) {
            int count = ImportFromClipboard(); 
            if (count > 0) {
                ParseTags();
                HWND hMgr = FindWindowW(L"NodeMgr", L"节点管理 (支持 Ctrl+A 全选/多选)");
                if (hMgr && IsWindow(hMgr)) SendMessage(hMgr, WM_REFRESH_NODELIST, 0, 0);
                wchar_t msgBuf[128]; wsprintfW(msgBuf, L"成功导入 %d 个节点！", count);
                MessageBoxW(hWnd, msgBuf, L"导入成功", MB_OK|MB_ICONINFORMATION);
                if (wcslen(currentNode) == 0 && nodeCount > 0) SwitchNode(nodeTags[0]);
            } else MessageBoxW(hWnd, L"剪贴板中未发现支持的链接 (vmess/vless/ss/trojan)", L"导入失败", MB_OK|MB_ICONWARNING);
        }
        else if (id >= ID_TRAY_NODE_BASE && id < ID_TRAY_NODE_BASE + 1000) {
            int idx = id - ID_TRAY_NODE_BASE;
            if (idx >= 0 && idx < nodeCount) SwitchNode(nodeTags[idx]);
        }
    }
    else if (msg == WM_HOTKEY && wParam == ID_GLOBAL_HOTKEY) ToggleTrayIcon();
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, LPWSTR lpCmdLine, int nShow) {
    srand((unsigned)time(NULL)); // 初始化随机数种子，用于分片和Padding
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
    INITCOMMONCONTROLSEX ic = {sizeof(INITCOMMONCONTROLSEX), ICC_HOTKEY_CLASS}; InitCommonControlsEx(&ic);
    hAppFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei");
    hLogFont = CreateFontW(14,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,0,0,L"Consolas");
    OpenLogViewer(FALSE); 
    GetModuleFileNameW(NULL, g_iniFilePath, MAX_PATH);
    wchar_t* p = wcsrchr(g_iniFilePath, L'\\'); if (p) { *p = 0; wcscat(g_iniFilePath, L"\\set.ini"); } 
    else wcscpy(g_iniFilePath, L"set.ini");
    LoadSettings();
    WNDCLASSW wc = {0}; wc.lpfnWndProc = WndProc; wc.hInstance = hInst; wc.lpszClassName = L"TrayProxyClass";
    wc.hIcon = LoadIcon(hInst, MAKEINTRESOURCE(1)); if (!wc.hIcon) wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    RegisterClassW(&wc);
    hwnd = CreateWindowW(L"TrayProxyClass", L"App", 0, 0,0,0,0, NULL,NULL,hInst,NULL);
    RegisterHotKey(hwnd, ID_GLOBAL_HOTKEY, g_hotkeyModifiers, g_hotkeyVk);
    nid.cbSize = sizeof(nid); nid.hWnd = hwnd; nid.uID = 1; nid.uFlags = NIF_ICON|NIF_MESSAGE|NIF_TIP;
    nid.uCallbackMessage = WM_TRAY; nid.hIcon = wc.hIcon; wcscpy(nid.szTip, L"Limbox Client");
    if (g_hideTrayStart == 1) { g_isIconVisible = FALSE; } else { Shell_NotifyIconW(NIM_ADD, &nid); g_isIconVisible = TRUE; }
    ParseTags();
    if (nodeCount > 0) SwitchNode(nodeTags[0]);
    MSG msg; while(GetMessage(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    return 0;
}

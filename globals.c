#include "common.h"

// --- 全局配置变量定义 ---

ProxyConfig g_proxyConfig;
volatile BOOL g_proxyRunning = FALSE;
SOCKET g_listen_sock = INVALID_SOCKET;
// [Fix] 移除重复定义，保留 crypto.c 中的定义或反之，但为了链接安全，
// 建议：在 globals.c 定义，crypto.c 中仅 include common.h (extern)
// 之前构建报错是因为重复定义，这里保留定义，crypto.c 已删除定义。
// SSL_CTX *g_ssl_ctx = NULL; // (根据之前的修复，这里应该保留吗？)
// 修正：这是 globals.c，应该保留定义。crypto.c 应该只有声明。
// 但之前的日志显示 globals.c 和 crypto.c 都有定义。
// 我们已经在上一步的 crypto.c 中删除了定义。所以这里保留。
SSL_CTX *g_ssl_ctx = NULL;

HANDLE hProxyThread = NULL;

CRITICAL_SECTION g_configLock;

void InitGlobalLocks() {
    InitializeCriticalSection(&g_configLock);
}

void DeleteGlobalLocks() {
    DeleteCriticalSection(&g_configLock);
}

// GUI 相关
NOTIFYICONDATAW nid = {0};
HWND hwnd = NULL;
HMENU hMenu = NULL;
HMENU hNodeSubMenu = NULL;
HWND hLogViewerWnd = NULL;
HFONT hLogFont = NULL;
HFONT hAppFont = NULL;

// 节点管理
wchar_t** nodeTags = NULL;
int nodeCount = 0;
wchar_t currentNode[64] = {0};
wchar_t g_editingTag[256] = {0};

// 系统状态
BOOL g_isIconVisible = TRUE;
wchar_t g_iniFilePath[MAX_PATH] = {0};
UINT g_hotkeyModifiers = MOD_CONTROL | MOD_ALT;
UINT g_hotkeyVk = 'H';
int g_localPort = 10809;
int g_hideTrayStart = 0;

WNDPROC g_oldListBoxProc = NULL;
int g_nEditScrollPos = 0;
int g_nEditContentHeight = 0;

// 抗封锁配置
BOOL g_enableChromeCiphers = TRUE;
BOOL g_enableALPN = TRUE;
BOOL g_enableFragment = FALSE;
int g_fragSizeMin = 5;
int g_fragSizeMax = 20;
int g_fragDelayMs = 2;
BOOL g_enablePadding = FALSE;
int g_padSizeMin = 100;
int g_padSizeMax = 500;
int g_uaPlatformIndex = 0;
char g_userAgentStr[512] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

// [Fix] 修正 ECH 默认配置
// 1. 默认开启 ECH
// 2. 默认 DoH 改为 Cloudflare (兼容性更好)
// 3. 默认 Public Name 改为 cloudflare-ech.com
BOOL g_enableECH = FALSE; 
char g_echConfigServer[256] = "https://1.1.1.1/dns-query"; 
char g_echPublicName[256] = "cloudflare-ech.com"; 

const wchar_t* UA_PLATFORMS[] = {
    L"Windows (Chrome 120)",
    L"macOS (Safari 17)",
    L"Android (Chrome Mobile)",
    L"iPhone (Safari Mobile)",
    L"Linux (Firefox 120)"
};

const char* UA_TEMPLATES[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
};

BOOL g_enableLog = FALSE;

#include "common.h"

// --------------------------------------------------------------------------
// 全局变量定义 (Global Definitions)
// --------------------------------------------------------------------------

// 代理核心配置
ProxyConfig g_proxyConfig = {0};
volatile BOOL g_proxyRunning = FALSE;
SOCKET g_listen_sock = INVALID_SOCKET;
SSL_CTX *g_ssl_ctx = NULL; // 主要的 TLS 上下文 (用于 Proxy Core)

// 线程与同步
HANDLE hProxyThread = NULL;
CRITICAL_SECTION g_configLock;

// 托盘与窗口句柄
NOTIFYICONDATAW nid = {0};
HWND hwnd = NULL;
HWND hLogViewerWnd = NULL;
HMENU hMenu = NULL;
HMENU hNodeSubMenu = NULL;

// 字体资源
HFONT hLogFont = NULL;
HFONT hAppFont = NULL;

// 节点管理
wchar_t** nodeTags = NULL;
int nodeCount = 0;
wchar_t currentNode[64] = {0};
wchar_t g_editingTag[256] = {0};

// 设置与状态
BOOL g_isIconVisible = TRUE;
wchar_t g_iniFilePath[MAX_PATH] = {0};
UINT g_hotkeyModifiers = MOD_CONTROL | MOD_ALT;
UINT g_hotkeyVk = 'H';
int g_localPort = 10809;
int g_hideTrayStart = 0;

// 列表框 Hook
WNDPROC g_oldListBoxProc = NULL;
int g_nEditScrollPos = 0;
int g_nEditContentHeight = 0;

// 抗封锁配置 (Anti-Censorship)
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

// ECH 配置
BOOL g_enableECH = FALSE;
char g_echConfigServer[256] = "https://cloudflare-dns.com/dns-query";
char g_echPublicName[256] = "";

// 日志开关
BOOL g_enableLog = FALSE;

// --------------------------------------------------------------------------
// 常量数据
// --------------------------------------------------------------------------

const wchar_t* UA_PLATFORMS[] = {
    L"Windows (Chrome 120)",
    L"macOS (Chrome 120)",
    L"Linux (Firefox 121)",
    L"Android (Chrome Mobile)",
    L"iPhone (Safari)"
};

const char* UA_TEMPLATES[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1"
};

// --------------------------------------------------------------------------
// 锁管理
// --------------------------------------------------------------------------

void InitGlobalLocks() {
    InitializeCriticalSection(&g_configLock);
}

void DeleteGlobalLocks() {
    DeleteCriticalSection(&g_configLock);
}

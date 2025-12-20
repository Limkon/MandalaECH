#include "common.h"

// --- 全局配置变量定义 ---

ProxyConfig g_proxyConfig;
volatile BOOL g_proxyRunning = FALSE;
SOCKET g_listen_sock = INVALID_SOCKET;
SSL_CTX *g_ssl_ctx = NULL;
HANDLE hProxyThread = NULL;

// [Production Fix] 定义全局锁
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

// UI 滚动状态
WNDPROC g_oldListBoxProc = NULL;
int g_nEditScrollPos = 0;
int g_nEditContentHeight = 0;

// 抗封锁配置 (默认值)
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

// 定义常用 UA 模板
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

// 日志开关
BOOL g_enableLog = FALSE;

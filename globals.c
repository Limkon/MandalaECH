#include "common.h"
#include <openssl/ssl.h> // 必須包含此標頭以解決 SSL_CTX 錯誤

// --- 全局配置變量定義 ---

ProxyConfig g_proxyConfig;
BOOL g_proxyRunning = FALSE; // 移除 volatile 以匹配 common.h 中的聲明
SOCKET g_listen_sock = INVALID_SOCKET;
SSL_CTX *g_ssl_ctx = NULL;
HANDLE hProxyThread = NULL;

// GUI 相關
NOTIFYICONDATAW nid = {0};
HWND hwnd = NULL;
HMENU hMenu = NULL;
HMENU hNodeSubMenu = NULL;
HWND hLogViewerWnd = NULL;
HFONT hLogFont = NULL;
HFONT hAppFont = NULL;

// 節點管理
wchar_t** nodeTags = NULL;
int nodeCount = 0;
wchar_t currentNode[64] = {0};
wchar_t g_editingTag[256] = {0};

// 系統狀態
BOOL g_isIconVisible = TRUE;
wchar_t g_iniFilePath[MAX_PATH] = {0};
UINT g_hotkeyModifiers = MOD_CONTROL | MOD_ALT;
UINT g_hotkeyVk = 'H';
int g_localPort = 10809;
int g_hideTrayStart = 0;

// UI 滾動狀態
WNDPROC g_oldListBoxProc = NULL;
int g_nEditScrollPos = 0;
int g_nEditContentHeight = 0;

// 抗封鎖配置 (默認值)
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

// 注意：UA_PLATFORMS 和 UA_TEMPLATES 已在 common.h 中定義為 static，此處不再重複定義以避免 redefinition 錯誤

// 日誌開關
BOOL g_enableLog = FALSE;

#ifndef COMMON_H
#define COMMON_H

#include <winsock2.h>
#include <windows.h>

// [核心修正] 定義全域緩衝區大小，解決多個檔案的編譯錯誤
#define BUFFER_SIZE 65536

// [核心修正] 路徑分離：ini 用於設置，json 用於節點
extern wchar_t g_iniFilePath[MAX_PATH];    // 儲存 set.ini 路徑
extern wchar_t g_configFilePath[MAX_PATH]; // 儲存 config.json 路徑
#define CONFIG_FILE g_configFilePath       // 將節點配置指向 JSON 檔案

// 代理配置結構體
typedef struct {
    char type[32];      // 協議類型: vless, trojan, socks, shadowsocks, mandala, vmess
    char tag[256];      // 備註
    char host[256];     // 伺服器地址 (真實目標 IP 或域名 / Inner SNI)
    int port;           // 端口
    
    char user[256];     // UUID 或 用戶名
    char pass[256];     // 密碼
    
    char sni[256];      // TLS SNI (通常用於普通 TLS，或作為 ECH 的 Outer SNI)
    char path[256];     // WS Path / gRPC ServiceName
    
    // [ECH 新增字段]
    char outer_sni[256]; // ECH 偽裝域名 (Outer SNI, 例如 cloudflare-ech.com)
    char ech[2048];      // ECH 配置字串 (Base64)
} ProxyConfig;

// --- 全域變數聲明 (解決 undeclared 錯誤) ---
extern ProxyConfig g_proxyConfig;
extern int g_localPort;
extern BOOL g_enableLog;
extern BOOL g_proxyRunning;
extern HANDLE hProxyThread;
extern SOCKET g_listen_sock;

// 視窗與菜單控制
extern HWND hwnd;
extern HWND hLogViewerWnd;
extern HMENU hMenu;
extern HMENU hNodeSubMenu;
extern NOTIFYICONDATAW nid;
extern BOOL g_isIconVisible;

// UI 滾動與回調狀態
extern WNDPROC g_oldListBoxProc;
extern int g_nEditScrollPos;
extern int g_nEditContentHeight;

// 字型
extern HFONT hAppFont;
extern HFONT hLogFont;

// 節點管理
extern wchar_t** nodeTags;
extern int nodeCount;
extern wchar_t currentNode[64];
extern wchar_t g_editingTag[256];

// 抗封鎖配置
extern UINT g_hotkeyModifiers;
extern UINT g_hotkeyVk;
extern int g_hideTrayStart;
extern int g_enableChromeCiphers;
extern int g_enableALPN;
extern int g_enableFragment;
extern int g_fragSizeMin;
extern int g_fragSizeMax;
extern int g_fragDelayMs;
extern int g_enablePadding;
extern int g_padSizeMin;
extern int g_padSizeMax;
extern int g_uaPlatformIndex;
extern char g_userAgentStr[512];
extern char g_dohUrl[512]; // [ECH] 全域 DoH 地址

// UI 常量
#define ID_TRAY_EXIT            1001
#define ID_TRAY_Show            1002
#define ID_TRAY_HIDE            1003
#define ID_TRAY_SYSTEM_PROXY    1004
#define ID_TRAY_SHOW_CONSOLE    1005
#define ID_TRAY_MANAGE_NODES    1006
#define ID_TRAY_IMPORT_CLIPBOARD 1007
#define ID_TRAY_SETTINGS        1008
#define ID_TRAY_HIDE_ICON       1009
#define ID_TRAY_AUTORUN         1010
#define ID_GLOBAL_HOTKEY        1011
#define ID_TRAY_NODE_BASE       20000

#define WM_TRAY                 (WM_USER + 1)
#define WM_LOG_UPDATE           (WM_USER + 2)
#define WM_REFRESH_NODELIST     (WM_USER + 3)

// 顏色
#define COLOR_BTNFACE           15

// [修正] 改為 extern 聲明，由 globals.c 提供實際定義
extern const char* UA_TEMPLATES[];
extern const wchar_t* UA_PLATFORMS[];

// 函數聲明 (解決隱式聲明警告)
void SetSystemProxy(BOOL enable);
BOOL IsSystemProxyEnabled();

#endif // COMMON_H

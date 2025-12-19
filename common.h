#ifndef COMMON_H
#define COMMON_H

#include <winsock2.h>
#include <windows.h>

// 定義配置文件的路徑變數
extern wchar_t g_iniFilePath[MAX_PATH];
#define CONFIG_FILE g_iniFilePath

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

// 全局變量聲明
extern ProxyConfig g_proxyConfig;
extern int g_localPort;
extern BOOL g_enableLog;
extern BOOL g_proxyRunning;
extern HANDLE hProxyThread;
extern SOCKET g_listen_sock;

// 窗口句柄
extern HWND hwnd;
extern HWND hLogViewerWnd;
extern NOTIFYICONDATAW nid;
extern BOOL g_isIconVisible;

// 字體
extern HFONT hAppFont;
extern HFONT hLogFont;

// 節點列表
extern wchar_t** nodeTags;
extern int nodeCount;
extern wchar_t currentNode[64];
extern wchar_t g_editingTag[256];

// 高級設置
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

#endif // COMMON_H

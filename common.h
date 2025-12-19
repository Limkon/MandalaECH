#ifndef COMMON_H
#define COMMON_H

#include <winsock2.h>
#include <windows.h>

// 定义配置文件的路径变量
extern wchar_t g_iniFilePath[MAX_PATH];
#define CONFIG_FILE g_iniFilePath

// 代理配置结构体
typedef struct {
    char type[32];      // 协议类型: vless, trojan, socks, shadowsocks, mandala, vmess
    char tag[256];      // 备注
    char host[256];     // 服务器地址 (真实目标 IP 或域名 / Inner SNI)
    int port;           // 端口
    
    char user[256];     // UUID 或 用户名
    char pass[256];     // 密码
    
    char sni[256];      // TLS SNI (通常用于普通 TLS，或作为 ECH 的 Outer SNI)
    char path[256];     // WS Path / gRPC ServiceName
    
    // [ECH 新增字段]
    char outer_sni[256]; // ECH 伪装域名 (Outer SNI, 例如 cloudflare-ech.com)
    char ech[2048];      // ECH 配置字符串 (Base64)
} ProxyConfig;

// 全局变量声明
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

// 字体
extern HFONT hAppFont;
extern HFONT hLogFont;

// 节点列表
extern wchar_t** nodeTags;
extern int nodeCount;
extern wchar_t currentNode[64];
extern wchar_t g_editingTag[256];

// 高级设置
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

// 颜色
#define COLOR_BTNFACE           15

// UA 模板
static const char* UA_TEMPLATES[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.0.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
};
static const wchar_t* UA_PLATFORMS[] = { L"Windows", L"macOS", L"Linux", L"iOS", L"Android" };

#endif // COMMON_H

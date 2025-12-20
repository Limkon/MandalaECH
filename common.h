#ifndef COMMON_H
#define COMMON_H

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

// [Fix] 添加宏定义检查，防止与系统头文件冲突导致的重定义警告
#ifndef _WIN32_IE
#define _WIN32_IE 0x0601
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#define WIN32_LEAN_AND_MEAN
#define MAX_CONNECTIONS 512

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

// OpenSSL Headers
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "cJSON.h"

// --- 宏定义 ---
#define REG_PATH_PROXY L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
#define CONFIG_FILE L"config.json"

// [Refactor] 内存优化：分离 IO 缓冲区和最大帧限制
// IO_BUFFER_SIZE: 用于 TCP 接收和初始 WebSocket 缓冲区 (16KB)
#define IO_BUFFER_SIZE 16384 
// MAX_WS_FRAME_SIZE: WebSocket 最大允许帧大小 (8MB)，用于防止内存耗尽攻击，但允许大文件传输
#define MAX_WS_FRAME_SIZE 8388608 

// Windows Messages
#define WM_TRAY (WM_USER + 1)
#define WM_LOG_UPDATE (WM_USER + 2)
#define WM_REFRESH_NODELIST (WM_USER + 50)

// Command IDs
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

// GUI Control IDs
#define ID_LOGVIEWER_EDIT 6001
#define ID_LOG_CHK        6002 
#define ID_NODEMGR_LIST 3001
#define ID_NODEMGR_DEL 3002
#define ID_NODEMGR_EDIT 3003 
#define ID_HOTKEY_CTRL 7001 
#define ID_PORT_EDIT 7002

// Settings GUI IDs
#define ID_CHK_CIPHERS    7010
#define ID_CHK_ALPN       7011
#define ID_COMBO_PLATFORM 7012 
#define ID_EDIT_UA_STR    7013 
#define ID_CHK_FRAG       7014
#define ID_EDIT_FRAG_DLY  7016 
#define ID_EDIT_FRAG_MIN  7017
#define ID_EDIT_FRAG_MAX  7018
#define ID_CHK_PADDING    7019
#define ID_EDIT_PAD_MIN   7020
#define ID_EDIT_PAD_MAX   7021

// Node Edit IDs
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

// --- 结构体定义 ---
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
    char type[32]; 
} ProxyConfig;

// --- 全局变量声明 (extern) ---
extern ProxyConfig g_proxyConfig;
extern volatile BOOL g_proxyRunning;
extern SOCKET g_listen_sock;
extern SSL_CTX *g_ssl_ctx;
extern HANDLE hProxyThread;
extern NOTIFYICONDATAW nid;
extern HWND hwnd;
extern HMENU hMenu, hNodeSubMenu;
extern HWND hLogViewerWnd;
extern HFONT hLogFont;
extern HFONT hAppFont;
extern wchar_t** nodeTags;
extern int nodeCount;
extern wchar_t currentNode[64];
extern wchar_t g_editingTag[256];
extern BOOL g_isIconVisible;
extern wchar_t g_iniFilePath[MAX_PATH];
extern UINT g_hotkeyModifiers; 
extern UINT g_hotkeyVk;                          
extern int g_localPort;
extern int g_hideTrayStart; 
extern WNDPROC g_oldListBoxProc;
extern int g_nEditScrollPos;
extern int g_nEditContentHeight;

// 抗封锁配置
extern BOOL g_enableChromeCiphers;
extern BOOL g_enableALPN;
extern BOOL g_enableFragment;
extern int g_fragSizeMin;
extern int g_fragSizeMax;
extern int g_fragDelayMs;
extern BOOL g_enablePadding;
extern int g_padSizeMin;
extern int g_padSizeMax;
extern int g_uaPlatformIndex; 
extern char g_userAgentStr[512];

extern const wchar_t* UA_PLATFORMS[];
extern const char* UA_TEMPLATES[];

extern BOOL g_enableLog;

extern CRITICAL_SECTION g_configLock; 
void InitGlobalLocks();
void DeleteGlobalLocks();

#endif // COMMON_H

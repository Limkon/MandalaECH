#ifndef COMMON_H
#define COMMON_H

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

// 防止旧版 SDK 警告
#ifndef _WIN32_IE
#define _WIN32_IE 0x0601
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#define WIN32_LEAN_AND_MEAN

// 尝试阻止 windows.h 包含 wincrypt.h
#define NOCRYPT 

#define MAX_CONNECTIONS 512

// --- 1. Windows 系统头文件 ---
#include <windows.h>
#include <shellapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <commctrl.h>
#include <shlobj.h>
#include <wininet.h>

// --- 2. 引入资源头文件 (解决重定义警告) ---
// 必须包含此文件以获取 GUI 控件 ID (ID_CHK_FRAG 等)
#include "resource.h"

// --- 3. 清理 Windows 宏污染 ---
#ifdef X509_NAME
#undef X509_NAME
#endif
#ifdef X509_EXTENSIONS
#undef X509_EXTENSIONS
#endif
#ifdef X509_CERT_PAIR
#undef X509_CERT_PAIR
#endif
#ifdef PKCS7_ISSUER_AND_SERIAL
#undef PKCS7_ISSUER_AND_SERIAL
#endif
#ifdef PKCS7_SIGNER_INFO
#undef PKCS7_SIGNER_INFO
#endif
#ifdef OCSP_REQUEST
#undef OCSP_REQUEST
#endif
#ifdef OCSP_RESPONSE
#undef OCSP_RESPONSE
#endif

// --- 4. 标准 C 头文件 ---
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <time.h>
#include <ctype.h>

// --- 5. OpenSSL/BoringSSL 头文件 ---
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "cJSON.h"

// --- 宏定义 ---
#define REG_PATH_PROXY L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
#define CONFIG_FILE L"config.json"

#define IO_BUFFER_SIZE 16384 
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

// ECH 设置控件 ID
#define ID_CHK_ECH         7022
#define ID_EDIT_ECH_SERVER 7023
#define ID_EDIT_ECH_DOMAIN 7024

// --- 结构体定义 ---

// [修复] 补充抗封锁配置结构体，解决 proxy.c 和 crypto.c 的编译错误
typedef struct {
    BOOL enableFragment;
    int fragMin;
    int fragMax;
    int fragDelay;
    BOOL enablePadding;
    int padMin;
    int padMax;
    BOOL enableChromeCiphers;
} CryptoSettings;

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

// 抗封锁配置全局变量
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

// ECH 全局配置变量
extern BOOL g_enableECH;
extern char g_echConfigServer[256]; 
extern char g_echPublicName[256];   

extern const wchar_t* UA_PLATFORMS[];
extern const char* UA_TEMPLATES[];

extern BOOL g_enableLog;

extern CRITICAL_SECTION g_configLock; 

// --- 函数原型声明 ---

// [修复] 补充 log_msg 声明，解决多处隐式调用错误
void log_msg(const char* fmt, ...);

void InitGlobalLocks();
void DeleteGlobalLocks();

#endif // COMMON_H

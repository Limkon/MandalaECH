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

// 减少 Windows 头文件包含的内容
#define WIN32_LEAN_AND_MEAN

// 尝试阻止 windows.h 包含 wincrypt.h
#define NOCRYPT 

#define MAX_CONNECTIONS 512

// --- 1. Windows 系统头文件 (必须先包含) ---
#include <windows.h>
#include <shellapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <commctrl.h>
#include <shlobj.h>
#include <wininet.h>

// --- 2. [关键修复] 强制清理 Windows 宏污染 ---
// 即使定义了 NOCRYPT，某些环境仍可能引入这些与 OpenSSL/BoringSSL 冲突的宏。
// 必须在包含 OpenSSL 头文件之前手动 undef 它们。

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

// --- 3. 标准 C 头文件 ---
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <time.h>
#include <ctype.h>

// --- 4. OpenSSL/BoringSSL 头文件 (现在是安全的) ---
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "cJSON.h"

// --- 宏定义 ---
#define REG_PATH_PROXY L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
#define CONFIG_FILE L"config.json"

// IO_BUFFER_SIZE: 用于 TCP 接收和初始 WebSocket 缓冲区 (16KB)
#define IO_BUFFER_SIZE 16384 
// MAX_WS_FRAME_SIZE: WebSocket 最大允许帧大小 (8MB)
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

// ECH 设置控件 ID
#define ID_CHK_ECH         7022
#define ID_EDIT_ECH_SERVER 7023
#define ID_EDIT_ECH_DOMAIN 7024

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

// ECH 全局配置变量
extern BOOL g_enableECH;
extern char g_echConfigServer[256]; 
extern char g_echPublicName[256];   

extern const wchar_t* UA_PLATFORMS[];
extern const char* UA_TEMPLATES[];

extern BOOL g_enableLog;

extern CRITICAL_SECTION g_configLock; 
void InitGlobalLocks();
void DeleteGlobalLocks();

#endif // COMMON_H

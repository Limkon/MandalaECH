#ifndef COMMON_H
#define COMMON_H

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

// 防止旧版 SDK 警告，锁定最低支持 Windows 7 (0x0601)
#ifndef _WIN32_IE
#define _WIN32_IE 0x0601
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#define WIN32_LEAN_AND_MEAN

// 尝试阻止 windows.h 包含 wincrypt.h 以避免与 OpenSSL 冲突
#define NOCRYPT 

// --- 生产环境限制参数 ---
#define MAX_CONNECTIONS 512
#define IO_BUFFER_SIZE 16384 
// 允许的最大单帧大小 (8MB)，但在处理时将增加更严苛的内存水位检查
#define MAX_WS_FRAME_SIZE 8388608 
// 生产环境建议：单个进程用于网络缓冲的最大内存总量 (如 512MB)，防止 OOM
#define MAX_TOTAL_MEMORY_USAGE (512 * 1024 * 1024)

// --- 调试与安全配置 ---
#define LOG_DESENSITIZE TRUE  // 开启日志脱敏，隐藏密码和敏感 Host

// --- 1. Windows 系统头文件 ---
#include <windows.h>
#include <shellapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <commctrl.h>
#include <shlobj.h>
#include <wininet.h>

// --- 2. 引入资源头文件 ---
#include "resource.h"

// --- 3. 清理 Windows 宏污染 (解决与 OpenSSL 的命名冲突) ---
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

// --- 全局变量声明 ---
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

// 内存水位管理变量 (由 proxy.c 维护)
extern volatile LONG64 g_total_allocated_mem;

extern CRITICAL_SECTION g_configLock; 
void InitGlobalLocks();
void DeleteGlobalLocks();

// --- 生产环境优化：内存池声明 ---
// 仅针对 IO_BUFFER_SIZE (16KB) 的缓冲区进行池化
void InitMemoryPool();
void CleanupMemoryPool();
void* Pool_Alloc_16K();
void Pool_Free_16K(void* ptr);

#endif // COMMON_H

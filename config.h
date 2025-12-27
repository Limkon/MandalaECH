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
#define NOCRYPT 

// --- 生产环境限制参数 ---
#define MAX_CONNECTIONS 10000
#define IO_BUFFER_SIZE 16384 
#define MAX_WS_FRAME_SIZE 8388608 
#define MAX_TOTAL_MEMORY_USAGE (1024LL * 1024 * 1024) // 1GB

#define LOG_DESENSITIZE TRUE

// --- Windows 头文件 ---
#include <windows.h>
#include <shellapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h> 
#include <commctrl.h>
#include <shlobj.h>
#include <wininet.h>

#include "resource.h"

// --- OpenSSL ---
#ifdef X509_NAME
#undef X509_NAME
#endif
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
#define ID_CHK_ECH         7022
#define ID_EDIT_ECH_SERVER 7023
#define ID_EDIT_ECH_DOMAIN 7024

// --- [IOCP] 结构体定义 ---

typedef enum {
    IO_READ_CLIENT,
    IO_WRITE_CLIENT,
    IO_READ_REMOTE,
    IO_WRITE_REMOTE
} IO_OPERATION_TYPE;

typedef struct {
    OVERLAPPED overlapped;
    IO_OPERATION_TYPE opType;
    WSABUF wsaBuf;
    char buffer[IO_BUFFER_SIZE]; 
    DWORD bytesTransferred;
} IO_CONTEXT;

typedef struct {
    SOCKET clientSock;
    SOCKET remoteSock;
    SSL *ssl;
    
    // IOCP 使用 Memory BIO
    BIO *io_in;  
    BIO *io_out; 
    
    // 用于 WS 解析的残留缓冲区
    char *ws_frag_buf;
    int ws_frag_len;
    int ws_frag_cap;

    // 两个方向的 IO 上下文
    IO_CONTEXT rxClient; 
    IO_CONTEXT rxRemote; 
    
    volatile LONG refCount; 
    BOOL closing;

    // [关键修复] 之前缺失的字段，导致编译错误
    BOOL is_vless;
    BOOL header_stripped;
} CONNECTION_CONTEXT;

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
extern HANDLE hIOCP; 

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

extern BOOL g_enableECH;
extern char g_echConfigServer[256]; 
extern char g_echPublicName[256];   

extern const wchar_t* UA_PLATFORMS[];
extern const char* UA_TEMPLATES[];

extern BOOL g_enableLog;
extern volatile LONG64 g_total_allocated_mem;
extern CRITICAL_SECTION g_configLock; 

// 锁初始化函数
void InitGlobalLocks();
void DeleteGlobalLocks();

#endif // COMMON_H

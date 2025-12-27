// common.h
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
// [IOCP] 连接数限制主要受内存限制，可大幅提高
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
#include <mswsock.h> // AcceptEx, GetAcceptExSockaddrs
#include <commctrl.h>
#include <shlobj.h>
#include <wininet.h>

#include "resource.h"

// --- OpenSSL ---
#ifdef X509_NAME
#undef X509_NAME
#endif
// ... (保留原有的宏清理) ...
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

// 操作类型
typedef enum {
    IO_READ_CLIENT,
    IO_WRITE_CLIENT,
    IO_READ_REMOTE,
    IO_WRITE_REMOTE
} IO_OPERATION_TYPE;

// 单次 IO 操作的上下文 (继承自 OVERLAPPED)
typedef struct {
    OVERLAPPED overlapped;
    IO_OPERATION_TYPE opType;
    WSABUF wsaBuf;
    char buffer[IO_BUFFER_SIZE]; // 每个操作独立的缓冲区
    DWORD bytesTransferred;
} IO_CONTEXT;

// 每个连接的上下文
typedef struct {
    SOCKET clientSock;
    SOCKET remoteSock;
    SSL *ssl;
    
    // IOCP 使用 Memory BIO
    BIO *io_in;  // 写加密数据供 SSL_read
    BIO *io_out; // 读加密数据供发送
    
    // 用于 WS 解析的残留缓冲区
    char *ws_frag_buf;
    int ws_frag_len;
    int ws_frag_cap;

    // 两个方向的 IO 上下文
    IO_CONTEXT rxClient; // 从 Client 读 (明文)
    IO_CONTEXT rxRemote; // 从 Remote 读 (密文)
    
    // 发送通常是即时提交的，但也需要 Context 追踪完成
    // 简化起见，我们在 Worker 中动态分配 Write Context 或使用对象池
    // 这里保留引用计数以决定何时释放 Connection
    volatile LONG refCount; 
    BOOL closing;
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
extern HANDLE hIOCP; // IOCP 句柄

// ... (保留原有全局变量) ...
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

void InitGlobalLocks();
void DeleteGlobalLocks();

#endif // COMMON_H

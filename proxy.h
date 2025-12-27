#ifndef PROXY_H
#define PROXY_H

#include <winsock2.h>
#include <windows.h>
#include "crypto.h" 

// --- 常量定义 ---
#define IO_BUFFER_SIZE 16384
#define MAX_CONNECTIONS 512
// 确保只定义一次
#ifndef MAX_TOTAL_MEMORY_USAGE
#define MAX_TOTAL_MEMORY_USAGE (1024LL * 1024 * 1024) 
#endif

// --- 数据结构 ---
typedef struct {
    char host[256];
    int port;
    char user[256];
    char pass[256];
    char sni[256];
    char path[256];
    char type[32];
} ProxyConfig;

// --- 全局变量声明 ---
// 核心运行状态
extern BOOL g_proxyRunning; 
extern int g_localPort;
extern int g_hideTrayStart; // 补充声明

// 统计
extern volatile LONG g_active_connections;
extern volatile LONG64 g_total_allocated_mem;

// 配置对象
extern ProxyConfig g_proxyConfig;
extern CRITICAL_SECTION g_configLock;

// --- 函数声明 ---
void StartProxyCore();
void StopProxyCore();

// 内存管理
void Proxy_InitMemPool();
void Proxy_CleanupMemPool();
void* Proxy_PoolAlloc();
void Proxy_PoolFree(void* ptr);
void* Proxy_Malloc(size_t size);
void Proxy_Free(void* p, size_t size);

#endif // PROXY_H

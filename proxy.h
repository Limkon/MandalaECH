#ifndef PROXY_H
#define PROXY_H

#include <winsock2.h>
#include <windows.h>
#include "crypto.h" // 引用 CryptoSettings 定义

// --- 常量定义 ---
#define IO_BUFFER_SIZE 16384            // 标准 I/O 缓冲区大小 (16KB)
#define MAX_CONNECTIONS 512             // 最大并发连接限制 (防止句柄耗尽)
#define MAX_TOTAL_MEMORY_USAGE (1024LL * 1024 * 1024) // 全局内存水位限制 (1GB)

// --- 数据结构 ---

// 代理节点配置结构
// 对应 config.c 中的解析逻辑
typedef struct {
    char host[256];
    int port;
    char user[256];     // UUID 或 用户名
    char pass[256];     // 密码
    char sni[256];      // TLS SNI
    char path[256];     // WebSocket Path
    char type[32];      // 协议类型: vless, trojan, socks, shadowsocks, mandala
} ProxyConfig;

// --- 全局变量声明 ---

// 运行状态控制
extern BOOL g_proxyRunning;
extern int g_localPort;

// 统计与监控
extern volatile LONG g_active_connections;
extern volatile LONG64 g_total_allocated_mem;

// 配置与同步
extern ProxyConfig g_proxyConfig;
extern CRITICAL_SECTION g_configLock;
extern char g_userAgentStr[512];

// --- 函数声明 ---

// 核心控制
void StartProxyCore();
void StopProxyCore();

// 内存管理 (重构核心：引入内存池)
// 用于减少高并发下的 malloc/free 开销和碎片
void Proxy_InitMemPool();       // 初始化全局内存池
void Proxy_CleanupMemPool();    // 清理并销毁内存池

// 从池中分配一个固定大小(IO_BUFFER_SIZE)的缓冲区
// 如果池为空，则回退到 malloc
void* Proxy_PoolAlloc();        

// 将缓冲区归还给池
// 必须是 Proxy_PoolAlloc 分配的指针
void Proxy_PoolFree(void* ptr); 

// 通用内存分配 (带全局水位控制)
// 用于非固定大小或需要动态扩容的内存
void* Proxy_Malloc(size_t size);

// 通用内存释放
void Proxy_Free(void* p, size_t size);

#endif // PROXY_H

#ifndef PROXY_H
#define PROXY_H

#include "common.h"

// 启动代理核心服务 (启动监听线程)
void StartProxyCore();

// 停止代理核心服务 (关闭 Socket，清理线程)
void StopProxyCore();

// 代理监听线程入口 (通常由 StartProxyCore 内部调用)
DWORD WINAPI server_thread(LPVOID p);

// 客户端处理线程入口
DWORD WINAPI client_handler(LPVOID p);

// 内存池初始化 (内部使用)
void init_buffer_pool();

#endif // PROXY_H

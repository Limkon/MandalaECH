#ifndef PROXY_H
#define PROXY_H

#include "common.h"

// --- 代理核心控制函数 ---

// 启动代理监听线程
void StartProxyCore();

// 停止代理并释放资源
void StopProxyCore();

// 监听线程入口 (通常由 StartProxyCore 内部调用，但如果需要在外部创建线程也可暴露)
DWORD WINAPI server_thread(LPVOID p);

// 客户端处理线程入口 (通常由 accept 循环调用)
DWORD WINAPI client_handler(LPVOID p);

#endif // PROXY_H

#ifndef PROXY_H
#define PROXY_H

#include "common.h"

void StartProxyCore();
void StopProxyCore();
int recv_timeout(SOCKET s, char *buf, int len, int timeout_sec);
int send_all(SOCKET s, const char *buf, int len);

// [Fix] 使用 _beginthreadex 兼容的签名
unsigned __stdcall server_thread(void* p);
unsigned __stdcall client_handler(void* p);

#endif // PROXY_H

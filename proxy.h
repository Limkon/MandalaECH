#ifndef PROXY_H
#define PROXY_H

#include "common.h"

void StartProxyCore();
void StopProxyCore();
int recv_timeout(SOCKET s, char *buf, int len, int timeout_sec);
int send_all(SOCKET s, const char *buf, int len);

DWORD WINAPI server_thread(LPVOID p);
DWORD WINAPI client_handler(LPVOID p);

#endif // PROXY_H
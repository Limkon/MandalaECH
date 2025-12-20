#ifndef UTILS_H
#define UTILS_H

#include <windows.h>

// 日志
#define WM_LOG_UPDATE (WM_USER + 1)
void log_msg(const char *format, ...);
void log_wsa_error(const char* context);

// 网络与 HTTP
char* Utils_HttpGet(const char* url);
char* Utils_HttpBytesGet(const char* url, int* out_len);
char* FetchECHFromDoH(const char* dohUrl, const char* sni);

// 编码解码
unsigned char* Base64Decode(const char* src, size_t* out_len);
void Base64Encode(const unsigned char* src, int len, char* dst);
void Base64UrlEncode(const unsigned char* src, int len, char* dst);

// 其他工具
BOOL ReadFileToBuffer(const wchar_t* filename, char** buffer, long* fileSize);
BOOL WriteBufferToFile(const wchar_t* filename, const char* buffer);
char* GetClipboardText();
void TrimString(char* str);
char* GetQueryParam(const char* query, const char* key);

// 系统代理
void SetSystemProxy(BOOL enable);
BOOL IsSystemProxyEnabled();

#endif // UTILS_H

#ifndef UTILS_H
#define UTILS_H

#include "common.h"

void SetSystemProxy(BOOL enable);
BOOL IsSystemProxyEnabled();

// 日志记录函数
void log_msg(const char *format, ...);
// 记录 Winsock 错误
void log_wsa_error(const char* context);

// 文件读写辅助
BOOL ReadFileToBuffer(const wchar_t* filename, char** buffer, long* fileSize);
BOOL WriteBufferToFile(const wchar_t* filename, const char* buffer);

// 字符串辅助
void TrimString(char* str);
void UrlDecode(char* dst, const char* src);
char* GetQueryParam(const char* query, const char* key);
unsigned char* Base64Decode(const char* src, size_t* out_len);
char* GetClipboardText();

// HTTP 请求 (文本版)
char* Utils_HttpGet(const char* url);

// [ECH] HTTP 请求 (二进制版)
char* Utils_HttpBytesGet(const char* url, int* out_len);

// [ECH] Base64Url 编码
void Base64UrlEncode(const unsigned char* src, int len, char* dst);

// [ECH] 从 DoH 获取 ECH Config (返回 Base64 字符串)
char* FetchECHFromDoH(const char* dohUrl, const char* sni);

#endif


#ifndef UTILS_H
#define UTILS_H

#include "common.h"

// 日志
void log_msg(const char *format, ...);
void log_wsa_error(const char* context);

// 文件
BOOL ReadFileToBuffer(const wchar_t* filename, char** buffer, long* fileSize);
BOOL WriteBufferToFile(const wchar_t* filename, const char* buffer);

// 字符串
void TrimString(char* str);
void UrlDecode(char* dst, const char* src);
char* GetQueryParam(const char* query, const char* key);

// 剪贴板
char* GetClipboardText();

// 网络
char* Utils_HttpGet(const char* url);

// Base64
unsigned char* Base64Decode(const char* src, size_t* out_len);

// [新增] ECH 获取函数声明
char* FetchECHFromDoH(const char* dohUrl, const char* sni);

// 系统代理
BOOL IsWindows8OrGreater();
void SetSystemProxy(BOOL enable);
BOOL IsSystemProxyEnabled();

#endif // UTILS_H

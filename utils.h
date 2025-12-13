#ifndef UTILS_H
#define UTILS_H

#include "common.h"

void log_msg(const char *format, ...);
void log_wsa_error(const char* context);
char* GetClipboardText(); 
void TrimString(char* str);
void UrlDecode(char* dst, const char* src);
unsigned char* Base64Decode(const char* src, size_t* out_len);
char* GetQueryParam(const char* query, const char* key);
BOOL ReadFileToBuffer(const wchar_t* filename, char** buffer, long* fileSize);
BOOL WriteBufferToFile(const wchar_t* filename, const char* buffer);

// --- 网络功能 (新增) ---
// 下载指定 URL 内容，超时时间固定为 10 秒
char* Utils_HttpGet(const char* url);

// --- 系统代理功能 ---
BOOL IsWindows8OrGreater();
void SetSystemProxy(BOOL enable);
BOOL IsSystemProxyEnabled();

#endif // UTILS_H

#ifndef UTILS_H
#define UTILS_H

#include <windows.h>
#include <stdio.h>
#include "cJSON.h" 

// --- 字符串与数据处理 ---
unsigned char* Base64Decode(const char* input, size_t* out_len);
void TrimString(char* str);
void UrlDecode(char* dst, const char* src);
char* GetQueryParam(const char* query, const char* key);
char* GetClipboardText();

// [Fix] 暴露给 config.c 使用
char* SafeStrDup(const char* s, int len);

// --- 网络与 ECH ---
char* Utils_HttpGet(const char* url);
unsigned char* FetchECHConfig(const char* domain, const char* doh_server, size_t* out_len);

// --- 文件操作 ---
BOOL ReadFileToBuffer(const wchar_t* filename, char** buffer, long* size);
BOOL WriteBufferToFile(const wchar_t* filename, const char* buffer);

// --- 系统设置 ---
void SetSystemProxy(BOOL enable);
BOOL IsSystemProxyEnabled();
BOOL IsWindows8OrGreater();

// --- 日志 ---
void log_msg(const char *format, ...);

// --- 内存池 ---
void InitMemoryPool();
void CleanupMemoryPool();
void* Pool_Alloc_16K();
void Pool_Free_16K(void* ptr);

#endif // UTILS_H

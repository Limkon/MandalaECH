#ifndef UTILS_H
#define UTILS_H

#include "common.h"

// --- 基础工具函数 ---
void log_msg(const char *format, ...);
// [Delete] log_wsa_error 未在 utils.c 实现，已删除

char* GetClipboardText();
void TrimString(char* str);
void UrlDecode(char* dst, const char* src);
unsigned char* Base64Decode(const char* src, size_t* out_len);
char* GetQueryParam(const char* query, const char* key);
BOOL ReadFileToBuffer(const wchar_t* filename, char** buffer, long* fileSize);
BOOL WriteBufferToFile(const wchar_t* filename, const char* buffer);

// --- 网络功能 ---
char* Utils_HttpGet(const char* url);

// --- 系统代理功能 ---
BOOL IsWindows8OrGreater();
void SetSystemProxy(BOOL enable);
BOOL IsSystemProxyEnabled();

// --- [新增] ECH 功能 ---
// 供 crypto.c 调用
unsigned char* FetchECHConfig(const char* domain, const char* doh_server, size_t* out_len);

#endif // UTILS_H

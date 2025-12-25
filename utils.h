#ifndef UTILS_H
#define UTILS_H

#include "common.h"

// --- 文件操作 ---
BOOL ReadFileToBuffer(const wchar_t* filename, char** buffer, long* size);
BOOL WriteBufferToFile(const wchar_t* filename, const char* buffer);

// --- 字符串处理 ---
void TrimString(char* str);
void UrlDecode(char* dst, const char* src);
// 从 URL 查询字符串中提取参数值 (需调用 free 释放返回值)
char* GetQueryParam(const char* query, const char* key);

// --- 编码/网络 ---
// Base64 解码 (需调用 free 释放返回值)
unsigned char* Base64Decode(const char* input, size_t* out_len);

// 发起简单的 HTTPS GET 请求 (用于订阅更新/ECH查询)
char* Utils_HttpGet(const char* url);

// 通过 DoH 获取 ECH 配置
unsigned char* FetchECHConfig(const char* domain, const char* doh_server, size_t* out_len);

// --- 系统交互 ---
char* GetClipboardText();
void SetSystemProxy(BOOL enable);
BOOL IsSystemProxyEnabled();
BOOL IsWindows8OrGreater();

#endif // UTILS_H

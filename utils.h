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

#endif // UTILS_H
#include "utils.h"
#include "common.h"
#include "cJSON.h"
#include <windows.h>
#include <wininet.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "user32.lib")

// --- 1. 字符编码转换工具 ---

wchar_t* UTF8ToWide(const char* str) {
    if (!str) return NULL;
    int len = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    if (len == 0) return NULL;
    wchar_t* wstr = (wchar_t*)malloc(len * sizeof(wchar_t));
    if (wstr) MultiByteToWideChar(CP_UTF8, 0, str, -1, wstr, len);
    return wstr;
}

char* WideToUTF8(const wchar_t* wstr) {
    if (!wstr) return NULL;
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (len == 0) return NULL;
    char* str = (char*)malloc(len);
    if (str) WideCharToMultiByte(CP_UTF8, 0, wstr, -1, str, len, NULL, NULL);
    return str;
}

// --- 2. Base64 工具 (支持标准和 URL-Safe) ---

static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char* Base64Encode(const unsigned char* data, size_t input_length) {
    size_t output_length = 4 * ((input_length + 2) / 3);
    char* encoded_data = (char*)malloc(output_length + 1);
    if (encoded_data == NULL) return NULL;

    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = base64_chars[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < (int)(3 - input_length % 3) % 3; i++)
        encoded_data[output_length - 1 - i] = '=';

    encoded_data[output_length] = '\0';
    return encoded_data;
}

unsigned char* Base64Decode(const char* data, size_t* out_len) {
    if (!data) return NULL;
    size_t input_length = strlen(data);
    
    // URL-Safe Base64 兼容处理 (- -> +, _ -> /)
    char* temp_data = _strdup(data);
    if (!temp_data) return NULL;
    for (size_t i = 0; i < input_length; i++) {
        if (temp_data[i] == '-') temp_data[i] = '+';
        else if (temp_data[i] == '_') temp_data[i] = '/';
    }

    int padding = 0;
    if (input_length > 0 && temp_data[input_length - 1] == '=') padding++;
    if (input_length > 1 && temp_data[input_length - 2] == '=') padding++;

    size_t output_length = (input_length / 4) * 3 - padding;
    unsigned char* decoded_data = (unsigned char*)malloc(output_length + 1);
    if (decoded_data == NULL) { free(temp_data); return NULL; }

    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : strchr(base64_chars, temp_data[i++]) - base64_chars;
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : strchr(base64_chars, temp_data[i++]) - base64_chars;
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : strchr(base64_chars, temp_data[i++]) - base64_chars;
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : strchr(base64_chars, temp_data[i++]) - base64_chars;
        uint32_t triple = (sextet_a << 3 * 6) + (sextet_b << 2 * 6) + (sextet_c << 1 * 6) + (sextet_d << 0 * 6);

        if (j < output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    decoded_data[output_length] = '\0';
    if (out_len) *out_len = output_length;
    free(temp_data);
    return decoded_data;
}

// --- 3. 文件操作 ---

BOOL ReadFileToBuffer(const wchar_t* filename, char** buffer, long* size) {
    FILE* f = _wfopen(filename, L"rb");
    if (!f) return FALSE;
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    *buffer = (char*)malloc(fsize + 1);
    if (!*buffer) { fclose(f); return FALSE; }
    
    fread(*buffer, 1, fsize, f);
    (*buffer)[fsize] = 0;
    fclose(f);
    if (size) *size = fsize;
    return TRUE;
}

BOOL WriteBufferToFile(const wchar_t* filename, const char* buffer) {
    FILE* f = _wfopen(filename, L"wb");
    if (!f) return FALSE;
    fwrite(buffer, 1, strlen(buffer), f);
    fclose(f);
    return TRUE;
}

// --- 4. 剪贴板 ---

char* GetClipboardText() {
    if (!OpenClipboard(NULL)) return NULL;
    HANDLE hData = GetClipboardData(CF_TEXT);
    if (hData == NULL) { CloseClipboard(); return NULL; }
    char* pszText = (char*)GlobalLock(hData);
    if (pszText == NULL) { CloseClipboard(); return NULL; }
    char* text = _strdup(pszText);
    GlobalUnlock(hData);
    CloseClipboard();
    return text;
}

// --- 5. 字符串与 URL 处理 ---

void TrimString(char* str) {
    if (!str) return;
    char* p = str;
    char* l = str + strlen(str) - 1;
    while(isspace(*p)) p++;
    while(l > p && isspace(*l)) l--;
    *(l + 1) = 0;
    if(p != str) memmove(str, p, strlen(p) + 1);
}

void UrlDecode(char* dst, const char* src) {
    char a, b;
    while (*src) {
        if ((*src == '%') &&
            ((a = src[1]) && (b = src[2])) &&
            (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a') a -= 'a' - 'A';
            if (a >= 'A') a -= ('A' - 10);
            else a -= '0';
            if (b >= 'a') b -= 'a' - 'A';
            if (b >= 'A') b -= ('A' - 10);
            else b -= '0';
            *dst++ = 16 * a + b;
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst++ = '\0';
}

char* GetQueryParam(const char* query, const char* key) {
    if (!query || !key) return NULL;
    char keyEq[64]; snprintf(keyEq, 64, "%s=", key);
    const char* start = query;
    while ((start = strstr(start, keyEq)) != NULL) {
        if (start == query || *(start-1) == '&' || *(start-1) == '?') {
            start += strlen(keyEq);
            const char* end = strpbrk(start, "&");
            int len = end ? (int)(end - start) : (int)strlen(start);
            char* val = (char*)malloc(len + 1);
            strncpy(val, start, len); val[len] = 0;
            return val;
        }
        start++;
    }
    return NULL;
}

// --- 6. 网络请求 (WinInet) ---

char* Utils_HttpGet(const char* url) {
    HINTERNET hInet, hFile;
    char* result = NULL;
    
    // 使用全局配置的 UserAgent
    char ua[512];
    strncpy(ua, g_userAgentStr, 511); ua[511] = 0;
    if (strlen(ua) == 0) strcpy(ua, "Mandala/1.0");

    hInet = InternetOpenA(ua, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInet) return NULL;

    DWORD timeout = 5000;
    InternetSetOption(hInet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(DWORD));
    InternetSetOption(hInet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(DWORD));

    // 强制使用 TLS 1.2/1.3
    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE;
    hFile = InternetOpenUrlA(hInet, url, NULL, 0, flags, 0);
    if (hFile) {
        DWORD read = 0;
        DWORD size = 0;
        DWORD capacity = 4096;
        result = (char*)malloc(capacity);
        
        while (InternetReadFile(hFile, result + size, 2048, &read) && read > 0) {
            size += read;
            if (size + 2048 > capacity) {
                capacity *= 2;
                char* temp = (char*)realloc(result, capacity);
                if (!temp) { free(result); result = NULL; break; }
                result = temp;
            }
        }
        if (result) result[size] = 0;
        InternetCloseHandle(hFile);
    }
    InternetCloseHandle(hInet);
    return result;
}

// --- 7. ECH 配置获取 (DoH) ---

static unsigned char* hex_to_bytes(const char* hex, int* out_len) {
    if (!hex) return NULL;
    int len = strlen(hex);
    if (len % 2 != 0) return NULL;
    *out_len = len / 2;
    unsigned char* buf = (unsigned char*)malloc(*out_len);
    for (int i = 0; i < *out_len; i++) {
        sscanf(hex + i*2, "%2hhx", &buf[i]);
    }
    return buf;
}

static unsigned char* ExtractECHFromDoHAnswer(const char* rdata_hex, size_t* out_ech_len) {
    int rdata_len = 0;
    unsigned char* rdata = hex_to_bytes(rdata_hex, &rdata_len);
    if (!rdata) return NULL;

    unsigned char* p = rdata;
    unsigned char* end = rdata + rdata_len;
    unsigned char* result = NULL;

    if (p + 2 > end) goto cleanup;
    p += 2;

    if (p >= end) goto cleanup;
    if (*p == 0) {
        p++;
    } else {
        while(p < end && *p != 0) {
            int label_len = *p;
            if (p + 1 + label_len > end) goto cleanup;
            p += 1 + label_len;
        }
        if (p < end) p++;
    }

    while (p + 4 <= end) {
        int key = (p[0] << 8) | p[1];
        int vlen = (p[2] << 8) | p[3];
        p += 4;
        
        if (p + vlen > end) goto cleanup;

        if (key == 5) {
            result = (unsigned char*)malloc(vlen);
            if (result) {
                memcpy(result, p, vlen);
                *out_ech_len = vlen;
            }
            goto cleanup;
        }
        p += vlen;
    }

cleanup:
    free(rdata);
    return result;
}

unsigned char* FetchECHConfig(const char* domain, const char* doh_server, size_t* out_len) {
    if (!domain || !doh_server) return NULL;
    
    char url[1024];
    snprintf(url, sizeof(url), "%s?name=%s&type=65&ct=application/dns-json", doh_server, domain);
    
    char* json_res = Utils_HttpGet(url);
    if (!json_res) return NULL;
    
    unsigned char* ech_config = NULL;
    cJSON* root = cJSON_Parse(json_res);
    if (root) {
        cJSON* answers = cJSON_GetObjectItem(root, "Answer");
        if (cJSON_IsArray(answers)) {
            cJSON* item = NULL;
            cJSON_ArrayForEach(item, answers) {
                cJSON* type = cJSON_GetObjectItem(item, "type");
                if (type && type->valueint == 65) {
                    cJSON* data = cJSON_GetObjectItem(item, "data");
                    if (data && cJSON_IsString(data)) {
                        const char* txt = data->valuestring;
                        if (strncmp(txt, "\\#", 2) == 0) {
                            const char* hex_start = strrchr(txt, ' ');
                            if (hex_start) {
                                hex_start++;
                                ech_config = ExtractECHFromDoHAnswer(hex_start, out_len);
                                if (ech_config) break;
                            }
                        }
                    }
                }
            }
        }
        cJSON_Delete(root);
    }
    
    free(json_res);
    return ech_config;
}

// --- 8. 日志记录 (修复版) ---

void log_msg(const char* fmt, ...) {
    // 逻辑修复：仅当全局开关开启 且 窗口句柄有效 且 窗口存在时才执行记录
    if (!g_enableLog || !hLogViewerWnd || !IsWindow(hLogViewerWnd)) {
        return;
    }

    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    wchar_t wMsg[2048];
    // 使用简体中文格式化时间戳
    swprintf_s(wMsg, 2048, L"[%02d:%02d:%02d] %S\r\n", t->tm_hour, t->tm_min, t->tm_sec, buf);

    // 通过异步消息发送到 GUI 线程
    wchar_t* msgCopy = _wcsdup(wMsg);
    if (msgCopy) {
        PostMessageW(hLogViewerWnd, WM_LOG_UPDATE, 0, (LPARAM)msgCopy);
    }
}

// --- 9. 系统代理设置 ---

BOOL IsSystemProxyEnabled() {
    HKEY hKey;
    DWORD data = 0, size = sizeof(DWORD);
    if (RegOpenKeyExW(HKEY_CURRENT_USER, REG_PATH_PROXY, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExW(hKey, L"ProxyEnable", NULL, NULL, (LPBYTE)&data, &size);
        RegCloseKey(hKey);
    }
    return (data == 1);
}

void SetSystemProxy(BOOL enable) {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, REG_PATH_PROXY, 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        DWORD dEnable = enable ? 1 : 0;
        RegSetValueExW(hKey, L"ProxyEnable", 0, REG_DWORD, (LPBYTE)&dEnable, sizeof(DWORD));

        if (enable) {
            wchar_t server[64];
            swprintf_s(server, 64, L"127.0.0.1:%d", g_localPort);
            RegSetValueExW(hKey, L"ProxyServer", 0, REG_SZ, (LPBYTE)server, (DWORD)(wcslen(server)+1)*sizeof(wchar_t));
            
            const wchar_t* override = L"<local>";
            RegSetValueExW(hKey, L"ProxyOverride", 0, REG_SZ, (LPBYTE)override, (DWORD)(wcslen(override)+1)*sizeof(wchar_t));
        }
        RegCloseKey(hKey);

        InternetSetOption(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
        InternetSetOption(NULL, INTERNET_OPTION_REFRESH, NULL, 0);
    }
}

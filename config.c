#include "config.h"
#include "utils.h"
#include "proxy.h" 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// --- 全局变量声明 ---
Subscription g_subs[MAX_SUBS];
int g_subCount = 0;

// --- 内部辅助函数声明 ---
// 核心函数：解析文本并将生成的节点直接添加到内存中的 JSON 数组
int Internal_BatchAddNodesFromText(const char* text, cJSON* outbounds);
// 核心函数：为新节点生成唯一 Tag
char* GetUniqueTagName(cJSON* outbounds, const char* type, const char* base_name);

// --- 配置文件基础操作 ---

void LoadSettings() {
    g_hotkeyModifiers = GetPrivateProfileIntW(L"Settings", L"Modifiers", MOD_CONTROL | MOD_ALT, g_iniFilePath);
    g_hotkeyVk = GetPrivateProfileIntW(L"Settings", L"VK", 'H', g_iniFilePath);
    g_localPort = GetPrivateProfileIntW(L"Settings", L"LocalPort", 10809, g_iniFilePath);
    g_hideTrayStart = GetPrivateProfileIntW(L"Settings", L"HideTray", 0, g_iniFilePath);
    
    g_enableChromeCiphers = GetPrivateProfileIntW(L"Settings", L"ChromeCiphers", 1, g_iniFilePath);
    g_enableALPN = GetPrivateProfileIntW(L"Settings", L"EnableALPN", 1, g_iniFilePath);
    g_enableFragment = GetPrivateProfileIntW(L"Settings", L"EnableFragment", 0, g_iniFilePath);
    
    g_fragSizeMin = GetPrivateProfileIntW(L"Settings", L"FragMin", 5, g_iniFilePath);
    g_fragSizeMax = GetPrivateProfileIntW(L"Settings", L"FragMax", 20, g_iniFilePath);
    g_fragDelayMs = GetPrivateProfileIntW(L"Settings", L"FragDelay", 2, g_iniFilePath);

    g_enablePadding = GetPrivateProfileIntW(L"Settings", L"EnablePadding", 0, g_iniFilePath);
    g_padSizeMin = GetPrivateProfileIntW(L"Settings", L"PadMin", 100, g_iniFilePath);
    g_padSizeMax = GetPrivateProfileIntW(L"Settings", L"PadMax", 500, g_iniFilePath);

    // 边界检查
    if (g_fragSizeMin < 1) g_fragSizeMin = 1;
    if (g_fragSizeMax < g_fragSizeMin) g_fragSizeMax = g_fragSizeMin;
    if (g_fragDelayMs < 0) g_fragDelayMs = 0;
    if (g_padSizeMin < 0) g_padSizeMin = 0;
    if (g_padSizeMax < g_padSizeMin) g_padSizeMax = g_padSizeMin;

    g_uaPlatformIndex = GetPrivateProfileIntW(L"Settings", L"UAPlatform", 0, g_iniFilePath);
    
    wchar_t wUABuf[512] = {0};
    GetPrivateProfileStringW(L"Settings", L"UserAgent", L"", wUABuf, 512, g_iniFilePath);
    if (wcslen(wUABuf) > 5) {
        WideCharToMultiByte(CP_UTF8, 0, wUABuf, -1, g_userAgentStr, sizeof(g_userAgentStr), NULL, NULL);
    } else {
        strcpy(g_userAgentStr, UA_TEMPLATES[0]);
    }

    // --- 读取订阅列表 ---
    g_subCount = GetPrivateProfileIntW(L"Subscriptions", L"Count", 0, g_iniFilePath);
    if (g_subCount > MAX_SUBS) g_subCount = MAX_SUBS;
    
    for (int i = 0; i < g_subCount; i++) {
        wchar_t wKeyEn[32], wKeyUrl[32], wUrl[512];
        wsprintfW(wKeyEn, L"Sub%d_Enabled", i);
        wsprintfW(wKeyUrl, L"Sub%d_Url", i);
        
        g_subs[i].enabled = GetPrivateProfileIntW(L"Subscriptions", wKeyEn, 1, g_iniFilePath);
        GetPrivateProfileStringW(L"Subscriptions", wKeyUrl, L"", wUrl, 512, g_iniFilePath);
        WideCharToMultiByte(CP_UTF8, 0, wUrl, -1, g_subs[i].url, 512, NULL, NULL);
    }
}

void SaveSettings() {
    wchar_t buffer[16];
    wsprintfW(buffer, L"%u", g_hotkeyModifiers);
    WritePrivateProfileStringW(L"Settings", L"Modifiers", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%u", g_hotkeyVk);
    WritePrivateProfileStringW(L"Settings", L"VK", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_localPort);
    WritePrivateProfileStringW(L"Settings", L"LocalPort", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_hideTrayStart);
    WritePrivateProfileStringW(L"Settings", L"HideTray", buffer, g_iniFilePath);
    
    wsprintfW(buffer, L"%d", g_enableChromeCiphers);
    WritePrivateProfileStringW(L"Settings", L"ChromeCiphers", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_enableALPN);
    WritePrivateProfileStringW(L"Settings", L"EnableALPN", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_enableFragment);
    WritePrivateProfileStringW(L"Settings", L"EnableFragment", buffer, g_iniFilePath);
    
    wsprintfW(buffer, L"%d", g_fragSizeMin);
    WritePrivateProfileStringW(L"Settings", L"FragMin", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_fragSizeMax);
    WritePrivateProfileStringW(L"Settings", L"FragMax", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_fragDelayMs);
    WritePrivateProfileStringW(L"Settings", L"FragDelay", buffer, g_iniFilePath);

    wsprintfW(buffer, L"%d", g_enablePadding);
    WritePrivateProfileStringW(L"Settings", L"EnablePadding", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_padSizeMin);
    WritePrivateProfileStringW(L"Settings", L"PadMin", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_padSizeMax);
    WritePrivateProfileStringW(L"Settings", L"PadMax", buffer, g_iniFilePath);

    wsprintfW(buffer, L"%d", g_uaPlatformIndex);
    WritePrivateProfileStringW(L"Settings", L"UAPlatform", buffer, g_iniFilePath);
    
    wchar_t wUABuf[512] = {0};
    MultiByteToWideChar(CP_UTF8, 0, g_userAgentStr, -1, wUABuf, 512);
    WritePrivateProfileStringW(L"Settings", L"UserAgent", wUABuf, g_iniFilePath);

    // 保存订阅列表
    WritePrivateProfileStringW(L"Subscriptions", NULL, NULL, g_iniFilePath); // 清空 Section
    wsprintfW(buffer, L"%d", g_subCount);
    WritePrivateProfileStringW(L"Subscriptions", L"Count", buffer, g_iniFilePath);
    
    for (int i = 0; i < g_subCount; i++) {
        wchar_t wKeyEn[32], wKeyUrl[32], wUrl[512], wVal[2];
        wsprintfW(wKeyEn, L"Sub%d_Enabled", i);
        wsprintfW(wKeyUrl, L"Sub%d_Url", i);
        
        wsprintfW(wVal, L"%d", g_subs[i].enabled);
        WritePrivateProfileStringW(L"Subscriptions", wKeyEn, wVal, g_iniFilePath);
        
        MultiByteToWideChar(CP_UTF8, 0, g_subs[i].url, -1, wUrl, 512);
        WritePrivateProfileStringW(L"Subscriptions", wKeyUrl, wUrl, g_iniFilePath);
    }
}

void SetAutorun(BOOL enable) {
    HKEY hKey; wchar_t path[MAX_PATH]; GetModuleFileNameW(NULL, path, MAX_PATH);
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        if (enable) RegSetValueExW(hKey, L"MyProxyClient", 0, REG_SZ, (BYTE*)path, (wcslen(path)+1)*sizeof(wchar_t));
        else RegDeleteValueW(hKey, L"MyProxyClient");
        RegCloseKey(hKey);
    }
}

BOOL IsAutorun() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, L"MyProxyClient", NULL, NULL, NULL, NULL) == ERROR_SUCCESS) { RegCloseKey(hKey); return TRUE; }
        RegCloseKey(hKey);
    }
    return FALSE;
}

// --- 节点 Tag 管理 ---

void ParseTags() {
    if (nodeTags) { for(int i=0; i<nodeCount; i++) free(nodeTags[i]); free(nodeTags); }
    nodeCount = 0; nodeTags = NULL;
    char* buffer = NULL; long size = 0;
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) return;
    cJSON* root = cJSON_Parse(buffer); free(buffer);
    if (!root) return;
    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    cJSON* node;
    cJSON_ArrayForEach(node, outbounds) {
        cJSON* tag = cJSON_GetObjectItem(node, "tag");
        if (tag && tag->valuestring) {
            nodeCount++;
            nodeTags = (wchar_t**)realloc(nodeTags, nodeCount * sizeof(wchar_t*));
            int wlen = MultiByteToWideChar(CP_UTF8, 0, tag->valuestring, -1, NULL, 0);
            nodeTags[nodeCount-1] = (wchar_t*)malloc((wlen+1)*sizeof(wchar_t));
            MultiByteToWideChar(CP_UTF8, 0, tag->valuestring, -1, nodeTags[nodeCount-1], wlen+1);
        }
    }
    cJSON_Delete(root);
}

// 生成唯一 Tag (辅助函数)
char* GetUniqueTagName(cJSON* outbounds, const char* type, const char* base_name) {
    static char final_tag[512];
    char candidate[450];
    const char* safe_name = (base_name && strlen(base_name) > 0) ? base_name : "Unnamed";
    char prefix[64]; snprintf(prefix, sizeof(prefix), "%s-", type);
    
    // 如果名字已经包含了类型前缀，就不再重复添加
    if (_strnicmp(safe_name, prefix, strlen(prefix)) == 0) snprintf(candidate, sizeof(candidate), "%s", safe_name);
    else snprintf(candidate, sizeof(candidate), "%s-%s", type, safe_name);
    
    int index = 0;
    while (1) {
        if (index == 0) snprintf(final_tag, sizeof(final_tag), "%s", candidate);
        else snprintf(final_tag, sizeof(final_tag), "%s (%d)", candidate, index);
        
        BOOL exists = FALSE;
        cJSON* item = NULL;
        cJSON_ArrayForEach(item, outbounds) {
            cJSON* t = cJSON_GetObjectItem(item, "tag");
            if (t && t->valuestring && strcmp(t->valuestring, final_tag) == 0) { exists = TRUE; break; }
        }
        if (!exists) break;
        index++;
    }
    return final_tag;
}

// --- 节点切换与配置 ---

void ParseNodeConfigToGlobal(cJSON *node) {
    if (!node) return;
    memset(&g_proxyConfig, 0, sizeof(ProxyConfig));
    
    strcpy(g_proxyConfig.path, "/"); 
    cJSON *server = cJSON_GetObjectItem(node, "server");
    cJSON *port = cJSON_GetObjectItem(node, "server_port");
    cJSON *uuid = cJSON_GetObjectItem(node, "uuid");
    if (!uuid) uuid = cJSON_GetObjectItem(node, "password"); 
    if (server && server->valuestring) strcpy(g_proxyConfig.host, server->valuestring);
    if (port) g_proxyConfig.port = port->valueint;
    if (uuid && uuid->valuestring) {
        strcpy(g_proxyConfig.user, uuid->valuestring); 
        strcpy(g_proxyConfig.pass, uuid->valuestring); 
    }
    cJSON *user = cJSON_GetObjectItem(node, "username");
    cJSON *pass = cJSON_GetObjectItem(node, "password");
    if(user && user->valuestring) strcpy(g_proxyConfig.user, user->valuestring);
    if(pass && pass->valuestring) strcpy(g_proxyConfig.pass, pass->valuestring);
    cJSON *tls = cJSON_GetObjectItem(node, "tls");
    if (tls) {
        cJSON *sni = cJSON_GetObjectItem(tls, "server_name");
        if (sni && sni->valuestring) strcpy(g_proxyConfig.sni, sni->valuestring);
    }
    cJSON *trans = cJSON_GetObjectItem(node, "transport");
    if(trans) {
        cJSON *path = cJSON_GetObjectItem(trans, "path");
        if(path && path->valuestring) strcpy(g_proxyConfig.path, path->valuestring);
    }
    if (strlen(g_proxyConfig.sni) == 0) strcpy(g_proxyConfig.sni, g_proxyConfig.host);
    log_msg("Node Config Loaded: %s:%d (SNI: %s)", g_proxyConfig.host, g_proxyConfig.port, g_proxyConfig.sni);
}

void SwitchNode(const wchar_t* tag) {
    wcsncpy(currentNode, tag, 63);
    char* buffer = NULL; long size = 0;
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) return;
    cJSON* root = cJSON_Parse(buffer); free(buffer);
    if (!root) return;
    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    cJSON* targetNode = NULL;
    char tagUtf8[256];
    WideCharToMultiByte(CP_UTF8, 0, tag, -1, tagUtf8, 256, NULL, NULL);
    cJSON* node;
    cJSON_ArrayForEach(node, outbounds) {
        cJSON* t = cJSON_GetObjectItem(node, "tag");
        if (t && strcmp(t->valuestring, tagUtf8) == 0) {
            targetNode = node; break;
        }
    }
    if (targetNode) {
        StopProxyCore();
        ParseNodeConfigToGlobal(targetNode);
        StartProxyCore();
        wchar_t tip[128]; wsprintfW(tip, L"已切换: %s", tag);
        wcsncpy(nid.szInfo, tip, 127);
        wcsncpy(nid.szInfoTitle, L"Mandala Client", 63);
        nid.uFlags |= NIF_INFO;
        Shell_NotifyIconW(NIM_MODIFY, &nid);
    }
    cJSON_Delete(root);
}

void DeleteNode(const wchar_t* tag) {
    char* buffer = NULL; long size = 0;
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) return;
    cJSON* root = cJSON_Parse(buffer); free(buffer);
    if (!root) return;
    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    char tagUtf8[256];
    WideCharToMultiByte(CP_UTF8, 0, tag, -1, tagUtf8, 256, NULL, NULL);
    int idx = 0;
    cJSON* node;
    cJSON_ArrayForEach(node, outbounds) {
        cJSON* t = cJSON_GetObjectItem(node, "tag");
        if (t && strcmp(t->valuestring, tagUtf8) == 0) {
            cJSON_DeleteItemFromArray(outbounds, idx);
            break;
        }
        idx++;
    }
    char* out = cJSON_Print(root);
    WriteBufferToFile(CONFIG_FILE, out);
    free(out); cJSON_Delete(root);
    ParseTags(); 
}

// --- 单个节点添加 (现在调用内部批量函数，虽然只加一个，但复用了逻辑) ---
BOOL AddNodeToConfig(cJSON* newNode) {
    if (!newNode) return FALSE;
    char* buffer = NULL; long size = 0; cJSON* root = NULL;
    
    // 读取
    if (ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) { root = cJSON_Parse(buffer); free(buffer); }
    if (!root) { root = cJSON_CreateObject(); cJSON_AddItemToObject(root, "outbounds", cJSON_CreateArray()); }
    
    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    if (!outbounds) { outbounds = cJSON_CreateArray(); cJSON_AddItemToObject(root, "outbounds", outbounds); }
    
    // 处理 Tag 唯一性
    cJSON* jsonType = cJSON_GetObjectItem(newNode, "type");
    const char* typeStr = (jsonType && jsonType->valuestring) ? jsonType->valuestring : "proxy";
    cJSON* jsonTag = cJSON_GetObjectItem(newNode, "tag");
    const char* originalTag = (jsonTag && jsonTag->valuestring) ? jsonTag->valuestring : "NewNode";
    char* uniqueTag = GetUniqueTagName(outbounds, typeStr, originalTag);
    
    if (cJSON_HasObjectItem(newNode, "tag")) cJSON_ReplaceItemInObject(newNode, "tag", cJSON_CreateString(uniqueTag));
    else cJSON_AddStringToObject(newNode, "tag", uniqueTag);
    
    // 添加
    cJSON_AddItemToArray(outbounds, newNode);
    
    // 写入
    char* out = cJSON_Print(root);
    BOOL ret = WriteBufferToFile(CONFIG_FILE, out);
    free(out); cJSON_Delete(root);
    return ret;
}

// --- 批量导入核心逻辑 (内存操作，无 IO) ---
// 返回值：添加成功的节点数量
int Internal_BatchAddNodesFromText(const char* text, cJSON* outbounds) {
    if (!text || !outbounds) return 0;
    
    int count = 0;
    // 尝试 Base64 解码，因为订阅链接内容通常是 Base64 编码的
    size_t decLen = 0;
    unsigned char* decoded = Base64Decode(text, &decLen);
    
    char* sourceText = NULL;
    if (decoded && decLen > 0) {
        sourceText = (char*)decoded;
    } else {
        sourceText = strdup(text); 
        if (decoded) free(decoded);
    }
    
    if (!sourceText) return 0;

    char* context = NULL;
    // 使用统一的分隔符：换行、空格、逗号
    char* line = strtok_s(sourceText, "\r\n ,", &context);
    while (line) {
        TrimString(line);
        if (strlen(line) > 0) {
            cJSON* node = NULL;
            // 根据前缀判断协议
            if (_strnicmp(line, "vmess://", 8) == 0) node = ParseVmess(line);
            else if (_strnicmp(line, "ss://", 5) == 0) node = ParseShadowsocks(line);
            else if (_strnicmp(line, "vless://", 8) == 0) node = ParseVlessOrTrojan(line);
            else if (_strnicmp(line, "trojan://", 9) == 0) node = ParseVlessOrTrojan(line);
            else if (_strnicmp(line, "socks://", 8) == 0) node = ParseSocks(line);
            
            if (node) {
                // 处理 Tag 唯一性
                cJSON* jsonType = cJSON_GetObjectItem(node, "type");
                const char* typeStr = (jsonType && jsonType->valuestring) ? jsonType->valuestring : "proxy";
                cJSON* jsonTag = cJSON_GetObjectItem(node, "tag");
                const char* originalTag = (jsonTag && jsonTag->valuestring) ? jsonTag->valuestring : "Auto";
                
                char* uniqueTag = GetUniqueTagName(outbounds, typeStr, originalTag);
                
                if (cJSON_HasObjectItem(node, "tag")) cJSON_ReplaceItemInObject(node, "tag", cJSON_CreateString(uniqueTag));
                else cJSON_AddStringToObject(node, "tag", uniqueTag);

                cJSON_AddItemToArray(outbounds, node);
                count++;
            }
        }
        line = strtok_s(NULL, "\r\n ,", &context);
    }
    free(sourceText);
    return count;
}

// --- 外部接口：从剪贴板导入 (重构后使用批量逻辑) ---
int ImportFromClipboard() {
    char* text = GetClipboardText(); 
    if (!text) return 0;

    // 1. 读取当前配置
    char* buffer = NULL; long size = 0; cJSON* root = NULL;
    if (ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) { root = cJSON_Parse(buffer); free(buffer); }
    if (!root) { root = cJSON_CreateObject(); cJSON_AddItemToObject(root, "outbounds", cJSON_CreateArray()); }
    
    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    if (!outbounds) { outbounds = cJSON_CreateArray(); cJSON_AddItemToObject(root, "outbounds", outbounds); }

    // 2. 批量处理内存数据
    int successCount = Internal_BatchAddNodesFromText(text, outbounds);

    // 3. 一次性写入
    if (successCount > 0) {
        char* out = cJSON_Print(root);
        WriteBufferToFile(CONFIG_FILE, out);
        free(out);
        ParseTags(); // 刷新全局 Tag 列表
    }
    
    cJSON_Delete(root);
    free(text);
    return successCount;
}

// --- 外部接口：更新所有订阅 (重构后解决 IO 性能问题) ---
int UpdateAllSubscriptions(BOOL forceMsg) {
    int activeSubs = 0;
    for(int i=0; i<g_subCount; i++) {
        if(g_subs[i].enabled && strlen(g_subs[i].url) > 4) activeSubs++;
    }

    if (activeSubs == 0) {
        if (forceMsg) log_msg("[Sub] No active subscriptions found.");
        return 0;
    }

    log_msg("[Sub] Starting update for %d subscriptions...", activeSubs);

    // 1. 下载所有订阅内容 (IO 操作，网络)
    // 为了避免下载时间过长阻塞 UI，实际生产环境建议用线程，这里先保持同步但优化逻辑
    char* rawData[MAX_SUBS] = {0};
    int downloadSuccess = 0;

    for (int i = 0; i < g_subCount; i++) {
        if (g_subs[i].enabled && strlen(g_subs[i].url) > 4) {
            log_msg("[Sub] Downloading (%d/%d): %s", i+1, g_subCount, g_subs[i].url);
            char* data = Utils_HttpGet(g_subs[i].url);
            if (data) {
                rawData[i] = data;
                downloadSuccess++;
            } else {
                log_msg("[Sub] Download failed: %s", g_subs[i].url);
            }
        }
    }

    if (downloadSuccess == 0) {
        log_msg("[Error] All downloads failed. Config not updated.");
        return 0;
    }

    // 2. 准备配置文件 (IO 操作，文件读取 - 仅一次)
    char* buffer = NULL; long size = 0; cJSON* root = NULL;
    if (ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) { root = cJSON_Parse(buffer); free(buffer); }
    if (!root) { root = cJSON_CreateObject(); }

    // 3. 清空旧节点 (按照原逻辑，更新订阅会覆盖旧节点)
    // 注意：如果想保留手动添加的节点，逻辑会复杂很多，这里暂时保持“更新即重置”的原有逻辑
    if (cJSON_HasObjectItem(root, "outbounds")) {
        cJSON_DeleteItemFromObject(root, "outbounds");
    }
    cJSON* outbounds = cJSON_CreateArray();
    cJSON_AddItemToObject(root, "outbounds", outbounds);

    // 4. 批量添加节点 (内存操作)
    int totalNewNodes = 0;
    for (int i = 0; i < g_subCount; i++) {
        if (rawData[i]) {
            int count = Internal_BatchAddNodesFromText(rawData[i], outbounds);
            totalNewNodes += count;
            free(rawData[i]); // 释放下载的文本
            rawData[i] = NULL;
        }
    }

    // 5. 保存文件 (IO 操作，文件写入 - 仅一次)
    log_msg("[Sub] Total nodes parsed: %d. Saving config...", totalNewNodes);
    char* out = cJSON_Print(root);
    WriteBufferToFile(CONFIG_FILE, out);
    free(out);
    cJSON_Delete(root);

    // 6. 刷新界面用的 Tag 列表
    ParseTags();
    
    log_msg("[Sub] Update complete.");
    return totalNewNodes;
}

void ToggleTrayIcon() {
    if (g_isIconVisible) { 
        Shell_NotifyIconW(NIM_DELETE, &nid); 
        g_isIconVisible = FALSE; 
        g_hideTrayStart = 1;
    }
    else { 
        nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        Shell_NotifyIconW(NIM_ADD, &nid); 
        g_isIconVisible = TRUE; 
        g_hideTrayStart = 0;
    }
    SaveSettings();
}

// --- 协议解析函数 (保持不变) ---
cJSON* ParseSocks(const char* link) {
    if (strncmp(link, "socks://", 8) != 0) return NULL;
    const char* p = link + 8; const char* at = strchr(p, '@'); if (!at) return NULL; 
    int authLen = (int)(at - p); char* authBase64 = (char*)malloc(authLen + 1); strncpy(authBase64, p, authLen); authBase64[authLen] = 0;
    size_t decLen; unsigned char* decoded = Base64Decode(authBase64, &decLen); free(authBase64);
    if (!decoded) return NULL;
    char* user = (char*)decoded; char* pass = strchr(user, ':'); if (pass) { *pass = 0; pass++; } else pass = "";
    p = at + 1; const char* colon = strchr(p, ':'); const char* qMark = strchr(p, '?'); const char* hash = strchr(p, '#');
    const char* portStart = colon ? colon + 1 : NULL; const char* hostEnd = colon ? colon : (qMark ? qMark : (hash ? hash : p + strlen(p)));
    int hostLen = (int)(hostEnd - p); char* host = (char*)malloc(hostLen + 1); strncpy(host, p, hostLen); host[hostLen] = 0;
    int portNum = portStart ? atoi(portStart) : 443;
    char* tag = hash ? (char*)malloc(strlen(hash+1)+1) : strdup("Socks-Import");
    if(hash) UrlDecode(tag, hash+1);
    const char* query = qMark ? qMark + 1 : NULL;
    char* sni = GetQueryParam(query, "sni");
    char* path = GetQueryParam(query, "path"); 
    char* transport = GetQueryParam(query, "transport");
    cJSON* outbound = cJSON_CreateObject();
    cJSON_AddStringToObject(outbound, "type", "socks_tls");
    cJSON_AddStringToObject(outbound, "tag", tag);
    cJSON_AddStringToObject(outbound, "server", host);
    cJSON_AddNumberToObject(outbound, "server_port", portNum);
    cJSON_AddStringToObject(outbound, "username", user);
    cJSON_AddStringToObject(outbound, "password", pass);
    if (sni) {
        cJSON* tls = cJSON_CreateObject(); cJSON_AddStringToObject(tls, "server_name", sni);
        cJSON_AddItemToObject(outbound, "tls", tls); free(sni);
    }
    if (transport && strcmp(transport, "ws") == 0) {
        cJSON* trans = cJSON_CreateObject(); cJSON_AddStringToObject(trans, "type", "ws");
        if (path) cJSON_AddStringToObject(trans, "path", path);
        if (sni) { 
             cJSON* headers = cJSON_CreateObject(); cJSON_AddStringToObject(headers, "Host", host); 
             cJSON_AddItemToObject(trans, "headers", headers);
        }
        cJSON_AddItemToObject(outbound, "transport", trans);
    }
    if (path) free(path); if (transport) free(transport); free(host); free(tag); free(decoded);
    return outbound;
}

cJSON* ParseVmess(const char* link) {
    if (strncmp(link, "vmess://", 8) != 0) return NULL;
    size_t len; unsigned char* decoded = Base64Decode(link + 8, &len); if (!decoded) return NULL;
    cJSON* vmessJson = cJSON_Parse((const char*)decoded); free(decoded); if (!vmessJson) return NULL;
    cJSON* outbound = cJSON_CreateObject();
    cJSON_AddStringToObject(outbound, "type", "vmess");
    cJSON* ps = cJSON_GetObjectItem(vmessJson, "ps"); cJSON* add = cJSON_GetObjectItem(vmessJson, "add");
    cJSON* port = cJSON_GetObjectItem(vmessJson, "port"); cJSON* id = cJSON_GetObjectItem(vmessJson, "id");
    cJSON* net = cJSON_GetObjectItem(vmessJson, "net"); cJSON* host = cJSON_GetObjectItem(vmessJson, "host");
    cJSON* path = cJSON_GetObjectItem(vmessJson, "path"); cJSON* tls = cJSON_GetObjectItem(vmessJson, "tls");
    cJSON* sni = cJSON_GetObjectItem(vmessJson, "sni");
    cJSON_AddStringToObject(outbound, "tag", cJSON_IsString(ps) ? ps->valuestring : "VMess");
    cJSON_AddStringToObject(outbound, "server", cJSON_IsString(add) ? add->valuestring : "");
    cJSON_AddNumberToObject(outbound, "server_port", cJSON_IsNumber(port)?port->valueint:atoi(port->valuestring));
    cJSON_AddStringToObject(outbound, "uuid", cJSON_IsString(id) ? id->valuestring : "");
    if (cJSON_IsString(net) && strcmp(net->valuestring, "ws") == 0) {
        cJSON* t = cJSON_CreateObject(); cJSON_AddStringToObject(t, "type", "ws");
        if(cJSON_IsString(path)) cJSON_AddStringToObject(t, "path", path->valuestring);
        if(cJSON_IsString(host) && strlen(host->valuestring)>0) {
            cJSON* h = cJSON_CreateObject(); cJSON_AddStringToObject(h, "Host", host->valuestring);
            cJSON_AddItemToObject(t, "headers", h);
        }
        cJSON_AddItemToObject(outbound, "transport", t);
    } 
    if ((cJSON_IsString(tls) && strcmp(tls->valuestring, "tls") == 0)) {
        cJSON* t = cJSON_CreateObject(); cJSON_AddBoolToObject(t, "enabled", cJSON_True);
        if (cJSON_IsString(sni) && strlen(sni->valuestring)>0) cJSON_AddStringToObject(t, "server_name", sni->valuestring);
        else if (cJSON_IsString(host) && strlen(host->valuestring)>0) cJSON_AddStringToObject(t, "server_name", host->valuestring);
        cJSON_AddItemToObject(outbound, "tls", t);
    }
    cJSON_Delete(vmessJson); return outbound;
}

cJSON* ParseVlessOrTrojan(const char* link) {
    char protocol[16] = {0};
    if (strncmp(link, "vless://", 8) == 0) strcpy(protocol, "vless");
    else if (strncmp(link, "trojan://", 9) == 0) strcpy(protocol, "trojan");
    else return NULL;
    const char* p = link + strlen(protocol) + 3; const char* at = strchr(p, '@'); if (!at) return NULL;
    int uuidLen = (int)(at - p); char* uuid = (char*)malloc(uuidLen + 1); strncpy(uuid, p, uuidLen); uuid[uuidLen] = 0;
    p = at + 1; const char* colon = strchr(p, ':'); const char* qMark = strchr(p, '?'); const char* hash = strchr(p, '#');
    const char* portStart = colon ? colon + 1 : NULL; const char* hostEnd = colon ? colon : (qMark ? qMark : (hash ? hash : p + strlen(p)));
    int hostLen = (int)(hostEnd - p); char* host = (char*)malloc(hostLen + 1); strncpy(host, p, hostLen); host[hostLen] = 0;
    int portNum = portStart ? atoi(portStart) : 443;
    char* tag = hash ? (char*)malloc(strlen(hash+1)+1) : strdup(protocol);
    if(hash) UrlDecode(tag, hash+1);
    cJSON* outbound = cJSON_CreateObject();
    cJSON_AddStringToObject(outbound, "type", protocol);
    cJSON_AddStringToObject(outbound, "tag", tag);
    cJSON_AddStringToObject(outbound, "server", host);
    cJSON_AddNumberToObject(outbound, "server_port", portNum);
    if (strcmp(protocol, "vless") == 0) cJSON_AddStringToObject(outbound, "uuid", uuid);
    else cJSON_AddStringToObject(outbound, "password", uuid);
    const char* query = qMark ? qMark + 1 : NULL;
    char* type = GetQueryParam(query, "type");
    if (type && strcmp(type, "ws") == 0) {
        cJSON* t = cJSON_CreateObject(); cJSON_AddStringToObject(t, "type", "ws");
        char* path = GetQueryParam(query, "path");
        if (path) { cJSON_AddStringToObject(t, "path", path); free(path); }
        char* hHeader = GetQueryParam(query, "host");
        if (hHeader) {
            cJSON* headers = cJSON_CreateObject(); cJSON_AddStringToObject(headers, "Host", hHeader);
            cJSON_AddItemToObject(t, "headers", headers); free(hHeader);
        }
        cJSON_AddItemToObject(outbound, "transport", t);
    }
    if (type) free(type);
    char* security = GetQueryParam(query, "security");
    if (security && strcmp(security, "tls") == 0) {
        cJSON* tlsObj = cJSON_CreateObject(); cJSON_AddBoolToObject(tlsObj, "enabled", cJSON_True);
        char* sni = GetQueryParam(query, "sni");
        if (sni) { cJSON_AddStringToObject(tlsObj, "server_name", sni); free(sni); }
        else cJSON_AddStringToObject(tlsObj, "server_name", host);
        cJSON_AddItemToObject(outbound, "tls", tlsObj);
    }
    if (security) free(security);
    free(uuid); free(host); free(tag); return outbound;
}

cJSON* ParseShadowsocks(const char* link) {
    if (strncmp(link, "ss://", 5) != 0) return NULL;
    const char* p = link + 5; const char* hash = strchr(p, '#');
    char* tag = hash ? (char*)malloc(strlen(hash+1)+1) : strdup("SS");
    if(hash) UrlDecode(tag, hash+1);
    size_t mainLen = hash ? (size_t)(hash - p) : strlen(p);
    char* mainPart = (char*)malloc(mainLen + 1); strncpy(mainPart, p, mainLen); mainPart[mainLen] = 0;
    char serverPort[256] = {0}, methodPass[256] = {0};
    char* at = strchr(mainPart, '@');
    if (!at) {
        size_t decLen; unsigned char* decoded = Base64Decode(mainPart, &decLen);
        if(!decoded) { free(mainPart); free(tag); return NULL; }
        char* dStr = (char*)decoded;
        at = strchr(dStr, '@');
        if (at) { strncpy(serverPort, at+1, 255); strncpy(methodPass, dStr, at-dStr); }
        free(decoded);
    } else {
        strncpy(serverPort, at+1, 255);
        char tmp[256]; strncpy(tmp, mainPart, at-mainPart); tmp[at-mainPart]=0;
        size_t decLen; unsigned char* decoded = Base64Decode(tmp, &decLen);
        if(decoded) { strncpy(methodPass, (char*)decoded, 255); free(decoded); }
    }
    free(mainPart);
    char* colon = strrchr(serverPort, ':'); if (!colon) { free(tag); return NULL; }
    int port = atoi(colon + 1); *colon = 0;
    char* pass = strchr(methodPass, ':'); if (!pass) { free(tag); return NULL; }
    *pass = 0; pass++;
    cJSON* outbound = cJSON_CreateObject();
    cJSON_AddStringToObject(outbound, "type", "shadowsocks");
    cJSON_AddStringToObject(outbound, "tag", tag);
    cJSON_AddStringToObject(outbound, "server", serverPort);
    cJSON_AddNumberToObject(outbound, "server_port", port);
    cJSON_AddStringToObject(outbound, "method", methodPass);
    cJSON_AddStringToObject(outbound, "password", pass);
    free(tag); return outbound;
}

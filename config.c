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
int Internal_BatchAddNodesFromText(const char* text, cJSON* outbounds);
char* GetUniqueTagName(cJSON* outbounds, const char* type, const char* base_name);

// --- 辅助：安全获取或创建 JSON 对象 ---
static cJSON* GetOrCreateObj(cJSON* parent, const char* name) {
    cJSON* item = cJSON_GetObjectItem(parent, name);
    if (!item) {
        item = cJSON_CreateObject();
        cJSON_AddItemToObject(parent, name, item);
    }
    return item;
}

// ... (保留 ParseSSPlugin 函数，未修改) ...
static void ParseSSPlugin(cJSON* outbound, const char* pluginParam) {
    if (!pluginParam || !outbound) return;
    char* pluginCopy = strdup(pluginParam);
    if (!pluginCopy) return;

    char host[256] = {0}; char path[256] = {0}; char sni[256] = {0}; char mode[64] = {0};
    BOOL isTls = FALSE;
    BOOL isV2ray = (strstr(pluginCopy, "v2ray-plugin") != NULL);
    BOOL isObfs = (strstr(pluginCopy, "obfs-local") != NULL || strstr(pluginCopy, "simple-obfs") != NULL);
    
    char* ctx = NULL; char* token = strtok_s(pluginCopy, ";", &ctx);
    while (token) {
        if (strncmp(token, "host=", 5) == 0) strncpy(host, token+5, 255);
        else if (strncmp(token, "obfs-host=", 10) == 0) strncpy(host, token+10, 255);
        else if (strncmp(token, "path=", 5) == 0) strncpy(path, token+5, 255);
        else if (strncmp(token, "sni=", 4) == 0) strncpy(sni, token+4, 255);
        else if (strncmp(token, "mode=", 5) == 0) strncpy(mode, token+5, 63);
        else if (strcmp(token, "tls") == 0) isTls = TRUE;
        else if (strncmp(token, "obfs=", 5) == 0) { if (strcmp(token+5, "tls") == 0) isTls = TRUE; }
        token = strtok_s(NULL, ";", &ctx);
    }

    if (isTls) {
        cJSON* tlsObj = GetOrCreateObj(outbound, "tls");
        cJSON_AddBoolToObject(tlsObj, "enabled", cJSON_True);
        if (strlen(sni) > 0) cJSON_AddStringToObject(tlsObj, "server_name", sni);
        else if (strlen(host) > 0 && !cJSON_HasObjectItem(tlsObj, "server_name")) cJSON_AddStringToObject(tlsObj, "server_name", host);
    }

    if (isV2ray && strcmp(mode, "quic") != 0) {
        cJSON* trans = GetOrCreateObj(outbound, "transport");
        // 只有当没有设置 type 时才设置，避免覆盖
        if (!cJSON_HasObjectItem(trans, "type")) cJSON_AddStringToObject(trans, "type", "ws");
        if (strlen(path) > 0) cJSON_AddStringToObject(trans, "path", path);
        if (strlen(host) > 0) {
            cJSON* headers = GetOrCreateObj(trans, "headers");
            cJSON_AddStringToObject(headers, "Host", host);
        }
    }
    free(pluginCopy);
}

// ... (保留 LoadSettings, SaveSettings, SetAutorun, IsAutorun, ParseTags, GetUniqueTagName, 略过未修改部分) ...

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

    if (g_fragSizeMin < 1) g_fragSizeMin = 1; if (g_fragSizeMax < g_fragSizeMin) g_fragSizeMax = g_fragSizeMin;
    if (g_fragDelayMs < 0) g_fragDelayMs = 0; if (g_padSizeMin < 0) g_padSizeMin = 0; if (g_padSizeMax < g_padSizeMin) g_padSizeMax = g_padSizeMin;

    g_uaPlatformIndex = GetPrivateProfileIntW(L"Settings", L"UAPlatform", 0, g_iniFilePath);
    wchar_t wUABuf[512] = {0}; GetPrivateProfileStringW(L"Settings", L"UserAgent", L"", wUABuf, 512, g_iniFilePath);
    if (wcslen(wUABuf) > 5) WideCharToMultiByte(CP_UTF8, 0, wUABuf, -1, g_userAgentStr, sizeof(g_userAgentStr), NULL, NULL);
    else strcpy(g_userAgentStr, UA_TEMPLATES[0]);

    GetPrivateProfileStringW(L"Settings", L"LastNode", L"", currentNode, 64, g_iniFilePath);

    g_subCount = GetPrivateProfileIntW(L"Subscriptions", L"Count", 0, g_iniFilePath);
    if (g_subCount > MAX_SUBS) g_subCount = MAX_SUBS;
    for (int i = 0; i < g_subCount; i++) {
        wchar_t wKeyEn[32], wKeyUrl[32], wUrl[512];
        wsprintfW(wKeyEn, L"Sub%d_Enabled", i); wsprintfW(wKeyUrl, L"Sub%d_Url", i);
        g_subs[i].enabled = GetPrivateProfileIntW(L"Subscriptions", wKeyEn, 1, g_iniFilePath);
        GetPrivateProfileStringW(L"Subscriptions", wKeyUrl, L"", wUrl, 512, g_iniFilePath);
        WideCharToMultiByte(CP_UTF8, 0, wUrl, -1, g_subs[i].url, 512, NULL, NULL);
    }
}

void SaveSettings() {
    wchar_t buffer[16];
    wsprintfW(buffer, L"%u", g_hotkeyModifiers); WritePrivateProfileStringW(L"Settings", L"Modifiers", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%u", g_hotkeyVk); WritePrivateProfileStringW(L"Settings", L"VK", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_localPort); WritePrivateProfileStringW(L"Settings", L"LocalPort", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_hideTrayStart); WritePrivateProfileStringW(L"Settings", L"HideTray", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_enableChromeCiphers); WritePrivateProfileStringW(L"Settings", L"ChromeCiphers", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_enableALPN); WritePrivateProfileStringW(L"Settings", L"EnableALPN", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_enableFragment); WritePrivateProfileStringW(L"Settings", L"EnableFragment", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_fragSizeMin); WritePrivateProfileStringW(L"Settings", L"FragMin", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_fragSizeMax); WritePrivateProfileStringW(L"Settings", L"FragMax", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_fragDelayMs); WritePrivateProfileStringW(L"Settings", L"FragDelay", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_enablePadding); WritePrivateProfileStringW(L"Settings", L"EnablePadding", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_padSizeMin); WritePrivateProfileStringW(L"Settings", L"PadMin", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_padSizeMax); WritePrivateProfileStringW(L"Settings", L"PadMax", buffer, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_uaPlatformIndex); WritePrivateProfileStringW(L"Settings", L"UAPlatform", buffer, g_iniFilePath);
    wchar_t wUABuf[512] = {0}; MultiByteToWideChar(CP_UTF8, 0, g_userAgentStr, -1, wUABuf, 512);
    WritePrivateProfileStringW(L"Settings", L"UserAgent", wUABuf, g_iniFilePath);
    WritePrivateProfileStringW(L"Settings", L"LastNode", currentNode, g_iniFilePath);

    WritePrivateProfileStringW(L"Subscriptions", NULL, NULL, g_iniFilePath);
    wsprintfW(buffer, L"%d", g_subCount); WritePrivateProfileStringW(L"Subscriptions", L"Count", buffer, g_iniFilePath);
    for (int i = 0; i < g_subCount; i++) {
        wchar_t wKeyEn[32], wKeyUrl[32], wUrl[512], wVal[2];
        wsprintfW(wKeyEn, L"Sub%d_Enabled", i); wsprintfW(wKeyUrl, L"Sub%d_Url", i);
        wsprintfW(wVal, L"%d", g_subs[i].enabled); WritePrivateProfileStringW(L"Subscriptions", wKeyEn, wVal, g_iniFilePath);
        MultiByteToWideChar(CP_UTF8, 0, g_subs[i].url, -1, wUrl, 512); WritePrivateProfileStringW(L"Subscriptions", wKeyUrl, wUrl, g_iniFilePath);
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

char* GetUniqueTagName(cJSON* outbounds, const char* type, const char* base_name) {
    static char final_tag[512]; char candidate[450];
    const char* safe_name = (base_name && strlen(base_name) > 0) ? base_name : "Unnamed";
    char prefix[64]; snprintf(prefix, sizeof(prefix), "%s-", type);
    if (_strnicmp(safe_name, prefix, strlen(prefix)) == 0) snprintf(candidate, sizeof(candidate), "%s", safe_name);
    else snprintf(candidate, sizeof(candidate), "%s-%s", type, safe_name);
    int index = 0;
    while (1) {
        if (index == 0) snprintf(final_tag, sizeof(final_tag), "%s", candidate);
        else snprintf(final_tag, sizeof(final_tag), "%s (%d)", candidate, index);
        BOOL exists = FALSE; cJSON* item = NULL;
        cJSON_ArrayForEach(item, outbounds) {
            cJSON* t = cJSON_GetObjectItem(item, "tag");
            if (t && t->valuestring && strcmp(t->valuestring, final_tag) == 0) { exists = TRUE; break; }
        }
        if (!exists) break;
        index++;
    }
    return final_tag;
}

// [关键修改] 解析 Transport.Type 到 g_proxyConfig.net
void ParseNodeConfigToGlobal(cJSON *node) {
    if (!node) return;
    memset(&g_proxyConfig, 0, sizeof(ProxyConfig));
    strcpy(g_proxyConfig.path, "/"); 
    // 默认 net 为 tcp，除非配置中指定
    strcpy(g_proxyConfig.net, "tcp");

    cJSON *server = cJSON_GetObjectItem(node, "server");
    cJSON *port = cJSON_GetObjectItem(node, "server_port");
    cJSON *uuid = cJSON_GetObjectItem(node, "uuid");
    if (!uuid) uuid = cJSON_GetObjectItem(node, "password"); 
    if (server && server->valuestring) strcpy(g_proxyConfig.host, server->valuestring);
    if (port) g_proxyConfig.port = port->valueint;
    if (uuid && uuid->valuestring) { strcpy(g_proxyConfig.user, uuid->valuestring); strcpy(g_proxyConfig.pass, uuid->valuestring); }
    cJSON *user = cJSON_GetObjectItem(node, "username"); cJSON *pass = cJSON_GetObjectItem(node, "password");
    if(user && user->valuestring) strcpy(g_proxyConfig.user, user->valuestring);
    if(pass && pass->valuestring) strcpy(g_proxyConfig.pass, pass->valuestring);
    
    cJSON *tls = cJSON_GetObjectItem(node, "tls");
    if (tls) {
        cJSON *sni = cJSON_GetObjectItem(tls, "server_name");
        if (sni && sni->valuestring) strcpy(g_proxyConfig.sni, sni->valuestring);
    }
    
    cJSON *trans = cJSON_GetObjectItem(node, "transport");
    if(trans) {
        // [New] 读取 transport.type
        cJSON *ttype = cJSON_GetObjectItem(trans, "type");
        if(ttype && ttype->valuestring) strncpy(g_proxyConfig.net, ttype->valuestring, 31);
        
        cJSON *path = cJSON_GetObjectItem(trans, "path");
        if(path && path->valuestring) strcpy(g_proxyConfig.path, path->valuestring);
    }
    
    if (strlen(g_proxyConfig.sni) == 0) strcpy(g_proxyConfig.sni, g_proxyConfig.host);

    cJSON *type = cJSON_GetObjectItem(node, "type");
    if (type && type->valuestring) {
        strncpy(g_proxyConfig.type, type->valuestring, 31);
    } else {
        strcpy(g_proxyConfig.type, "socks");
    }

    log_msg("Node Config Loaded: %s:%d (Type: %s, Net: %s)", 
        g_proxyConfig.host, g_proxyConfig.port, g_proxyConfig.type, g_proxyConfig.net);
}

// ... (保留 SwitchNode, DeleteNode, AddNodeToConfig, Internal_BatchAddNodesFromText 等, 略过未修改部分) ...

void SwitchNode(const wchar_t* tag) {
    wcsncpy(currentNode, tag, 63);
    char* buffer = NULL; long size = 0;
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) return;
    cJSON* root = cJSON_Parse(buffer); free(buffer);
    if (!root) return;
    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    cJSON* targetNode = NULL;
    char tagUtf8[256]; WideCharToMultiByte(CP_UTF8, 0, tag, -1, tagUtf8, 256, NULL, NULL);
    cJSON* node;
    cJSON_ArrayForEach(node, outbounds) {
        cJSON* t = cJSON_GetObjectItem(node, "tag");
        if (t && strcmp(t->valuestring, tagUtf8) == 0) { targetNode = node; break; }
    }
    if (targetNode) {
        StopProxyCore(); ParseNodeConfigToGlobal(targetNode); StartProxyCore();
        SaveSettings(); 
        
        wchar_t tip[128]; wsprintfW(tip, L"已切换: %s", tag);
        wcsncpy(nid.szInfo, tip, 127); wcsncpy(nid.szInfoTitle, L"Mandala Client", 63); nid.uFlags |= NIF_INFO;
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
    char tagUtf8[256]; WideCharToMultiByte(CP_UTF8, 0, tag, -1, tagUtf8, 256, NULL, NULL);
    int idx = 0; cJSON* node;
    cJSON_ArrayForEach(node, outbounds) {
        cJSON* t = cJSON_GetObjectItem(node, "tag");
        if (t && strcmp(t->valuestring, tagUtf8) == 0) { cJSON_DeleteItemFromArray(outbounds, idx); break; }
        idx++;
    }
    char* out = cJSON_Print(root); WriteBufferToFile(CONFIG_FILE, out); free(out); cJSON_Delete(root);
    ParseTags(); 
}

BOOL AddNodeToConfig(cJSON* newNode) {
    if (!newNode) return FALSE;
    char* buffer = NULL; long size = 0; cJSON* root = NULL;
    if (ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) { root = cJSON_Parse(buffer); free(buffer); }
    if (!root) { root = cJSON_CreateObject(); cJSON_AddItemToObject(root, "outbounds", cJSON_CreateArray()); }
    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    if (!outbounds) { outbounds = cJSON_CreateArray(); cJSON_AddItemToObject(root, "outbounds", outbounds); }
    cJSON* jsonType = cJSON_GetObjectItem(newNode, "type");
    const char* typeStr = (jsonType && jsonType->valuestring) ? jsonType->valuestring : "proxy";
    cJSON* jsonTag = cJSON_GetObjectItem(newNode, "tag");
    const char* originalTag = (jsonTag && jsonTag->valuestring) ? jsonTag->valuestring : "NewNode";
    char* uniqueTag = GetUniqueTagName(outbounds, typeStr, originalTag);
    if (cJSON_HasObjectItem(newNode, "tag")) cJSON_ReplaceItemInObject(newNode, "tag", cJSON_CreateString(uniqueTag));
    else cJSON_AddStringToObject(newNode, "tag", uniqueTag);
    cJSON_AddItemToArray(outbounds, newNode);
    char* out = cJSON_Print(root); BOOL ret = WriteBufferToFile(CONFIG_FILE, out); free(out); cJSON_Delete(root);
    return ret;
}

int Internal_BatchAddNodesFromText(const char* text, cJSON* outbounds) {
    if (!text || !outbounds) return 0;
    int count = 0; size_t decLen = 0; unsigned char* decoded = Base64Decode(text, &decLen);
    char* sourceText = NULL;
    if (decoded && decLen > 0) sourceText = (char*)decoded; else { sourceText = strdup(text); if (decoded) free(decoded); }
    if (!sourceText) return 0;
    char* context = NULL; char* line = strtok_s(sourceText, "\r\n ,", &context);
    while (line) {
        TrimString(line);
        if (strlen(line) > 0) {
            cJSON* node = NULL;
            if (_strnicmp(line, "vmess://", 8) == 0) node = ParseVmess(line);
            else if (_strnicmp(line, "ss://", 5) == 0) node = ParseShadowsocks(line);
            else if (_strnicmp(line, "vless://", 8) == 0) node = ParseVlessOrTrojan(line);
            else if (_strnicmp(line, "trojan://", 9) == 0) node = ParseVlessOrTrojan(line);
            else if (_strnicmp(line, "socks://", 8) == 0) node = ParseSocks(line);
            if (node) {
                cJSON* jsonType = cJSON_GetObjectItem(node, "type");
                const char* typeStr = (jsonType && jsonType->valuestring) ? jsonType->valuestring : "proxy";
                cJSON* jsonTag = cJSON_GetObjectItem(node, "tag");
                const char* originalTag = (jsonTag && jsonTag->valuestring) ? jsonTag->valuestring : "Auto";
                char* uniqueTag = GetUniqueTagName(outbounds, typeStr, originalTag);
                if (cJSON_HasObjectItem(node, "tag")) cJSON_ReplaceItemInObject(node, "tag", cJSON_CreateString(uniqueTag));
                else cJSON_AddStringToObject(node, "tag", uniqueTag);
                cJSON_AddItemToArray(outbounds, node); count++;
            }
        }
        line = strtok_s(NULL, "\r\n ,", &context);
    }
    free(sourceText); return count;
}

int ImportFromClipboard() {
    char* text = GetClipboardText(); if (!text) return 0;
    char* buffer = NULL; long size = 0; cJSON* root = NULL;
    if (ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) { root = cJSON_Parse(buffer); free(buffer); }
    if (!root) { root = cJSON_CreateObject(); cJSON_AddItemToObject(root, "outbounds", cJSON_CreateArray()); }
    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    if (!outbounds) { outbounds = cJSON_CreateArray(); cJSON_AddItemToObject(root, "outbounds", outbounds); }
    int successCount = Internal_BatchAddNodesFromText(text, outbounds);
    if (successCount > 0) { char* out = cJSON_Print(root); WriteBufferToFile(CONFIG_FILE, out); free(out); ParseTags(); }
    cJSON_Delete(root); free(text); return successCount;
}

int UpdateAllSubscriptions(BOOL forceMsg) {
    int activeSubs = 0;
    for(int i=0; i<g_subCount; i++) if(g_subs[i].enabled && strlen(g_subs[i].url) > 4) activeSubs++;
    if (activeSubs == 0) { if (forceMsg) log_msg("[Sub] No active subscriptions found."); return 0; }
    log_msg("[Sub] Starting update for %d subscriptions...", activeSubs);
    char* rawData[MAX_SUBS] = {0}; int downloadSuccess = 0;
    for (int i = 0; i < g_subCount; i++) {
        if (g_subs[i].enabled && strlen(g_subs[i].url) > 4) {
            log_msg("[Sub] Downloading (%d/%d): %s", i+1, g_subCount, g_subs[i].url);
            char* data = Utils_HttpGet(g_subs[i].url);
            if (data) { rawData[i] = data; downloadSuccess++; } else log_msg("[Sub] Download failed: %s", g_subs[i].url);
        }
    }
    if (downloadSuccess == 0) { log_msg("[Error] All downloads failed. Config not updated."); return 0; }
    char* buffer = NULL; long size = 0; cJSON* root = NULL;
    if (ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) { root = cJSON_Parse(buffer); free(buffer); }
    if (!root) { root = cJSON_CreateObject(); }
    if (cJSON_HasObjectItem(root, "outbounds")) cJSON_DeleteItemFromObject(root, "outbounds");
    cJSON* outbounds = cJSON_CreateArray(); cJSON_AddItemToObject(root, "outbounds", outbounds);
    int totalNewNodes = 0;
    for (int i = 0; i < g_subCount; i++) {
        if (rawData[i]) { int count = Internal_BatchAddNodesFromText(rawData[i], outbounds); totalNewNodes += count; free(rawData[i]); }
    }
    log_msg("[Sub] Total nodes parsed: %d. Saving config...", totalNewNodes);
    char* out = cJSON_Print(root); WriteBufferToFile(CONFIG_FILE, out); free(out); cJSON_Delete(root);
    ParseTags(); log_msg("[Sub] Update complete.");
    return totalNewNodes;
}

void ToggleTrayIcon() {
    if (g_isIconVisible) { Shell_NotifyIconW(NIM_DELETE, &nid); g_isIconVisible = FALSE; g_hideTrayStart = 1; }
    else { nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP; Shell_NotifyIconW(NIM_ADD, &nid); g_isIconVisible = TRUE; g_hideTrayStart = 0; }
    SaveSettings();
}

// ... (保留 ParseSocks, ParseShadowsocks, ParseVmess, ParseVlessOrTrojan, 略过未修改部分) ...
cJSON* ParseSocks(const char* link) {
    if (strncmp(link, "socks://", 8) != 0) return NULL;
    const char* p = link + 8; const char* at = strchr(p, '@'); if (!at) return NULL; 
    int authLen = (int)(at - p); char* authBase64 = (char*)malloc(authLen + 1); strncpy(authBase64, p, authLen); authBase64[authLen] = 0;
    size_t decLen; unsigned char* decoded = Base64Decode(authBase64, &decLen); free(authBase64); if (!decoded) return NULL;
    char* user = (char*)decoded; char* pass = strchr(user, ':'); if (pass) { *pass = 0; pass++; } else pass = "";
    p = at + 1; const char* colon = strchr(p, ':'); const char* qMark = strchr(p, '?'); const char* hash = strchr(p, '#');
    const char* portStart = colon ? colon + 1 : NULL; const char* hostEnd = colon ? colon : (qMark ? qMark : (hash ? hash : p + strlen(p)));
    int hostLen = (int)(hostEnd - p); char* host = (char*)malloc(hostLen + 1); strncpy(host, p, hostLen); host[hostLen] = 0;
    int portNum = portStart ? atoi(portStart) : 443;
    char* tag = hash ? (char*)malloc(strlen(hash+1)+1) : strdup("Socks-Import"); if(hash) UrlDecode(tag, hash+1);
    const char* query = qMark ? qMark + 1 : NULL;
    char* sni = GetQueryParam(query, "sni"); if (!sni) sni = GetQueryParam(query, "peer");
    char* path = GetQueryParam(query, "path"); char* type = GetQueryParam(query, "type"); if (!type) type = GetQueryParam(query, "transport");
    char* security = GetQueryParam(query, "security"); char* hostHeader = GetQueryParam(query, "host");
    cJSON* outbound = cJSON_CreateObject();
    cJSON_AddStringToObject(outbound, "type", "socks_tls"); cJSON_AddStringToObject(outbound, "tag", tag);
    cJSON_AddStringToObject(outbound, "server", host); cJSON_AddNumberToObject(outbound, "server_port", portNum);
    cJSON_AddStringToObject(outbound, "username", user); cJSON_AddStringToObject(outbound, "password", pass);
    BOOL enableTls = (security && strcmp(security, "tls") == 0) || sni != NULL;
    if (enableTls) {
        cJSON* tls = cJSON_CreateObject(); cJSON_AddBoolToObject(tls, "enabled", cJSON_True);
        if (sni) cJSON_AddStringToObject(tls, "server_name", sni); else cJSON_AddStringToObject(tls, "server_name", host);
        cJSON_AddItemToObject(outbound, "tls", tls);
    }
    if (type && strcmp(type, "ws") == 0) {
        cJSON* trans = cJSON_CreateObject(); cJSON_AddStringToObject(trans, "type", "ws");
        if (path) cJSON_AddStringToObject(trans, "path", path);
        cJSON* headers = cJSON_CreateObject(); 
        if (hostHeader) cJSON_AddStringToObject(headers, "Host", hostHeader); else cJSON_AddStringToObject(headers, "Host", host);
        cJSON_AddItemToObject(trans, "headers", headers); cJSON_AddItemToObject(outbound, "transport", trans);
    }
    if (sni) free(sni); if (path) free(path); if (type) free(type); if (security) free(security); if (hostHeader) free(hostHeader);
    free(host); free(tag); free(decoded); return outbound;
}

cJSON* ParseShadowsocks(const char* link) {
    if (strncmp(link, "ss://", 5) != 0) return NULL;
    const char* p = link + 5; 
    const char* hash = strchr(p, '#'); char* tag = hash ? (char*)malloc(strlen(hash+1)+1) : strdup("SS");
    if(hash) UrlDecode(tag, hash+1); else strcpy(tag, "SS");
    const char* qMark = strchr(p, '?');
    const char* endOfMain = qMark ? qMark : (hash ? hash : p + strlen(p));
    size_t mainLen = (size_t)(endOfMain - p);
    char* mainPart = (char*)malloc(mainLen + 1); strncpy(mainPart, p, mainLen); mainPart[mainLen] = 0;
    char serverPort[256] = {0}, methodPass[256] = {0}; char* at = strchr(mainPart, '@');
    if (!at) {
        size_t decLen; unsigned char* decoded = Base64Decode(mainPart, &decLen);
        if(!decoded) { free(mainPart); free(tag); return NULL; }
        char* dStr = (char*)decoded; at = strchr(dStr, '@');
        if (at) { strncpy(serverPort, at+1, 255); strncpy(methodPass, dStr, at-dStr); methodPass[at-dStr]=0; }
        free(decoded);
    } else {
        strncpy(serverPort, at+1, 255); char b64User[256]; strncpy(b64User, mainPart, at-mainPart); b64User[at-mainPart] = 0;
        size_t decLen; unsigned char* decoded = Base64Decode(b64User, &decLen);
        if(decoded) { strncpy(methodPass, (char*)decoded, 255); free(decoded); } else strncpy(methodPass, b64User, 255);
    }
    free(mainPart);
    char* colon = strrchr(serverPort, ':'); if (!colon) { free(tag); return NULL; }
    int port = atoi(colon + 1); *colon = 0;
    char* pass = strchr(methodPass, ':'); if (!pass) { free(tag); return NULL; } *pass = 0; pass++;

    cJSON* outbound = cJSON_CreateObject();
    cJSON_AddStringToObject(outbound, "type", "shadowsocks"); cJSON_AddStringToObject(outbound, "tag", tag);
    cJSON_AddStringToObject(outbound, "server", serverPort); cJSON_AddNumberToObject(outbound, "server_port", port);
    cJSON_AddStringToObject(outbound, "method", methodPass); cJSON_AddStringToObject(outbound, "password", pass);

    if (qMark) {
        const char* qStart = qMark + 1; size_t qLen = hash ? (size_t)(hash - qStart) : strlen(qStart);
        char* queryStr = (char*)malloc(qLen + 1); strncpy(queryStr, qStart, qLen); queryStr[qLen] = 0;
        
        char* pluginVal = GetQueryParam(queryStr, "plugin");
        if (pluginVal) { UrlDecode(pluginVal, pluginVal); ParseSSPlugin(outbound, pluginVal); free(pluginVal); }

        char* directSni = GetQueryParam(queryStr, "sni");
        char* directHost = GetQueryParam(queryStr, "host"); if(!directHost) directHost = GetQueryParam(queryStr, "obfs-host");
        char* directPath = GetQueryParam(queryStr, "path");
        char* directMode = GetQueryParam(queryStr, "mode"); if(!directMode) directMode = GetQueryParam(queryStr, "type");
        char* directSecurity = GetQueryParam(queryStr, "security"); 

        BOOL needTls = (directSecurity && strcmp(directSecurity, "tls") == 0) || directSni != NULL;
        if (needTls) {
            cJSON* tlsObj = GetOrCreateObj(outbound, "tls");
            if (!cJSON_HasObjectItem(tlsObj, "enabled")) cJSON_AddBoolToObject(tlsObj, "enabled", cJSON_True);
            if (directSni && !cJSON_HasObjectItem(tlsObj, "server_name")) cJSON_AddStringToObject(tlsObj, "server_name", directSni);
            else if (directHost && !cJSON_HasObjectItem(tlsObj, "server_name")) cJSON_AddStringToObject(tlsObj, "server_name", directHost);
        }

        BOOL isWs = (directMode && strcmp(directMode, "ws") == 0);
        if (isWs) {
             cJSON* trans = GetOrCreateObj(outbound, "transport");
             if (!cJSON_HasObjectItem(trans, "type")) cJSON_AddStringToObject(trans, "type", "ws");
             if (directPath && !cJSON_HasObjectItem(trans, "path")) cJSON_AddStringToObject(trans, "path", directPath);
             if (directHost) {
                 cJSON* headers = GetOrCreateObj(trans, "headers");
                 if (!cJSON_HasObjectItem(headers, "Host")) cJSON_AddStringToObject(headers, "Host", directHost);
             }
        }

        if(directSni) free(directSni); if(directHost) free(directHost); if(directPath) free(directPath);
        if(directMode) free(directMode); if(directSecurity) free(directSecurity);
        free(queryStr);
    }
    
    free(tag); return outbound;
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
    cJSON_AddStringToObject(outbound, "type", protocol); cJSON_AddStringToObject(outbound, "tag", tag);
    cJSON_AddStringToObject(outbound, "server", host); cJSON_AddNumberToObject(outbound, "server_port", portNum);
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

#include "config.h"
#include "utils.h"
#include "proxy.h" 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h> 
#include <time.h> 

// --- 全局变量定义 ---
Subscription g_subs[MAX_SUBS];
int g_subCount = 0;

// 订阅更新配置
int g_subUpdateMode = 0;      // 0=每天, 1=每周, 2=自定义
int g_subUpdateInterval = 24; // 小时
long long g_lastUpdateTime = 0; 

// --- 内部辅助函数声明 ---
int Internal_BatchAddNodesFromText(const char* text, cJSON* outbounds);
char* GetUniqueTagName(cJSON* outbounds, const char* type, const char* base_name);
cJSON* ParseVmess(const char* link);
cJSON* ParseShadowsocks(const char* link);
cJSON* ParseVlessOrTrojan(const char* link);
cJSON* ParseSocks(const char* link);
cJSON* ParseMandala(const char* link);

// [Security] 安全字符串复制辅助函数
static void SafeStrCpy(char* dest, size_t destSize, const char* src) {
    if (!dest || destSize == 0) return;
    if (!src) { dest[0] = '\0'; return; }
    snprintf(dest, destSize, "%s", src);
}

// [Helper] 安全获取或创建 JSON 对象
static cJSON* GetOrCreateObj(cJSON* parent, const char* name) {
    cJSON* item = cJSON_GetObjectItem(parent, name);
    if (!item) {
        item = cJSON_CreateObject();
        cJSON_AddItemToObject(parent, name, item);
    }
    return item;
}

// [Helper] SS Plugin 解析辅助函数
static void ParseSSPlugin(cJSON* outbound, const char* pluginParam) {
    if (!pluginParam || !outbound) return;
    char* pluginCopy = _strdup(pluginParam);
    if (!pluginCopy) return;

    char host[256] = {0}; char path[256] = {0}; char sni[256] = {0}; char mode[64] = {0};
    BOOL isTls = FALSE;
    BOOL isV2ray = (strstr(pluginCopy, "v2ray-plugin") != NULL);
    
    char* start = pluginCopy;
    char* end = NULL;
    
    while (start && *start) {
        end = strchr(start, ';');
        if (end) *end = '\0'; 
        
        if (strncmp(start, "host=", 5) == 0) SafeStrCpy(host, sizeof(host), start+5);
        else if (strncmp(start, "obfs-host=", 10) == 0) SafeStrCpy(host, sizeof(host), start+10);
        else if (strncmp(start, "path=", 5) == 0) SafeStrCpy(path, sizeof(path), start+5);
        else if (strncmp(start, "sni=", 4) == 0) SafeStrCpy(sni, sizeof(sni), start+4);
        else if (strncmp(start, "mode=", 5) == 0) SafeStrCpy(mode, sizeof(mode), start+5);
        else if (strcmp(start, "tls") == 0) isTls = TRUE;
        else if (strncmp(start, "obfs=", 5) == 0) { if (strcmp(start+5, "tls") == 0) isTls = TRUE; }

        if (end) start = end + 1;
        else start = NULL;
    }

    if (isTls) {
        cJSON* tlsObj = GetOrCreateObj(outbound, "tls");
        cJSON_AddBoolToObject(tlsObj, "enabled", cJSON_True);
        if (strlen(sni) > 0) cJSON_AddStringToObject(tlsObj, "server_name", sni);
        else if (strlen(host) > 0 && !cJSON_HasObjectItem(tlsObj, "server_name")) cJSON_AddStringToObject(tlsObj, "server_name", host);
    }

    if (isV2ray && strcmp(mode, "quic") != 0) {
        cJSON* trans = GetOrCreateObj(outbound, "transport");
        if (!cJSON_HasObjectItem(trans, "type")) cJSON_AddStringToObject(trans, "type", "ws");
        if (strlen(path) > 0) cJSON_AddStringToObject(trans, "path", path);
        if (strlen(host) > 0) {
            cJSON* headers = GetOrCreateObj(trans, "headers");
            cJSON_AddStringToObject(headers, "Host", host);
        }
    }
    free(pluginCopy);
}

// --- 配置文件加载与保存 ---

void LoadSettings() {
    UINT modifiers = GetPrivateProfileIntW(L"Settings", L"Modifiers", MOD_CONTROL | MOD_ALT, g_iniFilePath);
    UINT vk = GetPrivateProfileIntW(L"Settings", L"VK", 'H', g_iniFilePath);
    int port = GetPrivateProfileIntW(L"Settings", L"LocalPort", 10809, g_iniFilePath);
    int hideTray = GetPrivateProfileIntW(L"Settings", L"HideTray", 0, g_iniFilePath);
    
    int enableChrome = GetPrivateProfileIntW(L"Settings", L"ChromeCiphers", 1, g_iniFilePath);
    int enableALPN = GetPrivateProfileIntW(L"Settings", L"EnableALPN", 1, g_iniFilePath);
    int enableFrag = GetPrivateProfileIntW(L"Settings", L"EnableFragment", 0, g_iniFilePath);
    int fragMin = GetPrivateProfileIntW(L"Settings", L"FragMin", 5, g_iniFilePath);
    int fragMax = GetPrivateProfileIntW(L"Settings", L"FragMax", 20, g_iniFilePath);
    int fragDly = GetPrivateProfileIntW(L"Settings", L"FragDelay", 2, g_iniFilePath);
    int enablePad = GetPrivateProfileIntW(L"Settings", L"EnablePadding", 0, g_iniFilePath);
    int padMin = GetPrivateProfileIntW(L"Settings", L"PadMin", 100, g_iniFilePath);
    int padMax = GetPrivateProfileIntW(L"Settings", L"PadMax", 500, g_iniFilePath);
    int uaIdx = GetPrivateProfileIntW(L"Settings", L"UAPlatform", 0, g_iniFilePath);

    int enableECH = GetPrivateProfileIntW(L"Settings", L"EnableECH", 0, g_iniFilePath);
    wchar_t wEchServer[256] = {0};
    GetPrivateProfileStringW(L"Settings", L"ECHServer", L"https://cloudflare-dns.com/dns-query", wEchServer, 256, g_iniFilePath);
    wchar_t wEchPub[256] = {0};
    GetPrivateProfileStringW(L"Settings", L"ECHPublicName", L"", wEchPub, 256, g_iniFilePath);

    int upMode = GetPrivateProfileIntW(L"Subscriptions", L"UpdateMode", 0, g_iniFilePath);
    int upInterval = GetPrivateProfileIntW(L"Subscriptions", L"UpdateInterval", 24, g_iniFilePath);
    wchar_t wTimeBuf[64] = {0};
    GetPrivateProfileStringW(L"Subscriptions", L"LastUpdateTime", L"0", wTimeBuf, 64, g_iniFilePath);
    long long lastTime = _wtoi64(wTimeBuf);

    wchar_t wUABuf[512] = {0}; 
    GetPrivateProfileStringW(L"Settings", L"UserAgent", L"", wUABuf, 512, g_iniFilePath);
    wchar_t wLastNode[64] = {0};
    GetPrivateProfileStringW(L"Settings", L"LastNode", L"", wLastNode, 64, g_iniFilePath);

    EnterCriticalSection(&g_configLock);

    g_hotkeyModifiers = modifiers;
    g_hotkeyVk = vk;
    g_localPort = port;
    g_hideTrayStart = hideTray;
    
    g_enableChromeCiphers = enableChrome;
    g_enableALPN = enableALPN;
    g_enableFragment = enableFrag;
    g_fragSizeMin = fragMin; 
    g_fragSizeMax = fragMax; 
    g_fragDelayMs = fragDly;
    g_enablePadding = enablePad; 
    g_padSizeMin = padMin; 
    g_padSizeMax = padMax;

    if (g_fragSizeMin < 1) g_fragSizeMin = 1; 
    if (g_fragSizeMax < g_fragSizeMin) g_fragSizeMax = g_fragSizeMin;
    if (g_padSizeMin < 0) g_padSizeMin = 0; 
    if (g_padSizeMax < g_padSizeMin) g_padSizeMax = g_padSizeMin;

    g_enableECH = enableECH;
    WideCharToMultiByte(CP_UTF8, 0, wEchServer, -1, g_echConfigServer, sizeof(g_echConfigServer), NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, wEchPub, -1, g_echPublicName, sizeof(g_echPublicName), NULL, NULL);

    g_uaPlatformIndex = uaIdx;
    g_subUpdateMode = upMode;
    g_subUpdateInterval = upInterval;
    g_lastUpdateTime = lastTime;

    if (wcslen(wUABuf) > 5) WideCharToMultiByte(CP_UTF8, 0, wUABuf, -1, g_userAgentStr, sizeof(g_userAgentStr), NULL, NULL);
    else SafeStrCpy(g_userAgentStr, sizeof(g_userAgentStr), UA_TEMPLATES[0]);

    wcsncpy(currentNode, wLastNode, 63); 
    currentNode[63] = 0;

    g_subCount = GetPrivateProfileIntW(L"Subscriptions", L"Count", 0, g_iniFilePath);
    if (g_subCount > MAX_SUBS) g_subCount = MAX_SUBS;
    
    for (int i = 0; i < g_subCount; i++) {
        wchar_t wKeyEn[32], wKeyUrl[32], wUrl[512];
        swprintf(wKeyEn, 32, L"Sub%d_Enabled", i); 
        swprintf(wKeyUrl, 32, L"Sub%d_Url", i);
        g_subs[i].enabled = GetPrivateProfileIntW(L"Subscriptions", wKeyEn, 1, g_iniFilePath);
        GetPrivateProfileStringW(L"Subscriptions", wKeyUrl, L"", wUrl, 512, g_iniFilePath);
        WideCharToMultiByte(CP_UTF8, 0, wUrl, -1, g_subs[i].url, 512, NULL, NULL);
    }

    LeaveCriticalSection(&g_configLock);
}

void SaveSettings() {
    EnterCriticalSection(&g_configLock);
    
    wchar_t buffer[32];
    swprintf(buffer, 32, L"%u", g_hotkeyModifiers); WritePrivateProfileStringW(L"Settings", L"Modifiers", buffer, g_iniFilePath);
    swprintf(buffer, 32, L"%u", g_hotkeyVk); WritePrivateProfileStringW(L"Settings", L"VK", buffer, g_iniFilePath);
    swprintf(buffer, 32, L"%d", g_localPort); WritePrivateProfileStringW(L"Settings", L"LocalPort", buffer, g_iniFilePath);
    swprintf(buffer, 32, L"%d", g_hideTrayStart); WritePrivateProfileStringW(L"Settings", L"HideTray", buffer, g_iniFilePath);
    
    swprintf(buffer, 32, L"%d", g_enableChromeCiphers); WritePrivateProfileStringW(L"Settings", L"ChromeCiphers", buffer, g_iniFilePath);
    swprintf(buffer, 32, L"%d", g_enableALPN); WritePrivateProfileStringW(L"Settings", L"EnableALPN", buffer, g_iniFilePath);
    swprintf(buffer, 32, L"%d", g_enableFragment); WritePrivateProfileStringW(L"Settings", L"EnableFragment", buffer, g_iniFilePath);
    swprintf(buffer, 32, L"%d", g_fragSizeMin); WritePrivateProfileStringW(L"Settings", L"FragMin", buffer, g_iniFilePath);
    swprintf(buffer, 32, L"%d", g_fragSizeMax); WritePrivateProfileStringW(L"Settings", L"FragMax", buffer, g_iniFilePath);
    swprintf(buffer, 32, L"%d", g_fragDelayMs); WritePrivateProfileStringW(L"Settings", L"FragDelay", buffer, g_iniFilePath);
    swprintf(buffer, 32, L"%d", g_enablePadding); WritePrivateProfileStringW(L"Settings", L"EnablePadding", buffer, g_iniFilePath);
    swprintf(buffer, 32, L"%d", g_padSizeMin); WritePrivateProfileStringW(L"Settings", L"PadMin", buffer, g_iniFilePath);
    swprintf(buffer, 32, L"%d", g_padSizeMax); WritePrivateProfileStringW(L"Settings", L"PadMax", buffer, g_iniFilePath);
    swprintf(buffer, 32, L"%d", g_uaPlatformIndex); WritePrivateProfileStringW(L"Settings", L"UAPlatform", buffer, g_iniFilePath);
    
    swprintf(buffer, 32, L"%d", g_enableECH); WritePrivateProfileStringW(L"Settings", L"EnableECH", buffer, g_iniFilePath);
    
    wchar_t wEchServerOut[256] = {0}; MultiByteToWideChar(CP_UTF8, 0, g_echConfigServer, -1, wEchServerOut, 256);
    WritePrivateProfileStringW(L"Settings", L"ECHServer", wEchServerOut, g_iniFilePath);
    
    wchar_t wEchPubOut[256] = {0}; MultiByteToWideChar(CP_UTF8, 0, g_echPublicName, -1, wEchPubOut, 256);
    WritePrivateProfileStringW(L"Settings", L"ECHPublicName", wEchPubOut, g_iniFilePath);

    wchar_t wUABuf[512] = {0}; MultiByteToWideChar(CP_UTF8, 0, g_userAgentStr, -1, wUABuf, 512);
    WritePrivateProfileStringW(L"Settings", L"UserAgent", wUABuf, g_iniFilePath);

    WritePrivateProfileStringW(L"Settings", L"LastNode", currentNode, g_iniFilePath);

    WritePrivateProfileStringW(L"Subscriptions", NULL, NULL, g_iniFilePath);
    swprintf(buffer, 32, L"%lld", g_lastUpdateTime); WritePrivateProfileStringW(L"Subscriptions", L"LastUpdateTime", buffer, g_iniFilePath);
    swprintf(buffer, 32, L"%d", g_subUpdateMode); WritePrivateProfileStringW(L"Subscriptions", L"UpdateMode", buffer, g_iniFilePath);
    swprintf(buffer, 32, L"%d", g_subUpdateInterval); WritePrivateProfileStringW(L"Subscriptions", L"UpdateInterval", buffer, g_iniFilePath);
    swprintf(buffer, 32, L"%d", g_subCount); WritePrivateProfileStringW(L"Subscriptions", L"Count", buffer, g_iniFilePath);
    
    for (int i = 0; i < g_subCount; i++) {
        wchar_t wKeyEn[32], wKeyUrl[32], wUrl[512], wVal[2];
        swprintf(wKeyEn, 32, L"Sub%d_Enabled", i); 
        swprintf(wKeyUrl, 32, L"Sub%d_Url", i);
        swprintf(wVal, 2, L"%d", g_subs[i].enabled); 
        WritePrivateProfileStringW(L"Subscriptions", wKeyEn, wVal, g_iniFilePath);
        MultiByteToWideChar(CP_UTF8, 0, g_subs[i].url, -1, wUrl, 512); 
        WritePrivateProfileStringW(L"Subscriptions", wKeyUrl, wUrl, g_iniFilePath);
    }

    LeaveCriticalSection(&g_configLock);
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
    EnterCriticalSection(&g_configLock);

    if (nodeTags) { for(int i=0; i<nodeCount; i++) free(nodeTags[i]); free(nodeTags); }
    nodeCount = 0; nodeTags = NULL;
    char* buffer = NULL; long size = 0;
    
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) {
        LeaveCriticalSection(&g_configLock);
        return;
    }

    cJSON* root = cJSON_Parse(buffer); free(buffer);
    if (!root) {
        LeaveCriticalSection(&g_configLock);
        return;
    }

    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    if (outbounds) {
        cJSON* node;
        cJSON_ArrayForEach(node, outbounds) {
            cJSON* tag = cJSON_GetObjectItem(node, "tag");
            if (tag && tag->valuestring) {
                nodeCount++;
                nodeTags = (wchar_t**)realloc(nodeTags, nodeCount * sizeof(wchar_t*));
                int wlen = MultiByteToWideChar(CP_UTF8, 0, tag->valuestring, -1, NULL, 0);
                nodeTags[nodeCount-1] = (wchar_t*)malloc((wlen+1)*sizeof(wchar_t));
                MultiByteToWideChar(CP_UTF8, 0, tag->valuestring, -1, nodeTags[nodeCount-1], wlen+1);
                nodeTags[nodeCount-1][wlen] = 0;
            }
        }
    }
    cJSON_Delete(root);
    LeaveCriticalSection(&g_configLock);
}

char* GetUniqueTagName(cJSON* outbounds, const char* type, const char* base_name) {
    static char final_tag[512]; char candidate[450];
    const char* safe_name = (base_name && strlen(base_name) > 0) ? base_name : "Unnamed";
    
    char clean_name[256];
    strncpy(clean_name, safe_name, 255); clean_name[255] = 0;
    for(int i=0; clean_name[i]; i++) {
        if(strchr("/\\:*?\"<>|", clean_name[i])) clean_name[i] = '_';
    }

    snprintf(candidate, sizeof(candidate), "%s-%s", type, clean_name);
    
    int index = 0;
    while (1) {
        if (index == 0) snprintf(final_tag, sizeof(final_tag), "%s", candidate);
        else snprintf(final_tag, sizeof(final_tag), "%s (%d)", candidate, index);
        
        BOOL exists = FALSE; 
        if (outbounds) {
            cJSON* item = NULL;
            cJSON_ArrayForEach(item, outbounds) {
                cJSON* t = cJSON_GetObjectItem(item, "tag");
                if (t && t->valuestring && strcmp(t->valuestring, final_tag) == 0) { exists = TRUE; break; }
            }
        }
        if (!exists) break;
        index++;
    }
    return final_tag;
}

void ParseNodeConfigToGlobal(cJSON *node) {
    if (!node) return;
    EnterCriticalSection(&g_configLock);

    memset(&g_proxyConfig, 0, sizeof(ProxyConfig));
    SafeStrCpy(g_proxyConfig.path, sizeof(g_proxyConfig.path), "/"); 

    cJSON *server = cJSON_GetObjectItem(node, "server");
    cJSON *port = cJSON_GetObjectItem(node, "server_port");
    cJSON *uuid = cJSON_GetObjectItem(node, "uuid");
    if (!uuid) uuid = cJSON_GetObjectItem(node, "password"); 
    
    if (server && server->valuestring) SafeStrCpy(g_proxyConfig.host, sizeof(g_proxyConfig.host), server->valuestring);
    if (port) g_proxyConfig.port = port->valueint;
    
    if (uuid && uuid->valuestring) { 
        SafeStrCpy(g_proxyConfig.user, sizeof(g_proxyConfig.user), uuid->valuestring); 
        SafeStrCpy(g_proxyConfig.pass, sizeof(g_proxyConfig.pass), uuid->valuestring); 
    }
    
    cJSON *user = cJSON_GetObjectItem(node, "username"); 
    cJSON *pass = cJSON_GetObjectItem(node, "password");
    if(user && user->valuestring) SafeStrCpy(g_proxyConfig.user, sizeof(g_proxyConfig.user), user->valuestring);
    if(pass && pass->valuestring) SafeStrCpy(g_proxyConfig.pass, sizeof(g_proxyConfig.pass), pass->valuestring);
    
    cJSON *tls = cJSON_GetObjectItem(node, "tls");
    cJSON *security = cJSON_GetObjectItem(node, "security");
    BOOL isTls = (tls && cJSON_GetObjectItem(tls, "enabled")) || (security && strcmp(security->valuestring, "tls")==0);
    
    if (isTls) {
        cJSON *sni = NULL;
        if (tls) sni = cJSON_GetObjectItem(tls, "server_name");
        if (sni && sni->valuestring) SafeStrCpy(g_proxyConfig.sni, sizeof(g_proxyConfig.sni), sni->valuestring);
    }
    
    cJSON *trans = cJSON_GetObjectItem(node, "transport");
    if(trans) {
        cJSON *path = cJSON_GetObjectItem(trans, "path");
        if(path && path->valuestring) SafeStrCpy(g_proxyConfig.path, sizeof(g_proxyConfig.path), path->valuestring);
        
        cJSON* wsSettings = cJSON_GetObjectItem(trans, "wsSettings");
        if (wsSettings) {
             cJSON *wpath = cJSON_GetObjectItem(wsSettings, "path");
             if(wpath && wpath->valuestring) SafeStrCpy(g_proxyConfig.path, sizeof(g_proxyConfig.path), wpath->valuestring);
        }
    }
    
    if (strlen(g_proxyConfig.sni) == 0) SafeStrCpy(g_proxyConfig.sni, sizeof(g_proxyConfig.sni), g_proxyConfig.host);

    cJSON *type = cJSON_GetObjectItem(node, "type");
    if (type && type->valuestring) SafeStrCpy(g_proxyConfig.type, sizeof(g_proxyConfig.type), type->valuestring);
    else SafeStrCpy(g_proxyConfig.type, sizeof(g_proxyConfig.type), "socks");

    LeaveCriticalSection(&g_configLock);
    log_msg("Node Config Loaded: %s:%d (Type: %s, SNI: %s)", g_proxyConfig.host, g_proxyConfig.port, g_proxyConfig.type, g_proxyConfig.sni);
}

void SwitchNode(const wchar_t* tag) {
    if (!tag) return;
    EnterCriticalSection(&g_configLock);
    wcsncpy(currentNode, tag, 63); currentNode[63] = 0;
    LeaveCriticalSection(&g_configLock);

    char* buffer = NULL; long size = 0;
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) return;
    cJSON* root = cJSON_Parse(buffer); free(buffer);
    if (!root) return;
    
    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    cJSON* targetNode = NULL;
    char tagUtf8[256]; WideCharToMultiByte(CP_UTF8, 0, tag, -1, tagUtf8, 256, NULL, NULL);
    if (outbounds) {
        cJSON* node;
        cJSON_ArrayForEach(node, outbounds) {
            cJSON* t = cJSON_GetObjectItem(node, "tag");
            if (t && strcmp(t->valuestring, tagUtf8) == 0) { targetNode = node; break; }
        }
    }
    
    if (targetNode) {
        ParseNodeConfigToGlobal(targetNode); 
        StartProxyCore(); 
        SaveSettings();   
        
        wchar_t tip[128]; swprintf(tip, 128, L"当前节点: %s", tag);
        wcsncpy(nid.szInfo, tip, 255); 
        wcsncpy(nid.szInfoTitle, L"连接切换", 63); 
        nid.uFlags |= NIF_INFO;
        Shell_NotifyIconW(NIM_MODIFY, &nid);
    }
    cJSON_Delete(root);
}

void DeleteNode(const wchar_t* tag) {
    if (!tag) return;
    char* buffer = NULL; long size = 0;
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) return;
    cJSON* root = cJSON_Parse(buffer); free(buffer);
    if (!root) return;
    
    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    if (outbounds) {
        char tagUtf8[256]; WideCharToMultiByte(CP_UTF8, 0, tag, -1, tagUtf8, 256, NULL, NULL);
        int idx = 0; cJSON* node;
        cJSON_ArrayForEach(node, outbounds) {
            cJSON* t = cJSON_GetObjectItem(node, "tag");
            if (t && strcmp(t->valuestring, tagUtf8) == 0) { cJSON_DeleteItemFromArray(outbounds, idx); break; }
            idx++;
        }
        char* out = cJSON_Print(root); 
        if (out) { WriteBufferToFile(CONFIG_FILE, out); free(out); }
    }
    cJSON_Delete(root);
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
    char* out = cJSON_Print(root); 
    BOOL ret = FALSE;
    if (out) { ret = WriteBufferToFile(CONFIG_FILE, out); free(out); }
    cJSON_Delete(root);
    return ret;
}

// --- 订阅更新 ---

int Internal_BatchAddNodesFromText(const char* text, cJSON* outbounds) {
    if (!text || !outbounds) return 0;
    int count = 0; 
    char* sourceText = NULL;
    unsigned char* decoded = NULL;
    size_t decLen = 0;

    if (strstr(text, "://")) { sourceText = _strdup(text); } 
    else {
        decoded = Base64Decode(text, &decLen);
        if (decoded && decLen > 0) sourceText = (char*)decoded;
        else { sourceText = _strdup(text); if (decoded) free(decoded); }
    }
    
    if (!sourceText) return 0;
    
    char* p = sourceText;
    while (*p) {
        p += strspn(p, "\r\n ,");
        if (!*p) break;
        size_t len = strcspn(p, "\r\n ,");
        if (len > 0) {
            char* line = (char*)malloc(len + 1);
            if (line) {
                strncpy(line, p, len); line[len] = '\0';
                TrimString(line);
                if (strlen(line) > 0) {
                    cJSON* node = NULL;
                    if (_strnicmp(line, "vmess://", 8) == 0) node = ParseVmess(line);
                    else if (_strnicmp(line, "ss://", 5) == 0) node = ParseShadowsocks(line);
                    else if (_strnicmp(line, "vless://", 8) == 0) node = ParseVlessOrTrojan(line);
                    else if (_strnicmp(line, "trojan://", 9) == 0) node = ParseVlessOrTrojan(line);
                    else if (_strnicmp(line, "socks://", 8) == 0) node = ParseSocks(line);
                    else if (_strnicmp(line, "mandala://", 10) == 0) node = ParseMandala(line); 
                    
                    if (node) {
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
                free(line);
            }
            p += len;
        }
    }
    if (sourceText != (char*)decoded) free(sourceText); else free(decoded);
    return count;
}

int ImportFromClipboard() {
    char* text = GetClipboardText(); if (!text) return 0;
    EnterCriticalSection(&g_configLock);
    char* buffer = NULL; long size = 0; cJSON* root = NULL;
    if (ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) { root = cJSON_Parse(buffer); free(buffer); }
    if (!root) { root = cJSON_CreateObject(); }
    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    if (!outbounds) { outbounds = cJSON_CreateArray(); cJSON_AddItemToObject(root, "outbounds", outbounds); }
    int successCount = Internal_BatchAddNodesFromText(text, outbounds);
    if (successCount > 0) { 
        char* out = cJSON_Print(root); 
        if (out) { WriteBufferToFile(CONFIG_FILE, out); free(out); }
    }
    cJSON_Delete(root); 
    ParseTags();
    LeaveCriticalSection(&g_configLock);
    free(text); 
    return successCount;
}

// [修复] 解决订阅更新时的线程冲突与 Runtime 错误
int UpdateAllSubscriptions(BOOL forceMsg) {
    char subUrls[MAX_SUBS][512]; int count = 0;
    EnterCriticalSection(&g_configLock);
    for (int i = 0; i < g_subCount; i++) {
        if (g_subs[i].enabled && strlen(g_subs[i].url) > 4) {
            strncpy(subUrls[count], g_subs[i].url, 511); subUrls[count][511]=0;
            count++;
        }
    }
    LeaveCriticalSection(&g_configLock);
    if (count == 0) return 0;

    char* rawData[MAX_SUBS] = {0}; 
    for (int i = 0; i < count; i++) {
        log_msg("[Sub] Downloading (%d/%d): %s", i+1, count, subUrls[i]);
        rawData[i] = Utils_HttpGet(subUrls[i]);
    }

    // 必须在加锁状态下操作配置文件
    EnterCriticalSection(&g_configLock);
    char* buffer = NULL; long size = 0; cJSON* root = NULL;
    if (ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) { root = cJSON_Parse(buffer); free(buffer); }
    if (!root) root = cJSON_CreateObject();
    
    cJSON_DeleteItemFromObject(root, "outbounds");
    cJSON* outbounds = cJSON_CreateArray(); 
    cJSON_AddItemToObject(root, "outbounds", outbounds);
    
    int totalNewNodes = 0;
    for (int i = 0; i < count; i++) {
        if (rawData[i]) { 
            totalNewNodes += Internal_BatchAddNodesFromText(rawData[i], outbounds); 
            free(rawData[i]); rawData[i] = NULL;
        }
    }
    
    char* out = cJSON_Print(root); 
    if (out) { WriteBufferToFile(CONFIG_FILE, out); free(out); }
    cJSON_Delete(root);
    g_lastUpdateTime = (long long)time(NULL);
    SaveSettings(); 
    ParseTags(); 
    LeaveCriticalSection(&g_configLock);
    
    log_msg("[Sub] Update complete. New nodes: %d", totalNewNodes);
    return totalNewNodes;
}

// --- 协议解析 (保持原有逻辑并修复内存泄漏) ---

cJSON* ParseVlessOrTrojan(const char* link) {
    char protocol[16] = {0};
    if (strncmp(link, "vless://", 8) == 0) strcpy(protocol, "vless");
    else if (strncmp(link, "trojan://", 9) == 0) strcpy(protocol, "trojan");
    else return NULL;
    const char* p = link + strlen(protocol) + 3; const char* at = strchr(p, '@'); if (!at) return NULL;
    int uuidLen = (int)(at - p); char* uuid = (char*)malloc(uuidLen + 1); strncpy(uuid, p, uuidLen); uuid[uuidLen] = 0;
    p = at + 1; const char* colon = strchr(p, ':'); const char* qMark = strchr(p, '?'); const char* hash = strchr(p, '#');
    const char* hostEnd = colon;
    if (!hostEnd || (qMark && qMark < hostEnd)) hostEnd = qMark;
    if (!hostEnd || (hash && hash < hostEnd)) hostEnd = hash;
    if (!hostEnd) hostEnd = p + strlen(p);
    const char* portStart = colon ? colon + 1 : NULL; int hostLen = (int)(hostEnd - p); char* host = (char*)malloc(hostLen + 1); 
    strncpy(host, p, hostLen); host[hostLen] = 0;
    int portNum = portStart ? atoi(portStart) : 443;
    char* tag = hash ? (char*)malloc(strlen(hash+1)+1) : _strdup(protocol);
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
        char* pth = GetQueryParam(query, "path");
        if (pth) { char* dPath = _strdup(pth); if(dPath) { UrlDecode(dPath, pth); cJSON_AddStringToObject(t, "path", dPath); free(dPath); } free(pth); }
        char* hHdr = GetQueryParam(query, "host");
        if (hHdr) { cJSON* hdrs = cJSON_CreateObject(); cJSON_AddStringToObject(hdrs, "Host", hHdr); cJSON_AddItemToObject(t, "headers", hdrs); free(hHdr); }
        cJSON_AddItemToObject(outbound, "transport", t);
    }
    if (type) free(type);
    char* sec = GetQueryParam(query, "security");
    if (sec && strcmp(sec, "tls") == 0) {
        cJSON* tObj = cJSON_CreateObject(); cJSON_AddBoolToObject(tObj, "enabled", cJSON_True);
        char* sni = GetQueryParam(query, "sni");
        if (sni) { cJSON_AddStringToObject(tObj, "server_name", sni); free(sni); }
        else cJSON_AddStringToObject(tObj, "server_name", host);
        cJSON_AddItemToObject(outbound, "tls", tObj);
    }
    if (sec) free(sec);
    free(uuid); free(host); free(tag); return outbound;
}

cJSON* ParseVmess(const char* link) {
    if (strncmp(link, "vmess://", 8) != 0) return NULL;
    size_t len; unsigned char* decoded = Base64Decode(link + 8, &len); if (!decoded) return NULL;
    cJSON* vmessJson = cJSON_Parse((const char*)decoded); free(decoded); if (!vmessJson) return NULL;
    cJSON* outbound = cJSON_CreateObject();
    cJSON_AddStringToObject(outbound, "type", "vmess");
    cJSON* ps = cJSON_GetObjectItem(vmessJson, "ps"); cJSON_AddStringToObject(outbound, "tag", cJSON_IsString(ps) ? ps->valuestring : "VMess");
    cJSON* add = cJSON_GetObjectItem(vmessJson, "add"); cJSON_AddStringToObject(outbound, "server", cJSON_IsString(add) ? add->valuestring : "");
    cJSON* prt = cJSON_GetObjectItem(vmessJson, "port");
    cJSON_AddNumberToObject(outbound, "server_port", cJSON_IsNumber(prt)?prt->valueint:(prt?atoi(prt->valuestring):0));
    cJSON* id = cJSON_GetObjectItem(vmessJson, "id"); cJSON_AddStringToObject(outbound, "uuid", cJSON_IsString(id) ? id->valuestring : "");
    cJSON* net = cJSON_GetObjectItem(vmessJson, "net");
    if (cJSON_IsString(net) && strcmp(net->valuestring, "ws") == 0) {
        cJSON* t = cJSON_CreateObject(); cJSON_AddStringToObject(t, "type", "ws");
        cJSON* pth = cJSON_GetObjectItem(vmessJson, "path"); if(cJSON_IsString(pth)) cJSON_AddStringToObject(t, "path", pth->valuestring);
        cJSON* hst = cJSON_GetObjectItem(vmessJson, "host");
        if(cJSON_IsString(hst) && strlen(hst->valuestring)>0) {
            cJSON* h = cJSON_CreateObject(); cJSON_AddStringToObject(h, "Host", hst->valuestring); cJSON_AddItemToObject(t, "headers", h);
        }
        cJSON_AddItemToObject(outbound, "transport", t);
    } 
    cJSON* tls = cJSON_GetObjectItem(vmessJson, "tls");
    if (cJSON_IsString(tls) && strcmp(tls->valuestring, "tls") == 0) {
        cJSON* t = cJSON_CreateObject(); cJSON_AddBoolToObject(t, "enabled", cJSON_True);
        cJSON* sni = cJSON_GetObjectItem(vmessJson, "sni"); if (cJSON_IsString(sni) && strlen(sni->valuestring)>0) cJSON_AddStringToObject(t, "server_name", sni->valuestring);
        cJSON_AddItemToObject(outbound, "tls", t);
    }
    cJSON_Delete(vmessJson); return outbound;
}

cJSON* ParseShadowsocks(const char* link) {
    if (strncmp(link, "ss://", 5) != 0) return NULL;
    const char* p = link + 5; const char* hash = strchr(p, '#'); 
    char* tag = hash ? (char*)malloc(strlen(hash+1)+1) : _strdup("SS-Node"); if (hash) UrlDecode(tag, hash+1); 
    const char* qMark = strchr(p, '?'); const char* endOfMain = qMark ? qMark : (hash ? hash : p + strlen(p));
    size_t mainLen = (size_t)(endOfMain - p); if (mainLen <= 0) { free(tag); return NULL; }
    char* mainPart = (char*)malloc(mainLen + 1); strncpy(mainPart, p, mainLen); mainPart[mainLen] = 0;
    char serverPort[256] = {0}, methodPass[256] = {0}; char* at = strchr(mainPart, '@');
    if (!at) {
        size_t decLen; unsigned char* decoded = Base64Decode(mainPart, &decLen);
        if(!decoded) { free(mainPart); free(tag); return NULL; }
        at = strchr((char*)decoded, '@');
        if (at) { SafeStrCpy(serverPort, sizeof(serverPort), at+1); size_t mpLen = at - (char*)decoded; if (mpLen >= sizeof(methodPass)) mpLen = sizeof(methodPass) - 1; strncpy(methodPass, (char*)decoded, mpLen); methodPass[mpLen]=0; }
        free(decoded);
    } else {
        SafeStrCpy(serverPort, sizeof(serverPort), at+1); char b64User[256]; size_t uLen = at - mainPart;
        if (uLen >= sizeof(b64User)) uLen = sizeof(b64User) - 1; strncpy(b64User, mainPart, uLen); b64User[uLen] = 0;
        size_t decLen; unsigned char* decoded = Base64Decode(b64User, &decLen);
        if(decoded) { SafeStrCpy(methodPass, sizeof(methodPass), (char*)decoded); free(decoded); }
        else SafeStrCpy(methodPass, sizeof(methodPass), b64User);
    }
    free(mainPart);
    char* colon = strrchr(serverPort, ':'); if (!colon) { free(tag); return NULL; }
    int prt = atoi(colon + 1); *colon = 0; 
    char* pass = strchr(methodPass, ':'); if (!pass) { free(tag); return NULL; } *pass = 0; pass++; 
    cJSON* outbound = cJSON_CreateObject();
    cJSON_AddStringToObject(outbound, "type", "shadowsocks"); cJSON_AddStringToObject(outbound, "tag", tag);
    cJSON_AddStringToObject(outbound, "server", serverPort); cJSON_AddNumberToObject(outbound, "server_port", prt);
    cJSON_AddStringToObject(outbound, "method", methodPass); cJSON_AddStringToObject(outbound, "password", pass);
    if (qMark) {
        const char* qStart = qMark + 1; size_t qLen = hash ? (size_t)(hash - qStart) : strlen(qStart);
        char* qStr = (char*)malloc(qLen + 1); strncpy(qStr, qStart, qLen); qStr[qLen] = 0;
        char* pVal = GetQueryParam(qStr, "plugin"); if (pVal) { UrlDecode(pVal, pVal); ParseSSPlugin(outbound, pVal); free(pVal); }
        free(qStr);
    }
    free(tag); return outbound;
}

cJSON* ParseSocks(const char* link) {
    if (strncmp(link, "socks://", 8) != 0) return NULL;
    const char* p = link + 8; const char* at = strchr(p, '@'); if (!at) return NULL; 
    int authLen = (int)(at - p); char* authB64 = (char*)malloc(authLen + 1); strncpy(authB64, p, authLen); authB64[authLen] = 0;
    size_t decLen; unsigned char* decoded = Base64Decode(authB64, &decLen); free(authB64); if (!decoded) return NULL;
    char* user = (char*)decoded; char* pass = strchr(user, ':'); if (pass) { *pass = 0; pass++; } else pass = "";
    p = at + 1; const char* colon = strchr(p, ':'); const char* qMark = strchr(p, '?'); const char* hash = strchr(p, '#');
    const char* hostEnd = colon;
    if (!hostEnd || (qMark && qMark < hostEnd)) hostEnd = qMark;
    if (!hostEnd || (hash && hash < hostEnd)) hostEnd = hash;
    if (!hostEnd) hostEnd = p + strlen(p);
    int prtNum = (colon && colon < hostEnd) ? atoi(colon + 1) : 443;
    int hostLen = (int)(hostEnd - p); char* host = (char*)malloc(hostLen + 1); strncpy(host, p, hostLen); host[hostLen] = 0;
    char* tag = hash ? (char*)malloc(strlen(hash+1)+1) : _strdup("Socks-Import"); if(hash) UrlDecode(tag, hash+1);
    const char* qry = qMark ? qMark + 1 : NULL; char* sni = GetQueryParam(qry, "sni"); if (!sni) sni = GetQueryParam(qry, "peer");
    char* pth = GetQueryParam(qry, "path");
    if (pth) { char* dPth = _strdup(pth); if (dPth) { UrlDecode(dPth, pth); free(pth); pth = dPth; } }
    char* typ = GetQueryParam(qry, "type"); if (!typ) typ = GetQueryParam(qry, "transport");
    char* sec = GetQueryParam(qry, "security"); char* hHdr = GetQueryParam(qry, "host");
    cJSON* outbound = cJSON_CreateObject();
    cJSON_AddStringToObject(outbound, "type", "socks_tls"); cJSON_AddStringToObject(outbound, "tag", tag);
    cJSON_AddStringToObject(outbound, "server", host); cJSON_AddNumberToObject(outbound, "server_port", prtNum);
    cJSON_AddStringToObject(outbound, "username", user); cJSON_AddStringToObject(outbound, "password", pass);
    if ((sec && strcmp(sec, "tls") == 0) || sni != NULL) {
        cJSON* tls = cJSON_CreateObject(); cJSON_AddBoolToObject(tls, "enabled", cJSON_True);
        cJSON_AddStringToObject(tls, "server_name", sni ? sni : host); cJSON_AddItemToObject(outbound, "tls", tls);
    }
    if (typ && strcmp(typ, "ws") == 0) {
        cJSON* trans = cJSON_CreateObject(); cJSON_AddStringToObject(trans, "type", "ws");
        if (pth) cJSON_AddStringToObject(trans, "path", pth);
        cJSON* hdrs = cJSON_CreateObject(); cJSON_AddStringToObject(hdrs, "Host", hHdr ? hHdr : host);
        cJSON_AddItemToObject(trans, "headers", hdrs); cJSON_AddItemToObject(outbound, "transport", trans);
    }
    if (sni) free(sni); if (pth) free(pth); if (typ) free(typ); if (sec) free(sec); if (hHdr) free(hHdr);
    free(host); free(tag); free(decoded); return outbound;
}

cJSON* ParseMandala(const char* link) { return ParseVlessOrTrojan(link); }

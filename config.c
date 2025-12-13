#include "config.h"
#include "utils.h"
#include "proxy.h" 
#include <wininet.h> // 需要包含此头文件以支持 WinINet

// --- 新增：全局订阅地址变量 ---
char g_subUrl[512] = "";

void LoadSettings() {
    g_hotkeyModifiers = GetPrivateProfileIntW(L"Settings", L"Modifiers", MOD_CONTROL | MOD_ALT, g_iniFilePath);
    g_hotkeyVk = GetPrivateProfileIntW(L"Settings", L"VK", 'H', g_iniFilePath);
    g_localPort = GetPrivateProfileIntW(L"Settings", L"LocalPort", 10809, g_iniFilePath);
    g_hideTrayStart = GetPrivateProfileIntW(L"Settings", L"HideTray", 0, g_iniFilePath);
    
    // 抗封锁配置读取
    g_enableChromeCiphers = GetPrivateProfileIntW(L"Settings", L"ChromeCiphers", 1, g_iniFilePath);
    g_enableALPN = GetPrivateProfileIntW(L"Settings", L"EnableALPN", 1, g_iniFilePath);
    g_enableFragment = GetPrivateProfileIntW(L"Settings", L"EnableFragment", 0, g_iniFilePath);
    
    g_fragSizeMin = GetPrivateProfileIntW(L"Settings", L"FragMin", 5, g_iniFilePath);
    g_fragSizeMax = GetPrivateProfileIntW(L"Settings", L"FragMax", 20, g_iniFilePath);
    g_fragDelayMs = GetPrivateProfileIntW(L"Settings", L"FragDelay", 2, g_iniFilePath);

    g_enablePadding = GetPrivateProfileIntW(L"Settings", L"EnablePadding", 0, g_iniFilePath);
    
    g_padSizeMin = GetPrivateProfileIntW(L"Settings", L"PadMin", 100, g_iniFilePath);
    g_padSizeMax = GetPrivateProfileIntW(L"Settings", L"PadMax", 500, g_iniFilePath);

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

    // --- 新增：读取订阅地址 (处理宽字符转 UTF-8) ---
    wchar_t wSubUrl[512] = {0};
    GetPrivateProfileStringW(L"Settings", L"SubUrl", L"", wSubUrl, 512, g_iniFilePath);
    if (wcslen(wSubUrl) > 0) {
        WideCharToMultiByte(CP_UTF8, 0, wSubUrl, -1, g_subUrl, 512, NULL, NULL);
    } else {
        g_subUrl[0] = '\0';
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

    // --- 新增：保存订阅地址 ---
    wchar_t wSubUrl[512] = {0};
    MultiByteToWideChar(CP_UTF8, 0, g_subUrl, -1, wSubUrl, 512);
    WritePrivateProfileStringW(L"Settings", L"SubUrl", wSubUrl, g_iniFilePath);
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

void ParseNodeConfigToGlobal(cJSON *node) {
    if (!node) return;
    memset(&g_proxyConfig, 0, sizeof(g_proxyConfig));
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

char* GetUniqueTagName(cJSON* outbounds, const char* type, const char* base_name) {
    static char final_tag[512];
    char candidate[450];
    const char* safe_name = (base_name && strlen(base_name) > 0) ? base_name : "Unnamed";
    char prefix[64]; snprintf(prefix, sizeof(prefix), "%s-", type);
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
    BOOL ret = WriteBufferToFile(CONFIG_FILE, out);
    free(out); cJSON_Delete(root);
    return ret;
}

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

int ImportFromClipboard() {
    char* text = GetClipboardText(); 
    if (!text) return 0;
    int successCount = 0;
    char* context = NULL;
    char* token = strtok_s(text, " \r\n\t,", &context);
    while (token != NULL) {
        TrimString(token);
        if (strlen(token) > 0) {
            cJSON* node = NULL;
            if (_strnicmp(token, "socks://", 8) == 0) node = ParseSocks(token);
            else if (_strnicmp(token, "vmess://", 8) == 0) node = ParseVmess(token);
            else if (_strnicmp(token, "vless://", 8) == 0) node = ParseVlessOrTrojan(token);
            else if (_strnicmp(token, "trojan://", 9) == 0) node = ParseVlessOrTrojan(token);
            else if (_strnicmp(token, "ss://", 5) == 0) node = ParseShadowsocks(token);
            if (node) {
                if (AddNodeToConfig(node)) successCount++;
            }
        }
        token = strtok_s(NULL, " \r\n\t,", &context);
    }
    free(text);
    return successCount;

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

// --- 新增：订阅管理核心逻辑 ---

// 清空现有节点
void ClearAllNodes() {
    char* buffer = NULL; long size = 0;
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) return;
    cJSON* root = cJSON_Parse(buffer); free(buffer);
    if (!root) return;
    
    // 移除所有出站节点
    cJSON_DeleteItemFromObject(root, "outbounds");
    // 重建空数组
    cJSON_AddItemToObject(root, "outbounds", cJSON_CreateArray());
    
    char* out = cJSON_Print(root);
    WriteBufferToFile(CONFIG_FILE, out);
    free(out); cJSON_Delete(root);
}

// 更新订阅主函数
// 1. 下载 -> 2. 解码 -> 3. 清空旧节点 -> 4. 逐行解析并添加 -> 5. 刷新
int UpdateNodesFromSubscription(const char* url) {
    if (!url || strlen(url) < 4) return -1;
    
    log_msg("[Sub] Downloading from: %s", url);
    char* data = Utils_HttpGet(url);
    if (!data) {
        log_msg("[Sub] Download failed.");
        return -1;
    }

    // 订阅内容通常是 Base64 编码的列表
    size_t decLen = 0;
    unsigned char* decoded = Base64Decode(data, &decLen);
    
    // 如果解码失败，可能返回的就是明文，或者是不支持的格式
    // 尝试使用解码后的内容，如果解码为空，则使用原始内容
    char* sourceText = NULL;
    if (decoded) {
        sourceText = (char*)decoded;
    } else {
        sourceText = strdup(data); 
    }
    free(data); // 释放原始下载数据

    if (!sourceText) return -1;

    // 清空旧节点 (覆盖模式)
    ClearAllNodes();

    int successCount = 0;
    char* context = NULL;
    // 按行拆分，支持 \r \n 和空格
    char* line = strtok_s(sourceText, "\r\n ", &context);
    
    while (line != NULL) {
        TrimString(line);
        if (strlen(line) > 0) {
            cJSON* node = NULL;
            // 尝试各种协议解析
            if (_strnicmp(line, "vmess://", 8) == 0) node = ParseVmess(line);
            else if (_strnicmp(line, "ss://", 5) == 0) node = ParseShadowsocks(line);
            else if (_strnicmp(line, "vless://", 8) == 0) node = ParseVlessOrTrojan(line);
            else if (_strnicmp(line, "trojan://", 9) == 0) node = ParseVlessOrTrojan(line);
            else if (_strnicmp(line, "socks://", 8) == 0) node = ParseSocks(line);

            if (node) {
                if (AddNodeToConfig(node)) successCount++;
                else cJSON_Delete(node); // 添加失败则释放
            }
        }
        line = strtok_s(NULL, "\r\n ", &context);
    }
    
    free(sourceText);
    ParseTags(); // 刷新内存中的标签列表，确保 GUI 能读到新节点
    return successCount;
}

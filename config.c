#include "config.h"
#include "common.h"
#include "utils.h"
#include "cJSON.h"
#include "proxy.h" // [Fix] 包含 proxy.h 以修复 StopProxyCore/StartProxyCore 隐式声明
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// --------------------------------------------------------------------------
// 辅助函数
// --------------------------------------------------------------------------

static void parse_node_tag(const char* url, char* tag_out, int tag_max) {
    if (!url || !tag_out) return;
    tag_out[0] = 0;
    
    const char* p = strchr(url, '#');
    if (p) {
        p++;
        char temp[512];
        strncpy(temp, p, 511); temp[511] = 0;
        UrlDecode(tag_out, temp);
        return;
    }
    
    p = strstr(url, "ps=");
    if (p) {
        p += 3;
        const char* end = strchr(p, '&');
        int len = end ? (int)(end - p) : (int)strlen(p);
        if (len > 0 && len < tag_max) {
            char temp[512];
            strncpy(temp, p, len); temp[len] = 0;
            UrlDecode(tag_out, temp);
        }
    }
}

// --------------------------------------------------------------------------
// 核心：节点切换逻辑
// --------------------------------------------------------------------------

void SwitchNode(const wchar_t* tag) {
    if (!tag) return;
    
    EnterCriticalSection(&g_configLock);
    wcsncpy(currentNode, tag, 63); currentNode[63] = 0;
    
    char* buffer = NULL; long size = 0;
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) {
        LeaveCriticalSection(&g_configLock);
        log_msg("[Config] SwitchNode: Read failed");
        return;
    }
    
    cJSON* root = cJSON_Parse(buffer);
    free(buffer);
    if (!root) {
        LeaveCriticalSection(&g_configLock);
        log_msg("[Config] SwitchNode: JSON parse failed");
        return;
    }
    
    char tagUtf8[256];
    WideCharToMultiByte(CP_UTF8, 0, tag, -1, tagUtf8, 256, NULL, NULL);
    
    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    cJSON* targetNode = NULL;
    cJSON* item = NULL;
    
    cJSON_ArrayForEach(item, outbounds) {
        cJSON* t = cJSON_GetObjectItem(item, "tag");
        if (t && strcmp(t->valuestring, tagUtf8) == 0) {
            targetNode = item;
            break;
        }
    }
    
    if (targetNode) {
        cJSON_DetachItemViaPointer(outbounds, targetNode);
        cJSON_InsertItemInArray(outbounds, 0, targetNode);
        
        memset(&g_proxyConfig, 0, sizeof(g_proxyConfig));
        
        cJSON* srv = cJSON_GetObjectItem(targetNode, "server");
        if (srv && srv->valuestring) strncpy(g_proxyConfig.host, srv->valuestring, 255);
        
        cJSON* prt = cJSON_GetObjectItem(targetNode, "server_port");
        if (prt) g_proxyConfig.port = prt->valueint;
        
        cJSON* type = cJSON_GetObjectItem(targetNode, "type");
        if (type && type->valuestring) strncpy(g_proxyConfig.type, type->valuestring, 31);
        
        cJSON* user = cJSON_GetObjectItem(targetNode, "username"); 
        if(!user) user = cJSON_GetObjectItem(targetNode, "uuid");  
        if (user && user->valuestring) strncpy(g_proxyConfig.user, user->valuestring, 127);
        
        cJSON* pass = cJSON_GetObjectItem(targetNode, "password");
        if (pass && pass->valuestring) strncpy(g_proxyConfig.pass, pass->valuestring, 127);
        
        cJSON* tls = cJSON_GetObjectItem(targetNode, "tls");
        if (tls) {
            cJSON* sni = cJSON_GetObjectItem(tls, "server_name");
            if (sni && sni->valuestring) strncpy(g_proxyConfig.sni, sni->valuestring, 255);
        }
        
        cJSON* trans = cJSON_GetObjectItem(targetNode, "transport");
        if (trans) {
            cJSON* ws = cJSON_GetObjectItem(trans, "wsSettings");
            if (ws) {
                cJSON* path = cJSON_GetObjectItem(ws, "path");
                if (path && path->valuestring) strncpy(g_proxyConfig.path, path->valuestring, 255);
                
                if (strlen(g_proxyConfig.sni) == 0) {
                    cJSON* headers = cJSON_GetObjectItem(ws, "headers");
                    if (headers) {
                        cJSON* host = cJSON_GetObjectItem(headers, "Host");
                        if (host && host->valuestring) strncpy(g_proxyConfig.sni, host->valuestring, 255);
                    }
                }
            }
        }

        char* out = cJSON_Print(root);
        if (out) {
            WriteBufferToFile(CONFIG_FILE, out);
            free(out);
        }
        log_msg("[Config] Switched to node: %s", tagUtf8);
    } else {
        log_msg("[Config] Node not found: %s", tagUtf8);
    }
    
    cJSON_Delete(root);
    LeaveCriticalSection(&g_configLock);
    
    if (g_proxyRunning) {
        StopProxyCore();
        StartProxyCore();
    }
}

void DeleteNode(const wchar_t* tag) {
    if (!tag) return;
    EnterCriticalSection(&g_configLock);
    
    char* buffer = NULL; long size = 0;
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) {
        LeaveCriticalSection(&g_configLock);
        return;
    }
    
    cJSON* root = cJSON_Parse(buffer);
    free(buffer);
    if (!root) {
        LeaveCriticalSection(&g_configLock);
        return;
    }
    
    char tagUtf8[256];
    WideCharToMultiByte(CP_UTF8, 0, tag, -1, tagUtf8, 256, NULL, NULL);
    
    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    int idx_to_del = -1;
    int idx = 0;
    cJSON* item = NULL;
    
    cJSON_ArrayForEach(item, outbounds) {
        cJSON* t = cJSON_GetObjectItem(item, "tag");
        if (t && strcmp(t->valuestring, tagUtf8) == 0) {
            idx_to_del = idx;
            break;
        }
        idx++;
    }
    
    if (idx_to_del != -1) {
        cJSON_DeleteItemFromArray(outbounds, idx_to_del);
        char* out = cJSON_Print(root);
        if (out) {
            WriteBufferToFile(CONFIG_FILE, out);
            free(out);
        }
    }
    
    cJSON_Delete(root);
    LeaveCriticalSection(&g_configLock);
}

// --------------------------------------------------------------------------
// 核心：协议解析 (全协议支持)
// --------------------------------------------------------------------------

static void ParseSS(const char* body, const char* fragment, cJSON* node) {
    char method[64] = {0};
    char password[128] = {0};
    char host[256] = {0};
    int port = 0;
    
    const char* at = strrchr(body, '@');
    if (at) {
        int user_len = (int)(at - body);
        char user_part[256];
        if (user_len > 255) user_len = 255;
        strncpy(user_part, body, user_len); user_part[user_len] = 0;
        
        char* colon = strchr(user_part, ':');
        if (colon) {
            *colon = 0;
            strncpy(method, user_part, 63);
            strncpy(password, colon + 1, 127);
        }
        
        const char* host_part = at + 1;
        const char* p_colon = strrchr(host_part, ':');
        if (p_colon) {
            int h_len = (int)(p_colon - host_part);
            if (h_len > 255) h_len = 255;
            strncpy(host, host_part, h_len);
            port = atoi(p_colon + 1);
        }
    } else {
        return;
    }
    
    cJSON_AddStringToObject(node, "type", "shadowsocks");
    cJSON_AddStringToObject(node, "server", host);
    cJSON_AddNumberToObject(node, "server_port", port);
    cJSON_AddStringToObject(node, "method", method);
    cJSON_AddStringToObject(node, "password", password);
    
    char tag[256] = {0};
    if (fragment && strlen(fragment) > 0) UrlDecode(tag, fragment);
    else snprintf(tag, 256, "ss-%s:%d", host, port);
    cJSON_AddStringToObject(node, "tag", tag);
    
    cJSON_AddStringToObject(node, "network", "tcp"); 
}

static void ParseLinkAndAdd(const char* link, cJSON* outbounds) {
    if (!link || strlen(link) < 5) return;
    
    char scheme[16] = {0};
    const char* p_colon = strstr(link, "://");
    if (!p_colon) return;
    
    int scheme_len = (int)(p_colon - link);
    if (scheme_len > 15) scheme_len = 15;
    strncpy(scheme, link, scheme_len);
    
    cJSON* node = cJSON_CreateObject();
    
    if (_stricmp(scheme, "vmess") == 0) {
        const char* b64 = p_colon + 3;
        size_t decoded_len = 0;
        unsigned char* decoded = Base64Decode(b64, &decoded_len);
        if (decoded) {
            cJSON* v = cJSON_Parse((char*)decoded);
            free(decoded);
            if (v) {
                cJSON* ps = cJSON_GetObjectItem(v, "ps");
                cJSON* add = cJSON_GetObjectItem(v, "add");
                cJSON* port = cJSON_GetObjectItem(v, "port");
                cJSON* id = cJSON_GetObjectItem(v, "id");
                
                cJSON* aid = cJSON_GetObjectItem(v, "aid");
                cJSON* net = cJSON_GetObjectItem(v, "net");
                cJSON* type = cJSON_GetObjectItem(v, "type"); 
                cJSON* host = cJSON_GetObjectItem(v, "host");
                cJSON* path = cJSON_GetObjectItem(v, "path");
                cJSON* tls = cJSON_GetObjectItem(v, "tls");
                cJSON* scy = cJSON_GetObjectItem(v, "scy"); 
                cJSON* sni = cJSON_GetObjectItem(v, "sni");
                cJSON* alpn = cJSON_GetObjectItem(v, "alpn");
                
                if (ps && add && id) {
                    cJSON_AddStringToObject(node, "tag", ps->valuestring);
                    cJSON_AddStringToObject(node, "type", "vmess");
                    cJSON_AddStringToObject(node, "server", add->valuestring);
                    
                    if (cJSON_IsNumber(port)) cJSON_AddNumberToObject(node, "server_port", port->valueint);
                    else if (cJSON_IsString(port)) cJSON_AddNumberToObject(node, "server_port", atoi(port->valuestring));
                    else cJSON_AddNumberToObject(node, "server_port", 443);
                    
                    cJSON_AddStringToObject(node, "uuid", id->valuestring);
                    if (aid) cJSON_AddNumberToObject(node, "alterId", cJSON_IsNumber(aid) ? aid->valueint : atoi(aid->valuestring));
                    else cJSON_AddNumberToObject(node, "alterId", 0);
                    
                    if (scy && scy->valuestring && strlen(scy->valuestring) > 0) 
                        cJSON_AddStringToObject(node, "security", scy->valuestring);
                    else 
                        cJSON_AddStringToObject(node, "security", "auto");

                    char netStr[32] = "tcp";
                    if (net && net->valuestring) strncpy(netStr, net->valuestring, 31);
                    
                    if (strcmp(netStr, "ws") == 0) {
                        cJSON* trans = cJSON_CreateObject();
                        cJSON_AddStringToObject(trans, "type", "ws");
                        cJSON* wsSettings = cJSON_CreateObject();
                        
                        if (path && path->valuestring && strlen(path->valuestring)>0) 
                            cJSON_AddStringToObject(wsSettings, "path", path->valuestring);
                            
                        if (host && host->valuestring && strlen(host->valuestring)>0) {
                            cJSON* headers = cJSON_CreateObject();
                            cJSON_AddStringToObject(headers, "Host", host->valuestring);
                            cJSON_AddItemToObject(wsSettings, "headers", headers);
                        }
                        cJSON_AddItemToObject(trans, "wsSettings", wsSettings);
                        cJSON_AddItemToObject(node, "transport", trans);
                    } else if (strcmp(netStr, "grpc") == 0) {
                        cJSON* trans = cJSON_CreateObject();
                        cJSON_AddStringToObject(trans, "type", "grpc");
                        cJSON* grpc = cJSON_CreateObject();
                        if (path && path->valuestring) cJSON_AddStringToObject(grpc, "serviceName", path->valuestring);
                        cJSON_AddItemToObject(trans, "grpcSettings", grpc);
                        cJSON_AddItemToObject(node, "transport", trans);
                    } else {
                        cJSON_AddStringToObject(node, "network", "tcp");
                        if (type && strcmp(type->valuestring, "http") == 0) {
                             cJSON* trans = cJSON_CreateObject();
                             cJSON_AddStringToObject(trans, "type", "tcp");
                             cJSON* tcp = cJSON_CreateObject();
                             cJSON* header = cJSON_CreateObject();
                             cJSON_AddStringToObject(header, "type", "http");
                             cJSON_AddItemToObject(tcp, "header", header);
                             cJSON_AddItemToObject(trans, "tcpSettings", tcp);
                             cJSON_AddItemToObject(node, "transport", trans);
                        }
                    }
                    
                    if ((tls && strcmp(tls->valuestring, "tls") == 0) || (port && port->valueint == 443)) {
                        cJSON* tObj = cJSON_CreateObject();
                        cJSON_AddBoolToObject(tObj, "enabled", cJSON_True);
                        
                        const char* sniVal = (sni && sni->valuestring) ? sni->valuestring : 
                                            ((host && host->valuestring) ? host->valuestring : add->valuestring);
                        cJSON_AddStringToObject(tObj, "server_name", sniVal);
                        
                        if (alpn && alpn->valuestring) {
                             cJSON* alpnArr = cJSON_CreateArray();
                             cJSON_AddItemToArray(alpnArr, cJSON_CreateString(alpn->valuestring));
                             cJSON_AddItemToObject(tObj, "alpn", alpnArr);
                        }
                        cJSON_AddItemToObject(node, "tls", tObj);
                    }
                    
                    cJSON_AddItemToArray(outbounds, node);
                } else cJSON_Delete(node);
                cJSON_Delete(v);
            } else cJSON_Delete(node);
        } else cJSON_Delete(node);
    }
    else if (_stricmp(scheme, "vless") == 0 || _stricmp(scheme, "trojan") == 0) {
        const char* body = p_colon + 3;
        const char* at = strchr(body, '@');
        const char* last_colon = strrchr(body, ':');
        const char* q = strchr(body, '?');
        const char* h = strchr(body, '#');
        
        if (at && last_colon && last_colon > at) {
            char user[128], host[256], tag[256] = {0};
            int port = 443;
            
            int uLen = (int)(at - body);
            if (uLen > 127) uLen = 127;
            strncpy(user, body, uLen); user[uLen] = 0;
            
            const char* host_start = at + 1;
            int hLen = (int)(last_colon - host_start);
            if (hLen > 255) hLen = 255;
            strncpy(host, host_start, hLen); host[hLen] = 0;
            
            port = atoi(last_colon + 1);
            
            parse_node_tag(link, tag, 256);
            if (strlen(tag) == 0) snprintf(tag, 256, "%s-%s:%d", scheme, host, port);
            
            cJSON_AddStringToObject(node, "tag", tag);
            cJSON_AddStringToObject(node, "type", scheme);
            cJSON_AddStringToObject(node, "server", host);
            cJSON_AddNumberToObject(node, "server_port", port);
            
            if (_stricmp(scheme, "trojan") == 0) cJSON_AddStringToObject(node, "password", user);
            else cJSON_AddStringToObject(node, "uuid", user);
            
            if (q) {
                char* type = GetQueryParam(q, "type");
                char* security = GetQueryParam(q, "security"); 
                char* sni = GetQueryParam(q, "sni");
                char* path = GetQueryParam(q, "path");
                char* hostParam = GetQueryParam(q, "host");
                char* flow = GetQueryParam(q, "flow"); 
                char* fp = GetQueryParam(q, "fp");
                char* alpn = GetQueryParam(q, "alpn");
                char* serviceName = GetQueryParam(q, "serviceName");
                
                if (flow && strlen(flow) > 0) cJSON_AddStringToObject(node, "flow", flow);

                if (type && strcmp(type, "ws") == 0) {
                     cJSON* trans = cJSON_CreateObject();
                     cJSON_AddStringToObject(trans, "type", "ws");
                     cJSON* ws = cJSON_CreateObject();
                     if (path) {
                         char decoded_path[256]; UrlDecode(decoded_path, path);
                         cJSON_AddStringToObject(ws, "path", decoded_path);
                     }
                     if (hostParam) {
                         cJSON* hObj = cJSON_CreateObject();
                         cJSON_AddStringToObject(hObj, "Host", hostParam);
                         cJSON_AddItemToObject(ws, "headers", hObj);
                     }
                     cJSON_AddItemToObject(trans, "wsSettings", ws);
                     cJSON_AddItemToObject(node, "transport", trans);
                } else if (type && strcmp(type, "grpc") == 0) {
                     cJSON* trans = cJSON_CreateObject();
                     cJSON_AddStringToObject(trans, "type", "grpc");
                     cJSON* grpc = cJSON_CreateObject();
                     if (serviceName) cJSON_AddStringToObject(grpc, "serviceName", serviceName);
                     cJSON_AddItemToObject(trans, "grpcSettings", grpc);
                     cJSON_AddItemToObject(node, "transport", trans);
                } else {
                     cJSON_AddStringToObject(node, "network", "tcp");
                }
                
                if ((security && strcmp(security, "tls") == 0) || (port == 443)) {
                    cJSON* tObj = cJSON_CreateObject();
                    cJSON_AddBoolToObject(tObj, "enabled", cJSON_True);
                    if (sni) cJSON_AddStringToObject(tObj, "server_name", sni);
                    else if (hostParam) cJSON_AddStringToObject(tObj, "server_name", hostParam);
                    else cJSON_AddStringToObject(tObj, "server_name", host);
                    
                    if (fp) cJSON_AddStringToObject(tObj, "fingerprint", fp);
                    if (alpn) {
                         cJSON* alpnArr = cJSON_CreateArray();
                         cJSON_AddItemToArray(alpnArr, cJSON_CreateString(alpn));
                         cJSON_AddItemToObject(tObj, "alpn", alpnArr);
                    }
                    cJSON_AddItemToObject(node, "tls", tObj);
                }
                
                if(type) free(type); if(security) free(security); if(sni) free(sni); 
                if(path) free(path); if(hostParam) free(hostParam); if(flow) free(flow);
                if(fp) free(fp); if(alpn) free(alpn); if(serviceName) free(serviceName);
            } else {
                cJSON_AddStringToObject(node, "network", "tcp");
            }
            cJSON_AddItemToArray(outbounds, node);
        } else cJSON_Delete(node);
    } 
    else if (_stricmp(scheme, "ss") == 0) {
        const char* body = p_colon + 3;
        const char* hash = strchr(body, '#');
        char fragment[256] = {0};
        if (hash) {
            strncpy(fragment, hash + 1, 255);
        }

        if (strchr(body, '@')) {
            char temp_body[1024];
            int len = hash ? (int)(hash - body) : (int)strlen(body);
            if (len > 1023) len = 1023;
            strncpy(temp_body, body, len); temp_body[len] = 0;
            ParseSS(temp_body, fragment, node);
            cJSON_AddItemToArray(outbounds, node);
        } else {
            int b64_len = hash ? (int)(hash - body) : (int)strlen(body);
            char b64_str[1024];
            if (b64_len > 1023) b64_len = 1023;
            strncpy(b64_str, body, b64_len); b64_str[b64_len] = 0;
            
            size_t decoded_len = 0;
            unsigned char* decoded = Base64Decode(b64_str, &decoded_len);
            if (decoded) {
                char decoded_str[1024];
                if (decoded_len > 1023) decoded_len = 1023;
                memcpy(decoded_str, decoded, decoded_len); decoded_str[decoded_len] = 0;
                free(decoded);
                ParseSS(decoded_str, fragment, node);
                cJSON_AddItemToArray(outbounds, node);
            } else {
                cJSON_Delete(node);
            }
        }
    }
    else if (_stricmp(scheme, "socks") == 0 || _stricmp(scheme, "http") == 0) {
         const char* body = p_colon + 3;
         const char* at = strchr(body, '@');
         const char* last_colon = strrchr(body, ':');
         const char* hash = strchr(body, '#');
         
         if (at && last_colon && last_colon > at) {
             char user_pass[128], host[256], tag[256]={0};
             int port = 1080;
             
             int upLen = (int)(at - body);
             if (upLen > 127) upLen = 127;
             strncpy(user_pass, body, upLen); user_pass[upLen] = 0;
             
             char* colon = strchr(user_pass, ':');
             if (colon) {
                 *colon = 0;
                 cJSON_AddStringToObject(node, "username", user_pass);
                 cJSON_AddStringToObject(node, "password", colon+1);
             }
             
             const char* hStart = at + 1;
             int hLen = (int)(last_colon - hStart);
             if (hLen > 255) hLen = 255;
             strncpy(host, hStart, hLen); host[hLen] = 0;
             
             port = atoi(last_colon + 1);
             
             if (hash) UrlDecode(tag, hash+1);
             else snprintf(tag, 256, "%s-%s", scheme, host);
             
             cJSON_AddStringToObject(node, "tag", tag);
             cJSON_AddStringToObject(node, "type", scheme);
             cJSON_AddStringToObject(node, "server", host);
             cJSON_AddNumberToObject(node, "server_port", port);
             cJSON_AddItemToArray(outbounds, node);
         } else cJSON_Delete(node);
    }
    else {
        cJSON_Delete(node);
    }
}

int UpdateAllSubscriptions(BOOL forceLog) {
    EnterCriticalSection(&g_configLock);
    int subCount = g_subCount;
    Subscription subsCopy[MAX_SUBS];
    for(int i=0; i<subCount; i++) subsCopy[i] = g_subs[i];
    LeaveCriticalSection(&g_configLock);

    if (subCount == 0) return 0;

    int new_nodes_count = 0;
    
    char* buffer = NULL; long size = 0;
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) {
        if(forceLog) log_msg("[Sub] Failed to read config file");
        return 0;
    }
    cJSON* root = cJSON_Parse(buffer); free(buffer);
    if (!root) return 0;
    
    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    if (!outbounds) { cJSON_Delete(root); return 0; }
    
    for (int i = 0; i < subCount; i++) {
        if (!subsCopy[i].enabled) continue;
        
        if (forceLog) log_msg("[Sub] Fetching: %s", subsCopy[i].url);
        
        char* resp = Utils_HttpGet(subsCopy[i].url);
        if (!resp) {
            if (forceLog) log_msg("[Sub] Network error: %s", subsCopy[i].url);
            continue;
        }
        
        size_t b64_len = 0;
        unsigned char* decoded = Base64Decode(resp, &b64_len);
        
        char* raw_list = NULL;
        if (decoded && b64_len > 0) {
            raw_list = (char*)decoded;
        } else {
            raw_list = SafeStrDup(resp, strlen(resp));
        }
        free(resp);
        
        if (!raw_list) continue;
        
        char* ctx = NULL;
        char* line = strtok_s(raw_list, "\r\n", &ctx);
        int count_in_sub = 0;
        
        while (line) {
            TrimString(line);
            if (strlen(line) > 0) {
                ParseLinkAndAdd(line, outbounds);
                new_nodes_count++;
                count_in_sub++;
            }
            line = strtok_s(NULL, "\r\n", &ctx);
        }
        
        free(raw_list);
        if (forceLog) log_msg("[Sub] Added %d nodes from sub %d", count_in_sub, i+1);
    }
    
    if (new_nodes_count > 0) {
        char* out = cJSON_Print(root);
        if (out) {
            WriteBufferToFile(CONFIG_FILE, out);
            free(out);
        }
        
        EnterCriticalSection(&g_configLock);
        g_lastUpdateTime = (long long)time(NULL);
        LeaveCriticalSection(&g_configLock);
        
        if (forceLog) log_msg("[Sub] Update complete. Total added: %d", new_nodes_count);
    }
    
    cJSON_Delete(root);
    return new_nodes_count;
}

// --------------------------------------------------------------------------
// 核心：节点列表缓存
// --------------------------------------------------------------------------

void ParseTags() {
    EnterCriticalSection(&g_configLock);
    
    if (nodeTags) {
        for(int i=0; i<nodeCount; i++) free(nodeTags[i]);
        free(nodeTags); nodeTags = NULL;
    }
    nodeCount = 0;
    
    char* buffer = NULL; long size = 0;
    if (ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) {
        cJSON* root = cJSON_Parse(buffer);
        free(buffer);
        if (root) {
            cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
            int count = cJSON_GetArraySize(outbounds);
            if (count > 0) {
                nodeTags = (wchar_t**)malloc(sizeof(wchar_t*) * count);
                for (int i=0; i<count; i++) {
                    cJSON* item = cJSON_GetArrayItem(outbounds, i);
                    cJSON* tag = cJSON_GetObjectItem(item, "tag");
                    if (tag && tag->valuestring) {
                        int len = MultiByteToWideChar(CP_UTF8, 0, tag->valuestring, -1, NULL, 0);
                        nodeTags[nodeCount] = (wchar_t*)malloc(len * sizeof(wchar_t));
                        MultiByteToWideChar(CP_UTF8, 0, tag->valuestring, -1, nodeTags[nodeCount], len);
                        nodeCount++;
                    }
                }
            }
            cJSON_Delete(root);
        }
    }
    LeaveCriticalSection(&g_configLock);
}

int ImportFromClipboard() {
    char* text = GetClipboardText();
    if (!text) return 0;
    
    int count = 0;
    char* buffer = NULL; long size = 0;
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) { free(text); return 0; }
    
    cJSON* root = cJSON_Parse(buffer); free(buffer);
    if (!root) { free(text); return 0; }
    
    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    
    char* ctx = NULL;
    char* line = strtok_s(text, "\r\n", &ctx);
    while (line) {
        TrimString(line);
        if (strlen(line) > 10) {
            int pre_count = cJSON_GetArraySize(outbounds);
            ParseLinkAndAdd(line, outbounds);
            int post_count = cJSON_GetArraySize(outbounds);
            if (post_count > pre_count) count++;
        }
        line = strtok_s(NULL, "\r\n", &ctx);
    }
    
    if (count > 0) {
        char* out = cJSON_Print(root);
        if (out) { WriteBufferToFile(CONFIG_FILE, out); free(out); }
    }
    
    cJSON_Delete(root);
    free(text);
    return count;
}

// --------------------------------------------------------------------------
// 初始化与 INI 读写
// --------------------------------------------------------------------------

void InitGlobalLocks() {
    InitializeCriticalSection(&g_configLock);
}

void DeleteGlobalLocks() {
    DeleteCriticalSection(&g_configLock);
}

void LoadSettings() {
    g_localPort = GetPrivateProfileIntW(L"Config", L"LocalPort", 10809, g_iniFilePath);
    g_hideTrayStart = GetPrivateProfileIntW(L"Config", L"HideTray", 0, g_iniFilePath);
    g_hotkeyModifiers = GetPrivateProfileIntW(L"Config", L"HotkeyMod", MOD_CONTROL | MOD_ALT, g_iniFilePath);
    g_hotkeyVk = GetPrivateProfileIntW(L"Config", L"HotkeyVk", 'H', g_iniFilePath);
    
    g_enableChromeCiphers = GetPrivateProfileIntW(L"Security", L"ChromeCiphers", 1, g_iniFilePath);
    g_enableALPN = GetPrivateProfileIntW(L"Security", L"ALPN", 1, g_iniFilePath);
    g_enableFragment = GetPrivateProfileIntW(L"Security", L"Fragment", 0, g_iniFilePath);
    g_fragSizeMin = GetPrivateProfileIntW(L"Security", L"FragMin", 100, g_iniFilePath);
    g_fragSizeMax = GetPrivateProfileIntW(L"Security", L"FragMax", 500, g_iniFilePath);
    g_fragDelayMs = GetPrivateProfileIntW(L"Security", L"FragDelay", 10, g_iniFilePath);
    g_enablePadding = GetPrivateProfileIntW(L"Security", L"Padding", 0, g_iniFilePath);
    g_padSizeMin = GetPrivateProfileIntW(L"Security", L"PadMin", 100, g_iniFilePath);
    g_padSizeMax = GetPrivateProfileIntW(L"Security", L"PadMax", 1000, g_iniFilePath);
    
    g_enableECH = GetPrivateProfileIntW(L"ECH", L"Enable", 0, g_iniFilePath);
    GetPrivateProfileStringA("ECH", "Server", "https://1.1.1.1/dns-query", g_echConfigServer, 256, "set.ini");
    GetPrivateProfileStringA("ECH", "PublicName", "cloudflare-ech.com", g_echPublicName, 256, "set.ini");

    g_uaPlatformIndex = GetPrivateProfileIntW(L"Network", L"UAIndex", 0, g_iniFilePath);
    GetPrivateProfileStringA("Network", "UserAgent", UA_TEMPLATES[0], g_userAgentStr, 512, "set.ini");

    g_subCount = GetPrivateProfileIntW(L"Subs", L"Count", 0, g_iniFilePath);
    if (g_subCount > MAX_SUBS) g_subCount = MAX_SUBS;
    for(int i=0; i<g_subCount; i++) {
        // [Fix] 使用 Wide API 读取 URL 并转换为 ANSI
        wchar_t wKey[32]; swprintf(wKey, 32, L"Url_%d", i);
        wchar_t wUrl[512] = {0};
        
        GetPrivateProfileStringW(L"Subs", wKey, L"", wUrl, 512, g_iniFilePath);
        if (wcslen(wUrl) > 0) {
            WideCharToMultiByte(CP_UTF8, 0, wUrl, -1, g_subs[i].url, 512, NULL, NULL);
        } else {
             // 兼容旧版 ANSI 读取
             GetPrivateProfileStringA("Subs", "Url", "", g_subs[i].url, 512, "set.ini");
        }
        
        swprintf(wKey, 32, L"En_%d", i);
        g_subs[i].enabled = GetPrivateProfileIntW(L"Subs", wKey, 1, g_iniFilePath);
    }
    
    g_subUpdateMode = GetPrivateProfileIntW(L"Subs", L"UpdateMode", UPDATE_MODE_DAILY, g_iniFilePath);
    g_subUpdateInterval = GetPrivateProfileIntW(L"Subs", L"UpdateInterval", 24, g_iniFilePath);
    
    // [Fix] 读取 LastTime (LongLong as String)
    wchar_t wTimeBuf[64];
    GetPrivateProfileStringW(L"Subs", L"LastTime", L"0", wTimeBuf, 64, g_iniFilePath);
    g_lastUpdateTime = _wtoi64(wTimeBuf);
}

void SaveSettings() {
    wchar_t buf[64];
    swprintf(buf, 64, L"%d", g_localPort); WritePrivateProfileStringW(L"Config", L"LocalPort", buf, g_iniFilePath);
    swprintf(buf, 64, L"%d", g_hideTrayStart); WritePrivateProfileStringW(L"Config", L"HideTray", buf, g_iniFilePath);
    swprintf(buf, 64, L"%d", g_hotkeyModifiers); WritePrivateProfileStringW(L"Config", L"HotkeyMod", buf, g_iniFilePath);
    swprintf(buf, 64, L"%d", g_hotkeyVk); WritePrivateProfileStringW(L"Config", L"HotkeyVk", buf, g_iniFilePath);

    WritePrivateProfileStringW(L"Security", L"ChromeCiphers", g_enableChromeCiphers ? L"1":L"0", g_iniFilePath);
    WritePrivateProfileStringW(L"Security", L"ALPN", g_enableALPN ? L"1":L"0", g_iniFilePath);
    WritePrivateProfileStringW(L"Security", L"Fragment", g_enableFragment ? L"1":L"0", g_iniFilePath);
    
    swprintf(buf, 64, L"%d", g_fragSizeMin); WritePrivateProfileStringW(L"Security", L"FragMin", buf, g_iniFilePath);
    swprintf(buf, 64, L"%d", g_fragSizeMax); WritePrivateProfileStringW(L"Security", L"FragMax", buf, g_iniFilePath);
    swprintf(buf, 64, L"%d", g_fragDelayMs); WritePrivateProfileStringW(L"Security", L"FragDelay", buf, g_iniFilePath);
    
    WritePrivateProfileStringW(L"Security", L"Padding", g_enablePadding ? L"1":L"0", g_iniFilePath);
    swprintf(buf, 64, L"%d", g_padSizeMin); WritePrivateProfileStringW(L"Security", L"PadMin", buf, g_iniFilePath);
    swprintf(buf, 64, L"%d", g_padSizeMax); WritePrivateProfileStringW(L"Security", L"PadMax", buf, g_iniFilePath);

    WritePrivateProfileStringW(L"ECH", L"Enable", g_enableECH ? L"1":L"0", g_iniFilePath);
    WritePrivateProfileStringA("ECH", "Server", g_echConfigServer, "set.ini");
    WritePrivateProfileStringA("ECH", "PublicName", g_echPublicName, "set.ini");

    swprintf(buf, 64, L"%d", g_uaPlatformIndex); WritePrivateProfileStringW(L"Network", L"UAIndex", buf, g_iniFilePath);
    WritePrivateProfileStringA("Network", "UserAgent", g_userAgentStr, "set.ini");

    swprintf(buf, 64, L"%d", g_subCount); WritePrivateProfileStringW(L"Subs", L"Count", buf, g_iniFilePath);
    for(int i=0; i<g_subCount; i++) {
        // [Fix] 写入 URL 使用 Wide API
        wchar_t wKey[32]; swprintf(wKey, 32, L"Url_%d", i);
        wchar_t wUrl[512];
        MultiByteToWideChar(CP_UTF8, 0, g_subs[i].url, -1, wUrl, 512);
        WritePrivateProfileStringW(L"Subs", wKey, wUrl, g_iniFilePath);
        
        swprintf(wKey, 32, L"En_%d", i);
        swprintf(buf, 64, L"%d", g_subs[i].enabled); 
        WritePrivateProfileStringW(L"Subs", wKey, buf, g_iniFilePath);
    }
    
    swprintf(buf, 64, L"%d", g_subUpdateMode); WritePrivateProfileStringW(L"Subs", L"UpdateMode", buf, g_iniFilePath);
    swprintf(buf, 64, L"%d", g_subUpdateInterval); WritePrivateProfileStringW(L"Subs", L"UpdateInterval", buf, g_iniFilePath);
    
    // [Fix] 写入 LastTime 使用 Wide API
    swprintf(buf, 64, L"%lld", g_lastUpdateTime);
    WritePrivateProfileStringW(L"Subs", L"LastTime", buf, g_iniFilePath);
}

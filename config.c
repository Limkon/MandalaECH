#include "config.h"
#include "common.h"
#include "utils.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// --------------------------------------------------------------------------
// 辅助函数
// --------------------------------------------------------------------------

// 提取 URL 中的 Fragment (#之后) 或 Query (?ps=) 作为节点备注
static void parse_node_tag(const char* url, char* tag_out, int tag_max) {
    if (!url || !tag_out) return;
    tag_out[0] = 0;
    
    // 1. 尝试取 Fragment (#)
    const char* p = strchr(url, '#');
    if (p) {
        p++;
        char temp[512];
        strncpy(temp, p, 511); temp[511] = 0;
        UrlDecode(tag_out, temp);
        return;
    }
    
    // 2. 尝试取 ps 参数 (常见于旧版链接)
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
    
    // 1. 读取配置文件
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
    
    // 2. 查找目标节点
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
    
    // 3. 激活节点：移至 outbounds[0] 并更新内存缓存
    if (targetNode) {
        // 调整顺序
        cJSON_DetachItemViaPointer(outbounds, targetNode);
        cJSON_InsertItemInArray(outbounds, 0, targetNode);
        
        // 提取配置到 g_proxyConfig (供 proxy.c 使用)
        memset(&g_proxyConfig, 0, sizeof(g_proxyConfig));
        
        cJSON* srv = cJSON_GetObjectItem(targetNode, "server");
        if (srv && srv->valuestring) strncpy(g_proxyConfig.host, srv->valuestring, 255);
        
        cJSON* prt = cJSON_GetObjectItem(targetNode, "server_port");
        if (prt) g_proxyConfig.port = prt->valueint;
        
        cJSON* type = cJSON_GetObjectItem(targetNode, "type");
        if (type && type->valuestring) strncpy(g_proxyConfig.type, type->valuestring, 31);
        
        // 用户名/UUID
        cJSON* user = cJSON_GetObjectItem(targetNode, "username"); // Socks/HTTP
        if(!user) user = cJSON_GetObjectItem(targetNode, "uuid");  // VMess/VLESS
        if (user && user->valuestring) strncpy(g_proxyConfig.user, user->valuestring, 127);
        
        // 密码
        cJSON* pass = cJSON_GetObjectItem(targetNode, "password");
        if (pass && pass->valuestring) strncpy(g_proxyConfig.pass, pass->valuestring, 127);
        
        // TLS SNI
        cJSON* tls = cJSON_GetObjectItem(targetNode, "tls");
        if (tls) {
            cJSON* sni = cJSON_GetObjectItem(tls, "server_name");
            if (sni && sni->valuestring) strncpy(g_proxyConfig.sni, sni->valuestring, 255);
        }
        
        // Transport Path (WS)
        cJSON* trans = cJSON_GetObjectItem(targetNode, "transport");
        if (trans) {
            cJSON* ws = cJSON_GetObjectItem(trans, "wsSettings");
            if (ws) {
                cJSON* path = cJSON_GetObjectItem(ws, "path");
                if (path && path->valuestring) strncpy(g_proxyConfig.path, path->valuestring, 255);
                
                // 兼容：如果 TLS SNI 为空，尝试从 Host header 获取
                if (strlen(g_proxyConfig.sni) == 0) {
                    cJSON* headers = cJSON_GetObjectItem(ws, "headers");
                    if (headers) {
                        cJSON* host = cJSON_GetObjectItem(headers, "Host");
                        if (host && host->valuestring) strncpy(g_proxyConfig.sni, host->valuestring, 255);
                    }
                }
            }
        }

        // 4. 原子保存配置
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
    
    // 重启代理核心
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

// 解析 SS 协议 (SIP002 & Legacy)
static void ParseSS(const char* body, const char* fragment, cJSON* node) {
    // 格式1 (SIP002): user:pass@host:port
    // 格式2 (Legacy): BASE64(method:pass@host:port) - 已由外层解码
    
    char method[64] = {0};
    char password[128] = {0};
    char host[256] = {0};
    int port = 0;
    
    const char* at = strrchr(body, '@');
    if (at) {
        // body = "method:pass@host:port"
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
        // 可能是旧版直接 Base64 包含所有信息，或者格式错误
        // 这里尝试处理 "method:pass:host:port" 这种非标准格式
        // 实际上标准 SS 必须有 @
        return;
    }
    
    // 构建 JSON
    cJSON_AddStringToObject(node, "type", "shadowsocks");
    cJSON_AddStringToObject(node, "server", host);
    cJSON_AddNumberToObject(node, "server_port", port);
    cJSON_AddStringToObject(node, "method", method);
    cJSON_AddStringToObject(node, "password", password);
    
    char tag[256] = {0};
    if (fragment && strlen(fragment) > 0) UrlDecode(tag, fragment);
    else snprintf(tag, 256, "ss-%s:%d", host, port);
    cJSON_AddStringToObject(node, "tag", tag);
    
    cJSON_AddStringToObject(node, "network", "tcp"); // 默认 TCP
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
    
    // ---------------- VMESS ----------------
    if (_stricmp(scheme, "vmess") == 0) {
        const char* b64 = p_colon + 3;
        size_t decoded_len = 0;
        unsigned char* decoded = Base64Decode(b64, &decoded_len);
        if (decoded) {
            cJSON* v = cJSON_Parse((char*)decoded);
            free(decoded);
            if (v) {
                // 必选字段
                cJSON* ps = cJSON_GetObjectItem(v, "ps");
                cJSON* add = cJSON_GetObjectItem(v, "add");
                cJSON* port = cJSON_GetObjectItem(v, "port");
                cJSON* id = cJSON_GetObjectItem(v, "id");
                
                // 可选/协议字段
                cJSON* aid = cJSON_GetObjectItem(v, "aid");
                cJSON* net = cJSON_GetObjectItem(v, "net");
                cJSON* type = cJSON_GetObjectItem(v, "type"); // header type
                cJSON* host = cJSON_GetObjectItem(v, "host");
                cJSON* path = cJSON_GetObjectItem(v, "path");
                cJSON* tls = cJSON_GetObjectItem(v, "tls");
                cJSON* scy = cJSON_GetObjectItem(v, "scy"); // security
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

                    // Transport
                    char netStr[32] = "tcp";
                    if (net && net->valuestring) strncpy(netStr, net->valuestring, 31);
                    
                    if (strcmp(netStr, "ws") == 0) {
                        cJSON* trans = cJSON_CreateObject();
                        cJSON_AddStringToObject(trans, "type", "ws");
                        cJSON* wsSettings = cJSON_CreateObject();
                        
                        if (path && path->valuestring && strlen(path->valuestring)>0) 
                            cJSON_AddStringToObject(wsSettings, "path", path->valuestring);
                            
                        // Headers / Host
                        if (host && host->valuestring && strlen(host->valuestring)>0) {
                            cJSON* headers = cJSON_CreateObject();
                            cJSON_AddStringToObject(headers, "Host", host->valuestring);
                            cJSON_AddItemToObject(wsSettings, "headers", headers);
                        }
                        cJSON_AddItemToObject(trans, "wsSettings", wsSettings);
                        cJSON_AddItemToObject(node, "transport", trans);
                    } else if (strcmp(netStr, "grpc") == 0) {
                        // 补充对 gRPC 的基本支持
                        cJSON* trans = cJSON_CreateObject();
                        cJSON_AddStringToObject(trans, "type", "grpc");
                        cJSON* grpc = cJSON_CreateObject();
                        if (path && path->valuestring) cJSON_AddStringToObject(grpc, "serviceName", path->valuestring);
                        cJSON_AddItemToObject(trans, "grpcSettings", grpc);
                        cJSON_AddItemToObject(node, "transport", trans);
                    } else {
                        cJSON_AddStringToObject(node, "network", "tcp");
                        // TCP HTTP Header (type=http)
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
                    
                    // TLS
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
                        // V2Ray Core 约定: 如果开启 TLS，外层 security 字段应设为 tls，或保留为 auto
                    }
                    
                    cJSON_AddItemToArray(outbounds, node);
                } else cJSON_Delete(node);
                cJSON_Delete(v);
            } else cJSON_Delete(node);
        } else cJSON_Delete(node);
    }
    // ---------------- VLESS / TROJAN ----------------
    else if (_stricmp(scheme, "vless") == 0 || _stricmp(scheme, "trojan") == 0) {
        const char* body = p_colon + 3;
        const char* at = strchr(body, '@');
        const char* last_colon = strrchr(body, ':');
        const char* q = strchr(body, '?');
        const char* h = strchr(body, '#');
        
        if (at && last_colon && last_colon > at) {
            char user[128], host[256], tag[256] = {0};
            int port = 443;
            
            // User
            int uLen = (int)(at - body);
            if (uLen > 127) uLen = 127;
            strncpy(user, body, uLen); user[uLen] = 0;
            
            // Host
            const char* host_start = at + 1;
            int hLen = (int)(last_colon - host_start);
            if (hLen > 255) hLen = 255;
            strncpy(host, host_start, hLen); host[hLen] = 0;
            
            // Port
            port = atoi(last_colon + 1);
            
            // Tag
            parse_node_tag(link, tag, 256);
            if (strlen(tag) == 0) snprintf(tag, 256, "%s-%s:%d", scheme, host, port);
            
            cJSON_AddStringToObject(node, "tag", tag);
            cJSON_AddStringToObject(node, "type", scheme);
            cJSON_AddStringToObject(node, "server", host);
            cJSON_AddNumberToObject(node, "server_port", port);
            
            if (_stricmp(scheme, "trojan") == 0) cJSON_AddStringToObject(node, "password", user);
            else cJSON_AddStringToObject(node, "uuid", user);
            
            // Query Params
            if (q) {
                char* type = GetQueryParam(q, "type");
                char* security = GetQueryParam(q, "security"); // tls, reality...
                char* sni = GetQueryParam(q, "sni");
                char* path = GetQueryParam(q, "path");
                char* hostParam = GetQueryParam(q, "host");
                char* flow = GetQueryParam(q, "flow"); // xtls-rprx-vision
                char* fp = GetQueryParam(q, "fp");
                char* alpn = GetQueryParam(q, "alpn");
                char* serviceName = GetQueryParam(q, "serviceName"); // grpc
                
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
                         // 简单处理逗号分隔
                         cJSON_AddItemToArray(alpnArr, cJSON_CreateString(alpn));
                         cJSON_AddItemToObject(tObj, "alpn", alpnArr);
                    }
                    cJSON_AddItemToObject(node, "tls", tObj);
                }
                
                if(type) free(type); if(security) free(security); if(sni) free(sni); 
                if(path) free(path); if(hostParam) free(hostParam); if(flow) free(flow);
                if(fp) free(fp); if(alpn) free(alpn); if(serviceName) free(serviceName);
            } else {
                // 无参数默认逻辑
                cJSON_AddStringToObject(node, "network", "tcp");
            }
            cJSON_AddItemToArray(outbounds, node);
        } else cJSON_Delete(node);
    } 
    // ---------------- SHADOWSOCKS ----------------
    else if (_stricmp(scheme, "ss") == 0) {
        // ss://BASE64(...)#tag 或 ss://method:pass@host:port#tag
        const char* body = p_colon + 3;
        const char* hash = strchr(body, '#');
        char fragment[256] = {0};
        if (hash) {
            strncpy(fragment, hash + 1, 255);
        }

        // 检查是否包含 @，如果有，则非 Base64 封装的全部信息 (SIP002 明文)
        if (strchr(body, '@')) {
            char temp_body[1024];
            int len = hash ? (int)(hash - body) : (int)strlen(body);
            if (len > 1023) len = 1023;
            strncpy(temp_body, body, len); temp_body[len] = 0;
            ParseSS(temp_body, fragment, node);
            cJSON_AddItemToArray(outbounds, node);
        } else {
            // 可能是 Base64 编码的 user:pass@host:port
            // 或者是旧版 method:pass@host:port
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
    // ---------------- SOCKS / HTTP ----------------
    else if (_stricmp(scheme, "socks") == 0 || _stricmp(scheme, "http") == 0) {
         // socks://user:pass@host:port#tag
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

// --------------------------------------------------------------------------
// 核心：订阅更新
// --------------------------------------------------------------------------

int UpdateAllSubscriptions(BOOL forceLog) {
    EnterCriticalSection(&g_configLock);
    int subCount = g_subCount;
    Subscription subsCopy[MAX_SUBS];
    for(int i=0; i<subCount; i++) subsCopy[i] = g_subs[i];
    LeaveCriticalSection(&g_configLock);

    if (subCount == 0) return 0;

    int new_nodes_count = 0;
    
    // 1. 读取配置文件
    char* buffer = NULL; long size = 0;
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) {
        if(forceLog) log_msg("[Sub] Failed to read config file");
        return 0;
    }
    cJSON* root = cJSON_Parse(buffer); free(buffer);
    if (!root) return 0;
    
    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    if (!outbounds) { cJSON_Delete(root); return 0; }
    
    // 2. 逐个更新订阅
    for (int i = 0; i < subCount; i++) {
        if (!subsCopy[i].enabled) continue;
        
        if (forceLog) log_msg("[Sub] Fetching: %s", subsCopy[i].url);
        
        char* resp = Utils_HttpGet(subsCopy[i].url);
        if (!resp) {
            if (forceLog) log_msg("[Sub] Network error: %s", subsCopy[i].url);
            continue;
        }
        
        // 尝试 Base64 解码 (订阅通常是 B64 编码的节点列表)
        size_t b64_len = 0;
        unsigned char* decoded = Base64Decode(resp, &b64_len);
        
        char* raw_list = NULL;
        if (decoded && b64_len > 0) {
            raw_list = (char*)decoded;
        } else {
            // 如果解码失败，可能服务器返回的就是明文列表
            raw_list = SafeStrDup(resp, strlen(resp));
        }
        free(resp);
        
        if (!raw_list) continue;
        
        // 逐行解析
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
    
    // 3. 保存更改
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
    
    // 释放旧缓存
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

// --------------------------------------------------------------------------
// 剪贴板导入
// --------------------------------------------------------------------------

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
        wchar_t key[32]; swprintf(key, 32, L"Url_%d", i);
        GetPrivateProfileStringA("Subs", key, "", g_subs[i].url, 512, "set.ini");
        
        swprintf(key, 32, L"En_%d", i);
        g_subs[i].enabled = GetPrivateProfileIntW(L"Subs", key, 1, g_iniFilePath);
    }
    
    g_subUpdateMode = GetPrivateProfileIntW(L"Subs", L"UpdateMode", UPDATE_MODE_DAILY, g_iniFilePath);
    g_subUpdateInterval = GetPrivateProfileIntW(L"Subs", L"UpdateInterval", 24, g_iniFilePath);
    char buf[64]; GetPrivateProfileStringA("Subs", "LastTime", "0", buf, 64, "set.ini");
    g_lastUpdateTime = _atoi64(buf);
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
        wchar_t key[32]; swprintf(key, 32, L"Url_%d", i);
        WritePrivateProfileStringA("Subs", key, g_subs[i].url, "set.ini");
        swprintf(key, 32, L"En_%d", i);
        swprintf(buf, 64, L"%d", g_subs[i].enabled); WritePrivateProfileStringW(L"Subs", key, buf, g_iniFilePath);
    }
    
    swprintf(buf, 64, L"%d", g_subUpdateMode); WritePrivateProfileStringW(L"Subs", L"UpdateMode", buf, g_iniFilePath);
    swprintf(buf, 64, L"%d", g_subUpdateInterval); WritePrivateProfileStringW(L"Subs", L"UpdateInterval", buf, g_iniFilePath);
    sprintf(buf, "%lld", g_lastUpdateTime); WritePrivateProfileStringA("Subs", "LastTime", buf, "set.ini");
}

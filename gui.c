#include "gui.h"
#include "config.h"
#include "proxy.h"
#include "utils.h"
#include "crypto.h"
#include "common.h" 
#include "resource.h" // 引入资源ID定义
#include <commctrl.h>
#include <stdio.h>
#include <wchar.h> 

// 链接 comctl32 库以支持高级控件
#pragma comment(lib, "comctl32.lib")

// 用于追踪窗口句柄，实现单例模式
static HWND hSettingsWnd = NULL;
static HWND hSubWnd = NULL;

// 订阅窗口控件 ID
#define ID_SUB_LIST     3000
#define ID_SUB_ADD_BTN  3001
#define ID_SUB_DEL_BTN  3002
#define ID_SUB_UPD_BTN  3003
#define ID_SUB_URL_EDIT 3004
#define ID_SUB_SAVE_BTN 3005

// 定义更新完成消息
#define WM_UPDATE_FINISH (WM_USER + 200)

// --- 辅助函数：字体设置回调 ---
BOOL CALLBACK EnumSetFont(HWND hWnd, LPARAM lParam) {
    SendMessageW(hWnd, WM_SETFONT, (WPARAM)lParam, TRUE);
    return TRUE;
}

// --- 自动更新线程 ---
DWORD WINAPI AutoUpdateThread(LPVOID lpParam) {
    // 延时 3 秒，等待主程序初始化完毕且界面显示出来
    Sleep(3000); 
    
    // 如果有启用的订阅，执行更新 (FALSE = 不弹窗，只写日志)
    // g_subCount 的读取虽理论上需加锁，但原子整数读取风险极低，此处从略以避免长锁
    if (g_subCount > 0) {
        int count = UpdateAllSubscriptions(FALSE); // 内部已加锁
        
        // 如果更新到了节点，仅通知界面刷新，不进行危险的 SwitchNode 操作
        if (count > 0) {
            HWND hMgr = FindWindowW(L"NodeMgr", NULL);
            if (hMgr && IsWindow(hMgr)) {
                PostMessage(hMgr, WM_REFRESH_NODELIST, 0, 0);
            }
        }
    }
    return 0;
}

// --- 手动更新线程 (解决 UI 卡死) ---
DWORD WINAPI ManualUpdateThread(LPVOID param) {
    HWND hWnd = (HWND)param;
    // 执行更新 (TRUE = 强制记录日志)
    int count = UpdateAllSubscriptions(TRUE); // 内部已加锁
    // 发送自定义消息通知 UI 线程更新完成
    PostMessage(hWnd, WM_UPDATE_FINISH, (WPARAM)count, 0);
    return 0;
}

void AddComboItem(HWND hCombo, const wchar_t* text, BOOL select) {
    int idx = SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)text);
    if (select) SendMessage(hCombo, CB_SETCURSEL, idx, 0);
}

void LoadNodeToEdit(HWND hWnd, const wchar_t* tag) {
    char* buffer = NULL; long size = 0;
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) return;
    cJSON* root = cJSON_Parse(buffer); free(buffer);
    if (!root) return;
    
    char tagUtf8[256];
    WideCharToMultiByte(CP_UTF8, 0, tag, -1, tagUtf8, 256, NULL, NULL);
    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    cJSON* target = NULL;
    cJSON* node;
    cJSON_ArrayForEach(node, outbounds) {
        cJSON* t = cJSON_GetObjectItem(node, "tag");
        if (t && strcmp(t->valuestring, tagUtf8) == 0) { target = node; break; }
    }
    if (target) {
        SetDlgItemTextW(hWnd, ID_EDIT_TAG, tag);
        cJSON* server = cJSON_GetObjectItem(target, "server");
        if(server) SetDlgItemTextA(hWnd, ID_EDIT_ADDR, server->valuestring);
        cJSON* port = cJSON_GetObjectItem(target, "server_port");
        if(port) SetDlgItemInt(hWnd, ID_EDIT_PORT, port->valueint, FALSE);
        cJSON* user = cJSON_GetObjectItem(target, "username");
        if(!user) user = cJSON_GetObjectItem(target, "uuid");
        if(user) SetDlgItemTextA(hWnd, ID_EDIT_USER, user->valuestring);
        cJSON* pass = cJSON_GetObjectItem(target, "password");
        if(pass) SetDlgItemTextA(hWnd, ID_EDIT_PASS, pass->valuestring);
        cJSON* trans = cJSON_GetObjectItem(target, "transport"); 
        if (!trans) trans = cJSON_GetObjectItem(target, "streamSettings");
        HWND hNet = GetDlgItem(hWnd, ID_EDIT_NET);
        SendMessage(hNet, CB_SETCURSEL, 0, 0); 
        cJSON* netType = NULL;
        if (trans) netType = cJSON_GetObjectItem(trans, "type");
        if (!netType) netType = cJSON_GetObjectItem(target, "network");
        if (netType && strcmp(netType->valuestring, "ws") == 0) SendMessage(hNet, CB_SETCURSEL, 1, 0);
        cJSON* wsSettings = NULL;
        if (trans) wsSettings = cJSON_GetObjectItem(trans, "wsSettings");
        if (!wsSettings && trans && netType && strcmp(netType->valuestring, "ws") == 0) wsSettings = trans;
        if (wsSettings) {
             cJSON* path = cJSON_GetObjectItem(wsSettings, "path");
             if (path) SetDlgItemTextA(hWnd, ID_EDIT_PATH, path->valuestring);
             cJSON* headers = cJSON_GetObjectItem(wsSettings, "headers");
             if (headers) {
                 cJSON* host = cJSON_GetObjectItem(headers, "Host");
                 if (host) SetDlgItemTextA(hWnd, ID_EDIT_HOST, host->valuestring);
             }
        }
        HWND hTls = GetDlgItem(hWnd, ID_EDIT_TLS);
        SendMessage(hTls, CB_SETCURSEL, 0, 0); 
        cJSON* tls = cJSON_GetObjectItem(target, "tls");
        cJSON* security = cJSON_GetObjectItem(target, "security");
        if (tls || (security && strcmp(security->valuestring, "tls") == 0)) {
             SendMessage(hTls, CB_SETCURSEL, 1, 0);
             cJSON* sni = NULL;
             if (tls) sni = cJSON_GetObjectItem(tls, "server_name");
             if (sni) SetDlgItemTextA(hWnd, ID_EDIT_HOST, sni->valuestring);
        }
    }
    cJSON_Delete(root);
}

// [修复] 保存节点时保留原始协议类型 (vless/trojan)，防止被误判为 vmess
void SaveEditedNode(HWND hWnd) {
    wchar_t wTag[256], wAddr[256], wUser[256], wPass[256], wHost[256], wPath[256];
    char tag[256], addr[256], user[256], pass[256], host[256], path[256];
    
    int port = GetDlgItemInt(hWnd, ID_EDIT_PORT, NULL, FALSE);
    if (port <= 0 || port > 65535) {
        MessageBoxW(hWnd, L"端口必须在 1-65535 之间", L"参数错误", MB_OK | MB_ICONERROR);
        return;
    }

    GetDlgItemTextW(hWnd, ID_EDIT_TAG, wTag, 256);
    GetDlgItemTextW(hWnd, ID_EDIT_ADDR, wAddr, 256);
    GetDlgItemTextW(hWnd, ID_EDIT_USER, wUser, 256);
    GetDlgItemTextW(hWnd, ID_EDIT_PASS, wPass, 256);
    GetDlgItemTextW(hWnd, ID_EDIT_HOST, wHost, 256);
    GetDlgItemTextW(hWnd, ID_EDIT_PATH, wPath, 256);
    
    WideCharToMultiByte(CP_UTF8, 0, wTag, -1, tag, 256, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, wAddr, -1, addr, 256, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, wUser, -1, user, 256, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, wPass, -1, pass, 256, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, wHost, -1, host, 256, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, wPath, -1, path, 256, NULL, NULL);
    
    int netIdx = SendMessage(GetDlgItem(hWnd, ID_EDIT_NET), CB_GETCURSEL, 0, 0);
    int tlsIdx = SendMessage(GetDlgItem(hWnd, ID_EDIT_TLS), CB_GETCURSEL, 0, 0);

    // 1. 读取配置文件，查找原始节点的类型
    char originalType[64] = {0};
    char* buffer = NULL; long size = 0;
    if (ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) {
        cJSON* root = cJSON_Parse(buffer); 
        free(buffer);
        if (root) {
            cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
            char oldTagUtf8[256];
            WideCharToMultiByte(CP_UTF8, 0, g_editingTag, -1, oldTagUtf8, 256, NULL, NULL);
            cJSON* node = NULL;
            cJSON_ArrayForEach(node, outbounds) {
                cJSON* t = cJSON_GetObjectItem(node, "tag");
                if (t && strcmp(t->valuestring, oldTagUtf8) == 0) {
                    cJSON* type = cJSON_GetObjectItem(node, "type");
                    // [Security] 限制复制长度
                    if (type && type->valuestring) snprintf(originalType, sizeof(originalType), "%s", type->valuestring);
                    break;
                }
            }
            cJSON_Delete(root);
        }
    }

    // 2. 构建新节点
    cJSON* newNode = cJSON_CreateObject();
    cJSON_AddStringToObject(newNode, "tag", tag);
    cJSON_AddStringToObject(newNode, "server", addr);
    cJSON_AddNumberToObject(newNode, "server_port", port);

    // 3. 智能设置类型 (优先使用原始类型)
    if (strlen(originalType) > 0) {
        cJSON_AddStringToObject(newNode, "type", originalType);
        // 根据类型决定字段名
        if (strcmp(originalType, "vless") == 0 || strcmp(originalType, "vmess") == 0) {
             cJSON_AddStringToObject(newNode, "uuid", user);
        } else {
             if (strlen(user)>0) cJSON_AddStringToObject(newNode, "username", user);
             if (strlen(pass)>0) cJSON_AddStringToObject(newNode, "password", pass);
        }
    } else {
        // 如果没有原始类型 (可能是新节点或读取失败)，则尝试推断
        if (strlen(user) > 20) {
            cJSON_AddStringToObject(newNode, "type", "vmess");
            cJSON_AddStringToObject(newNode, "uuid", user);
        } else {
            cJSON_AddStringToObject(newNode, "type", "socks");
            if (strlen(user)>0) cJSON_AddStringToObject(newNode, "username", user);
            if (strlen(pass)>0) cJSON_AddStringToObject(newNode, "password", pass);
        }
    }

    if (netIdx == 1) { 
        cJSON* trans = cJSON_CreateObject();
        cJSON_AddStringToObject(trans, "type", "ws");
        if (strlen(path) > 0) cJSON_AddStringToObject(trans, "path", path);
        if (strlen(host) > 0) {
            cJSON* h = cJSON_CreateObject();
            cJSON_AddStringToObject(h, "Host", host);
            cJSON_AddItemToObject(trans, "headers", h);
        }
        cJSON_AddItemToObject(newNode, "transport", trans);
    } else { cJSON_AddStringToObject(newNode, "network", "tcp"); }

    if (tlsIdx == 1) {
        cJSON* tlsObj = cJSON_CreateObject();
        cJSON_AddBoolToObject(tlsObj, "enabled", cJSON_True);
        if (strlen(host) > 0) cJSON_AddStringToObject(tlsObj, "server_name", host);
        cJSON_AddItemToObject(newNode, "tls", tlsObj);
    }

    // 4. 写入文件
    if (ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) {
        cJSON* root = cJSON_Parse(buffer); free(buffer);
        if (root) {
            cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
            int count = cJSON_GetArraySize(outbounds);
            int idxToReplace = -1;
            char oldTagUtf8[256];
            WideCharToMultiByte(CP_UTF8, 0, g_editingTag, -1, oldTagUtf8, 256, NULL, NULL);
            for (int i=0; i<count; i++) {
                cJSON* item = cJSON_GetArrayItem(outbounds, i);
                cJSON* t = cJSON_GetObjectItem(item, "tag");
                if (t && strcmp(t->valuestring, oldTagUtf8) == 0) {
                    idxToReplace = i; break;
                }
            }
            if (idxToReplace != -1) cJSON_ReplaceItemInArray(outbounds, idxToReplace, newNode);
            else cJSON_AddItemToArray(outbounds, newNode);
            char* out = cJSON_Print(root);
            WriteBufferToFile(CONFIG_FILE, out);
            free(out); cJSON_Delete(root);
        } else cJSON_Delete(newNode);
    } else cJSON_Delete(newNode);
}

// --- ListBox 与 Settings 窗口逻辑 ---

LRESULT CALLBACK ListBox_Proc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_KEYDOWN) {
        if (wParam == 'A' && (GetKeyState(VK_CONTROL) & 0x8000)) {
            SendMessage(hWnd, LB_SETSEL, TRUE, -1);
            return 0; 
        }
    }
    return CallWindowProc(g_oldListBoxProc, hWnd, msg, wParam, lParam);
}

LRESULT CALLBACK SettingsWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hHotkey, hPortEdit;
    switch(msg) {
        case WM_CREATE: {
            // [Lock] 保护读取，确保 UI 显示的是一致的全局配置
            EnterCriticalSection(&g_configLock);
            int localPort = g_localPort;
            int modifiers = g_hotkeyModifiers;
            int vk = g_hotkeyVk;
            BOOL chrome = g_enableChromeCiphers;
            BOOL alpn = g_enableALPN;
            BOOL frag = g_enableFragment;
            BOOL pad = g_enablePadding;
            int fMin = g_fragSizeMin;
            int fMax = g_fragSizeMax;
            int fDly = g_fragDelayMs;
            int pMin = g_padSizeMin;
            int pMax = g_padSizeMax;
            int uaIdx = g_uaPlatformIndex;
            char uaStr[512]; strcpy(uaStr, g_userAgentStr);
            LeaveCriticalSection(&g_configLock);

            int y = 25;
            // 基础设置区域
            CreateWindowW(L"STATIC", L"全局快捷键:", WS_CHILD|WS_VISIBLE, 25, y, 140, 20, hWnd, NULL,NULL,NULL);
            hHotkey = CreateWindowExW(0, HOTKEY_CLASSW, NULL, WS_CHILD|WS_VISIBLE|WS_BORDER, 160, y-3, 270, 25, hWnd, (HMENU)ID_HOTKEY_CTRL, NULL,NULL);
            UINT hkMod = 0; if (modifiers & MOD_SHIFT) hkMod |= HOTKEYF_SHIFT;
            if (modifiers & MOD_CONTROL) hkMod |= HOTKEYF_CONTROL;
            if (modifiers & MOD_ALT) hkMod |= HOTKEYF_ALT;
            SendMessage(hHotkey, HKM_SETHOTKEY, MAKEWORD(vk, hkMod), 0);
            
            y += 40;
            CreateWindowW(L"STATIC", L"本地代理端口:", WS_CHILD|WS_VISIBLE, 25, y, 140, 20, hWnd, NULL,NULL,NULL);
            hPortEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", NULL, WS_CHILD|WS_VISIBLE|ES_NUMBER, 160, y-3, 100, 25, hWnd, (HMENU)ID_PORT_EDIT, NULL,NULL);
            SetDlgItemInt(hWnd, ID_PORT_EDIT, localPort, FALSE);

            // 抗封锁设置 GroupBox
            y += 50;
            CreateWindowW(L"BUTTON", L"抗封锁策略配置", WS_CHILD|WS_VISIBLE|BS_GROUPBOX, 20, y, 420, 340, hWnd, NULL, NULL, NULL);
            
            y += 30;
            HWND hChk1 = CreateWindowW(L"BUTTON", L"启用 Chrome 浏览器指纹模拟", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 35, y, 380, 22, hWnd, (HMENU)ID_CHK_CIPHERS, NULL, NULL);
            y += 30;
            HWND hChk2 = CreateWindowW(L"BUTTON", L"启用 ALPN 协议伪装 (http/1.1)", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 35, y, 380, 22, hWnd, (HMENU)ID_CHK_ALPN, NULL, NULL);
            
            // --- 分片设置 ---
            y += 35;
            HWND hChk3 = CreateWindowW(L"BUTTON", L"启用 TCP 随机分片 (对抗 SNI 阻断)", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 35, y, 380, 22, hWnd, (HMENU)ID_CHK_FRAG, NULL, NULL);
            
            y += 30;
            CreateWindowW(L"STATIC", L"分片长度(字节):", WS_CHILD|WS_VISIBLE, 55, y+2, 110, 20, hWnd, NULL,NULL,NULL);
            HWND hFMin = CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_NUMBER|ES_CENTER, 170, y, 40, 22, hWnd, (HMENU)ID_EDIT_FRAG_MIN, NULL, NULL);
            CreateWindowW(L"STATIC", L"-", WS_CHILD|WS_VISIBLE, 215, y+2, 10, 20, hWnd, NULL,NULL,NULL);
            HWND hFMax = CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_NUMBER|ES_CENTER, 230, y, 40, 22, hWnd, (HMENU)ID_EDIT_FRAG_MAX, NULL, NULL);
            
            CreateWindowW(L"STATIC", L"延迟(ms):", WS_CHILD|WS_VISIBLE, 290, y+2, 60, 20, hWnd, NULL,NULL,NULL);
            HWND hDly = CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_NUMBER|ES_CENTER, 355, y, 40, 22, hWnd, (HMENU)ID_EDIT_FRAG_DLY, NULL, NULL);

            // --- Padding 设置 ---
            y += 40;
            HWND hChkPad = CreateWindowW(L"BUTTON", L"启用 TLS 流量填充 (随机包长度)", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 35, y, 380, 22, hWnd, (HMENU)ID_CHK_PADDING, NULL, NULL);
            
            y += 30;
            CreateWindowW(L"STATIC", L"随机填充(块):", WS_CHILD|WS_VISIBLE, 55, y+2, 110, 20, hWnd, NULL,NULL,NULL);
            HWND hPMin = CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_NUMBER|ES_CENTER, 170, y, 40, 22, hWnd, (HMENU)ID_EDIT_PAD_MIN, NULL, NULL);
            CreateWindowW(L"STATIC", L"-", WS_CHILD|WS_VISIBLE, 215, y+2, 10, 20, hWnd, NULL,NULL,NULL);
            HWND hPMax = CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_NUMBER|ES_CENTER, 230, y, 40, 22, hWnd, (HMENU)ID_EDIT_PAD_MAX, NULL, NULL);

            // --- UA 设置 ---
            y += 45;
            CreateWindowW(L"STATIC", L"伪装平台:", WS_CHILD|WS_VISIBLE, 35, y+3, 80, 20, hWnd, NULL,NULL,NULL);
            HWND hCombo = CreateWindowW(L"COMBOBOX", NULL, WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST|WS_VSCROLL, 120, y, 280, 200, hWnd, (HMENU)ID_COMBO_PLATFORM, NULL, NULL);
            
            y += 30;
            HWND hEditUA = CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL, 35, y, 365, 25, hWnd, (HMENU)ID_EDIT_UA_STR, NULL, NULL);

            // 按钮区域
            y += 60;
            CreateWindowW(L"BUTTON", L"确定", WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON, 110, y, 100, 32, hWnd, (HMENU)IDOK, NULL,NULL);
            CreateWindowW(L"BUTTON", L"取消", WS_CHILD|WS_VISIBLE, 250, y, 100, 32, hWnd, (HMENU)IDCANCEL, NULL,NULL);

            SendMessage(hChk1, BM_SETCHECK, chrome ? BST_CHECKED : BST_UNCHECKED, 0);
            SendMessage(hChk2, BM_SETCHECK, alpn ? BST_CHECKED : BST_UNCHECKED, 0);
            SendMessage(hChk3, BM_SETCHECK, frag ? BST_CHECKED : BST_UNCHECKED, 0);
            SendMessage(hChkPad, BM_SETCHECK, pad ? BST_CHECKED : BST_UNCHECKED, 0);

            SetDlgItemInt(hWnd, ID_EDIT_FRAG_MIN, fMin, FALSE);
            SetDlgItemInt(hWnd, ID_EDIT_FRAG_MAX, fMax, FALSE);
            SetDlgItemInt(hWnd, ID_EDIT_FRAG_DLY, fDly, FALSE);
            
            SetDlgItemInt(hWnd, ID_EDIT_PAD_MIN, pMin, FALSE);
            SetDlgItemInt(hWnd, ID_EDIT_PAD_MAX, pMax, FALSE);

            for(int i=0; i<5; i++) SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)UA_PLATFORMS[i]);
            SendMessage(hCombo, CB_SETCURSEL, uaIdx, 0);
            SetDlgItemTextA(hWnd, ID_EDIT_UA_STR, uaStr);
            
            EnumChildWindows(hWnd, EnumSetFont, (LPARAM)hAppFont);
            SendMessage(hWnd, WM_SETFONT, (WPARAM)hAppFont, TRUE);
            break;
        }
        case WM_COMMAND:
            if (LOWORD(wParam) == ID_COMBO_PLATFORM && HIWORD(wParam) == CBN_SELCHANGE) {
                int idx = SendMessage((HWND)lParam, CB_GETCURSEL, 0, 0);
                if (idx >= 0 && idx < 5) SetDlgItemTextA(hWnd, ID_EDIT_UA_STR, UA_TEMPLATES[idx]);
            }
            if (LOWORD(wParam) == IDOK) {
                // 读取 UI 状态
                int fMin = GetDlgItemInt(hWnd, ID_EDIT_FRAG_MIN, NULL, FALSE);
                int fMax = GetDlgItemInt(hWnd, ID_EDIT_FRAG_MAX, NULL, FALSE);
                int fDly = GetDlgItemInt(hWnd, ID_EDIT_FRAG_DLY, NULL, FALSE);
                int pMin = GetDlgItemInt(hWnd, ID_EDIT_PAD_MIN, NULL, FALSE);
                int pMax = GetDlgItemInt(hWnd, ID_EDIT_PAD_MAX, NULL, FALSE);
                
                if (fMin < 1) fMin = 1; if (fMax < fMin) fMax = fMin;
                if (pMin < 0) pMin = 0; if (pMax < pMin) pMax = pMin;

                LRESULT res = SendMessage(hHotkey, HKM_GETHOTKEY, 0, 0);
                UINT vk = LOBYTE(res); UINT mod = HIBYTE(res);
                UINT newMod = 0; if (mod & HOTKEYF_SHIFT) newMod |= MOD_SHIFT;
                if (mod & HOTKEYF_CONTROL) newMod |= MOD_CONTROL;
                if (mod & HOTKEYF_ALT) newMod |= MOD_ALT;
                
                int port = GetDlgItemInt(hWnd, ID_PORT_EDIT, NULL, FALSE);

                // [Lock] 保护写入，确保全局配置的一致性
                EnterCriticalSection(&g_configLock);

                g_fragSizeMin = fMin; g_fragSizeMax = fMax; g_fragDelayMs = fDly;
                g_padSizeMin = pMin; g_padSizeMax = pMax;

                g_enableChromeCiphers = (IsDlgButtonChecked(hWnd, ID_CHK_CIPHERS) == BST_CHECKED);
                g_enableALPN = (IsDlgButtonChecked(hWnd, ID_CHK_ALPN) == BST_CHECKED);
                g_enableFragment = (IsDlgButtonChecked(hWnd, ID_CHK_FRAG) == BST_CHECKED);
                g_enablePadding = (IsDlgButtonChecked(hWnd, ID_CHK_PADDING) == BST_CHECKED);

                g_uaPlatformIndex = SendMessage(GetDlgItem(hWnd, ID_COMBO_PLATFORM), CB_GETCURSEL, 0, 0);
                GetDlgItemTextA(hWnd, ID_EDIT_UA_STR, g_userAgentStr, 511);

                if (vk != 0 && newMod != 0) {
                    UnregisterHotKey(hwnd, ID_GLOBAL_HOTKEY);
                    if (RegisterHotKey(hwnd, ID_GLOBAL_HOTKEY, newMod, vk)) { g_hotkeyVk = vk; g_hotkeyModifiers = newMod; }
                }

                if (port > 0 && port < 65535) g_localPort = port;

                LeaveCriticalSection(&g_configLock);

                SaveSettings(); // 内部已加锁
                if (g_proxyRunning) { StopProxyCore(); StartProxyCore(); }
                DestroyWindow(hWnd);
            } else if (LOWORD(wParam) == IDCANCEL) DestroyWindow(hWnd);
            break;
        case WM_CLOSE: DestroyWindow(hWnd); break;
        case WM_DESTROY: hSettingsWnd = NULL; break;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

void OpenSettingsWindow() {
    if (hSettingsWnd && IsWindow(hSettingsWnd)) {
        ShowWindow(hSettingsWnd, SW_RESTORE);
        SetForegroundWindow(hSettingsWnd);
        return;
    }
    WNDCLASSW wc = {0}; wc.lpfnWndProc=SettingsWndProc; wc.hInstance=GetModuleHandle(NULL); wc.lpszClassName=L"Settings"; wc.hbrBackground=(HBRUSH)(COLOR_BTNFACE+1);
    WNDCLASSW temp; if (!GetClassInfoW(GetModuleHandle(NULL), L"Settings", &temp)) RegisterClassW(&wc);
    hSettingsWnd = CreateWindowW(L"Settings", L"软件设置", WS_VISIBLE|WS_CAPTION|WS_SYSMENU, CW_USEDEFAULT,0,480,560, hwnd,NULL,wc.hInstance,NULL);
    ShowWindow(hSettingsWnd, SW_SHOW);
}

// --- 订阅设置窗口逻辑 ---

static HWND hSubList;

void RefreshSubList() {
    if (!hSubList) return;
    ListView_DeleteAllItems(hSubList);
    
    // [Lock] 保护 g_subs 遍历，防止后台更新线程同时修改
    EnterCriticalSection(&g_configLock);
    for (int i = 0; i < g_subCount; i++) {
        LVITEMW li = {0};
        li.mask = LVIF_TEXT;
        li.iItem = i;
        li.iSubItem = 0;
        wchar_t wUrl[512];
        MultiByteToWideChar(CP_UTF8, 0, g_subs[i].url, -1, wUrl, 512);
        li.pszText = wUrl;
        ListView_InsertItem(hSubList, &li);
        ListView_SetCheckState(hSubList, i, g_subs[i].enabled);
    }
    LeaveCriticalSection(&g_configLock);
}

// 辅助：更新自定义时间编辑框的启用状态
void UpdateSubUIState(HWND hDlg) {
    BOOL isCustom = (SendMessage(GetDlgItem(hDlg, IDC_RADIO_CUSTOM), BM_GETCHECK, 0, 0) == BST_CHECKED);
    EnableWindow(GetDlgItem(hDlg, IDC_EDIT_CUSTOM_TIME), isCustom);
}

LRESULT CALLBACK SubWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch(msg) {
        case WM_CREATE: {
            hSubList = CreateWindowExW(0, WC_LISTVIEWW, NULL, 
                WS_CHILD|WS_VISIBLE|WS_BORDER|LVS_REPORT|LVS_NOCOLUMNHEADER|LVS_SHOWSELALWAYS|LVS_SINGLESEL, 
                10, 10, 460, 150, hWnd, (HMENU)ID_SUB_LIST, GetModuleHandle(NULL), NULL);
            
            ListView_SetExtendedListViewStyle(hSubList, LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
            LVCOLUMNW lc = {0}; lc.mask = LVCF_WIDTH; lc.cx = 430; ListView_InsertColumn(hSubList, 0, &lc);

            CreateWindowW(L"STATIC", L"新增地址:", WS_CHILD|WS_VISIBLE, 10, 175, 70, 20, hWnd, NULL,NULL,NULL);
            CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL, 80, 172, 300, 24, hWnd, (HMENU)ID_SUB_URL_EDIT, NULL,NULL);
            CreateWindowW(L"BUTTON", L"添加", WS_CHILD|WS_VISIBLE, 390, 172, 80, 24, hWnd, (HMENU)ID_SUB_ADD_BTN, NULL,NULL);

            CreateWindowW(L"BUTTON", L"删除选中", WS_CHILD|WS_VISIBLE, 10, 210, 80, 28, hWnd, (HMENU)ID_SUB_DEL_BTN, NULL,NULL);
            CreateWindowW(L"BUTTON", L"保存设置", WS_CHILD|WS_VISIBLE, 280, 210, 80, 28, hWnd, (HMENU)ID_SUB_SAVE_BTN, NULL,NULL);
            CreateWindowW(L"BUTTON", L"立即更新", WS_CHILD|WS_VISIBLE, 370, 210, 100, 28, hWnd, (HMENU)ID_SUB_UPD_BTN, NULL,NULL);
            
            // --- 新增：更新周期设置区域 ---
            int yGrp = 250;
            CreateWindowW(L"BUTTON", L"自动更新周期", WS_CHILD|WS_VISIBLE|BS_GROUPBOX, 10, yGrp, 460, 60, hWnd, (HMENU)IDC_GROUP_SUB_UPDATE, NULL, NULL);
            
            HWND hDaily = CreateWindowW(L"BUTTON", L"每天", WS_CHILD|WS_VISIBLE|BS_AUTORADIOBUTTON|WS_GROUP, 25, yGrp+25, 60, 20, hWnd, (HMENU)IDC_RADIO_DAILY, NULL, NULL);
            HWND hWeekly = CreateWindowW(L"BUTTON", L"每周", WS_CHILD|WS_VISIBLE|BS_AUTORADIOBUTTON, 100, yGrp+25, 60, 20, hWnd, (HMENU)IDC_RADIO_WEEKLY, NULL, NULL);
            HWND hCustom = CreateWindowW(L"BUTTON", L"自定义", WS_CHILD|WS_VISIBLE|BS_AUTORADIOBUTTON, 180, yGrp+25, 70, 20, hWnd, (HMENU)IDC_RADIO_CUSTOM, NULL, NULL);
            
            HWND hTime = CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_NUMBER|ES_CENTER, 260, yGrp+23, 50, 22, hWnd, (HMENU)IDC_EDIT_CUSTOM_TIME, NULL, NULL);
            CreateWindowW(L"STATIC", L"小时", WS_CHILD|WS_VISIBLE, 315, yGrp+25, 40, 20, hWnd, (HMENU)IDC_STATIC_CUSTOM_UNIT, NULL, NULL);

            // 初始化控件状态
            EnterCriticalSection(&g_configLock);
            int mode = g_subUpdateMode;
            int interval = g_subUpdateInterval;
            LeaveCriticalSection(&g_configLock);

            if (mode == UPDATE_MODE_WEEKLY) SendMessage(hWeekly, BM_SETCHECK, BST_CHECKED, 0);
            else if (mode == UPDATE_MODE_CUSTOM) SendMessage(hCustom, BM_SETCHECK, BST_CHECKED, 0);
            else SendMessage(hDaily, BM_SETCHECK, BST_CHECKED, 0);

            SetDlgItemInt(hWnd, IDC_EDIT_CUSTOM_TIME, interval, FALSE);
            UpdateSubUIState(hWnd);

            RefreshSubList();
            EnumChildWindows(hWnd, EnumSetFont, (LPARAM)hAppFont);
            SendMessage(hWnd, WM_SETFONT, (WPARAM)hAppFont, TRUE);
            break;
        }
        case WM_COMMAND: {
            int id = LOWORD(wParam);
            
            if (id == IDC_RADIO_DAILY || id == IDC_RADIO_WEEKLY || id == IDC_RADIO_CUSTOM) {
                UpdateSubUIState(hWnd);
            }
            else if (id == ID_SUB_ADD_BTN) {
                EnterCriticalSection(&g_configLock); // [Lock]
                if (g_subCount >= MAX_SUBS) { 
                    LeaveCriticalSection(&g_configLock);
                    MessageBoxW(hWnd, L"已达最大订阅数限制(20个)", L"提示", MB_OK); 
                    break; 
                }
                char newUrl[512]; GetDlgItemTextA(hWnd, ID_SUB_URL_EDIT, newUrl, 512);
                TrimString(newUrl);
                if (strlen(newUrl) < 4) { 
                    LeaveCriticalSection(&g_configLock);
                    MessageBoxW(hWnd, L"请输入有效的订阅地址", L"错误", MB_OK); 
                    break; 
                }
                strncpy(g_subs[g_subCount].url, newUrl, 511); g_subs[g_subCount].url[511] = 0;
                g_subs[g_subCount].enabled = TRUE; g_subCount++;
                LeaveCriticalSection(&g_configLock); // [Unlock]
                
                RefreshSubList(); SetDlgItemTextA(hWnd, ID_SUB_URL_EDIT, "");
            }
            else if (id == ID_SUB_DEL_BTN) {
                int sel = ListView_GetNextItem(hSubList, -1, LVNI_SELECTED);
                if (sel != -1) {
                    EnterCriticalSection(&g_configLock); // [Lock]
                    for (int i = sel; i < g_subCount - 1; i++) g_subs[i] = g_subs[i+1];
                    g_subCount--; 
                    LeaveCriticalSection(&g_configLock); // [Unlock]
                    RefreshSubList();
                } else MessageBoxW(hWnd, L"请先在列表中选中一项", L"提示", MB_OK);
            }
            else if (id == ID_SUB_SAVE_BTN || id == ID_SUB_UPD_BTN) {
                EnterCriticalSection(&g_configLock); // [Lock]
                
                for(int i=0; i<g_subCount; i++) g_subs[i].enabled = ListView_GetCheckState(hSubList, i);
                
                if (SendMessage(GetDlgItem(hWnd, IDC_RADIO_WEEKLY), BM_GETCHECK, 0, 0) == BST_CHECKED) {
                    g_subUpdateMode = UPDATE_MODE_WEEKLY;
                } else if (SendMessage(GetDlgItem(hWnd, IDC_RADIO_CUSTOM), BM_GETCHECK, 0, 0) == BST_CHECKED) {
                    g_subUpdateMode = UPDATE_MODE_CUSTOM;
                } else {
                    g_subUpdateMode = UPDATE_MODE_DAILY;
                }

                int interval = GetDlgItemInt(hWnd, IDC_EDIT_CUSTOM_TIME, NULL, FALSE);
                if (interval > 0) g_subUpdateInterval = interval;
                
                LeaveCriticalSection(&g_configLock); // [Unlock]
                
                SaveSettings(); 

                if (id == ID_SUB_SAVE_BTN) {
                    MessageBoxW(hWnd, L"订阅设置已保存", L"成功", MB_OK);
                } else {
                    SetWindowTextW(hWnd, L"正在更新 (后台进行中)...");
                    EnableWindow(GetDlgItem(hWnd, ID_SUB_UPD_BTN), FALSE); 
                    CreateThread(NULL, 0, ManualUpdateThread, (LPVOID)hWnd, 0, NULL);
                }
            }
            break;
        }
        case WM_UPDATE_FINISH: { 
            int count = (int)wParam;
            EnableWindow(GetDlgItem(hWnd, ID_SUB_UPD_BTN), TRUE);
            SetWindowTextW(hWnd, L"订阅设置");
            wchar_t msg[128]; 
            swprintf_s(msg, 128, L"更新完成，共获取 %d 个节点。", count);
            MessageBoxW(hWnd, msg, L"结果", MB_OK);
            HWND hMgr = FindWindowW(L"NodeMgr", NULL);
            if (hMgr) SendMessage(hMgr, WM_REFRESH_NODELIST, 0, 0);
            break;
        }
        case WM_CLOSE: DestroyWindow(hWnd); break;
        case WM_DESTROY: hSubWnd = NULL; break;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

void OpenSubWindow() {
    if (hSubWnd && IsWindow(hSubWnd)) { ShowWindow(hSubWnd, SW_RESTORE); SetForegroundWindow(hSubWnd); return; }
    WNDCLASSW wc = {0};
    if (!GetClassInfoW(GetModuleHandle(NULL), L"SubWnd", &wc)) {
        wc.lpfnWndProc = SubWndProc; wc.hInstance = GetModuleHandle(NULL); 
        wc.lpszClassName = L"SubWnd"; wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE+1);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW); RegisterClassW(&wc);
    }
    hSubWnd = CreateWindowW(L"SubWnd", L"订阅设置", WS_VISIBLE|WS_CAPTION|WS_SYSMENU, CW_USEDEFAULT,0,500,360, NULL,NULL,GetModuleHandle(NULL),NULL);
    ShowWindow(hSubWnd, SW_SHOW); UpdateWindow(hSubWnd);
}

// --- 节点管理窗口 ---

LRESULT CALLBACK NodeMgrWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hList;
    #define ID_NODEMGR_SUB 2003 

    switch(msg) {
        case WM_CREATE:
            hList = CreateWindowW(L"LISTBOX", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|LBS_NOTIFY|LBS_EXTENDEDSEL, 10, 10, 410, 170, hWnd, (HMENU)ID_NODEMGR_LIST, NULL, NULL);
            g_oldListBoxProc = (WNDPROC)SetWindowLongPtr(hList, GWLP_WNDPROC, (LONG_PTR)ListBox_Proc);
            
            CreateWindowW(L"BUTTON", L"编辑选中节点", WS_CHILD | WS_VISIBLE, 10, 185, 120, 30, hWnd, (HMENU)ID_NODEMGR_EDIT, NULL, NULL);
            CreateWindowW(L"BUTTON", L"删除选中节点", WS_CHILD | WS_VISIBLE, 140, 185, 120, 30, hWnd, (HMENU)ID_NODEMGR_DEL, NULL, NULL);
            CreateWindowW(L"BUTTON", L"订阅设置", WS_CHILD | WS_VISIBLE, 270, 185, 120, 30, hWnd, (HMENU)ID_NODEMGR_SUB, NULL, NULL);

            EnumChildWindows(hWnd, EnumSetFont, (LPARAM)hAppFont);
            SendMessage(hWnd, WM_SETFONT, (WPARAM)hAppFont, TRUE);
            SendMessage(hWnd, WM_REFRESH_NODELIST, 0, 0); 
            break;
        case WM_REFRESH_NODELIST:
            SendMessage(hList, LB_RESETCONTENT, 0, 0);
            
            // [Lock] 保护节点列表更新和遍历
            // ParseTags 内部虽然有锁，但我们需要确保 ParseTags 之后到遍历结束期间 nodeTags 不被释放
            EnterCriticalSection(&g_configLock); 
            
            ParseTags(); // 内部有锁，递归锁是安全的
            for(int i = 0; i < nodeCount; i++) {
                SendMessageW(hList, LB_ADDSTRING, 0, (LPARAM)nodeTags[i]);
            }
            
            LeaveCriticalSection(&g_configLock); 
            break;
        case WM_COMMAND:
            if (LOWORD(wParam) == ID_NODEMGR_SUB) OpenSubWindow();
            else if (LOWORD(wParam) == ID_NODEMGR_EDIT) {
                int selCount = SendMessage(hList, LB_GETSELCOUNT, 0, 0);
                if (selCount <= 0) { MessageBoxW(hWnd, L"请先选择一个需要编辑的节点！", L"提示", MB_OK|MB_ICONWARNING); break; }
                int selIndex = 0;
                if (SendMessage(hList, LB_GETSELITEMS, 1, (LPARAM)&selIndex) == LB_ERR) break; 
                int len = SendMessage(hList, LB_GETTEXTLEN, selIndex, 0);
                if (len > 0) {
                    wchar_t* tag = (wchar_t*)malloc((len + 1) * sizeof(wchar_t));
                    SendMessageW(hList, LB_GETTEXT, selIndex, (LPARAM)tag);
                    OpenNodeEditWindow(tag);
                    free(tag);
                }
            }
            else if (LOWORD(wParam) == ID_NODEMGR_DEL) {
                int selCount = SendMessage(hList, LB_GETSELCOUNT, 0, 0);
                if (selCount <= 0) { MessageBoxW(hWnd, L"请先选择至少一个节点", L"提示", MB_OK); break; }
                wchar_t confirmMsg[64]; 
                swprintf_s(confirmMsg, 64, L"确定要删除选中的 %d 个节点吗？", selCount);
                if (MessageBoxW(hWnd, confirmMsg, L"确认删除", MB_YESNO | MB_ICONQUESTION) != IDYES) break;
                int* selIndices = (int*)malloc(selCount * sizeof(int));
                if (!selIndices) break;
                SendMessage(hList, LB_GETSELITEMS, (WPARAM)selCount, (LPARAM)selIndices);
                wchar_t** tagsToDelete = (wchar_t**)malloc(selCount * sizeof(wchar_t*));
                for (int i = 0; i < selCount; i++) {
                    int len = SendMessage(hList, LB_GETTEXTLEN, selIndices[i], 0);
                    tagsToDelete[i] = (wchar_t*)malloc((len + 1) * sizeof(wchar_t));
                    SendMessageW(hList, LB_GETTEXT, selIndices[i], (LPARAM)tagsToDelete[i]);
                }
                for (int i = 0; i < selCount; i++) { DeleteNode(tagsToDelete[i]); free(tagsToDelete[i]); }
                free(tagsToDelete); free(selIndices);
                SendMessage(hWnd, WM_REFRESH_NODELIST, 0, 0); MessageBoxW(hWnd, L"删除完成", L"提示", MB_OK);
            }
            break;
        case WM_SHOWWINDOW: if ((BOOL)wParam == TRUE) SendMessage(hWnd, WM_REFRESH_NODELIST, 0, 0); break;
        case WM_CLOSE: ShowWindow(hWnd, SW_HIDE); return 0;
        case WM_DESTROY: if (hList && g_oldListBoxProc) SetWindowLongPtr(hList, GWLP_WNDPROC, (LONG_PTR)g_oldListBoxProc); break;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

void OpenNodeManager() {
    static HWND hMgr = NULL; 
    if (hMgr && IsWindow(hMgr)) { ShowWindow(hMgr, SW_SHOW); SetForegroundWindow(hMgr); SendMessage(hMgr, WM_REFRESH_NODELIST, 0, 0); return; }
    WNDCLASSW wc = {0};
    if (!GetClassInfoW(GetModuleHandle(NULL), L"NodeMgr", &wc)) {
        wc.lpfnWndProc = NodeMgrWndProc; wc.hInstance = GetModuleHandle(NULL); wc.lpszClassName = L"NodeMgr"; wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE+1);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW); RegisterClassW(&wc);
    }
    hMgr = CreateWindowW(L"NodeMgr", L"节点管理 (支持 Ctrl+A 全选/多选)", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, 0, 450, 270, NULL, NULL, GetModuleHandle(NULL), NULL);
    ShowWindow(hMgr, SW_SHOW);
}

LRESULT CALLBACK NodeEditWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch(msg) {
        case WM_CREATE: {
            int x = 25, w_lbl = 110, w_edit = 300, h = 24, gap = 40; int y = 20;
            #define CREATE_LABEL(txt) CreateWindowW(L"STATIC", txt, WS_CHILD|WS_VISIBLE, x, y, w_lbl, h, hWnd, NULL, NULL, NULL)
            #define CREATE_EDIT(id, styles) CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|styles, x+w_lbl, y-2, w_edit, h+4, hWnd, (HMENU)id, NULL, NULL)
            #define CREATE_COMBO(id) CreateWindowW(L"COMBOBOX", NULL, WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST|WS_VSCROLL, x+w_lbl, y-2, 140, 200, hWnd, (HMENU)id, NULL, NULL)
            CREATE_LABEL(L"节点备注:"); CREATE_EDIT(ID_EDIT_TAG, ES_AUTOHSCROLL); y += gap;
            CREATE_LABEL(L"服务器地址:"); CREATE_EDIT(ID_EDIT_ADDR, ES_AUTOHSCROLL); y += gap;
            CREATE_LABEL(L"服务器端口:"); CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_NUMBER, x+w_lbl, y-2, 80, h+4, hWnd, (HMENU)ID_EDIT_PORT, NULL, NULL); y += gap + 10;
            CreateWindowW(L"STATIC", L"认证信息", WS_CHILD|WS_VISIBLE|SS_GRAYFRAME, x, y+5, 420, 1, hWnd, NULL, NULL, NULL); y += 25;
            CREATE_LABEL(L"用户/UUID:"); CREATE_EDIT(ID_EDIT_USER, ES_AUTOHSCROLL); y += gap;
            CREATE_LABEL(L"连接密码:"); CREATE_EDIT(ID_EDIT_PASS, ES_AUTOHSCROLL); y += gap + 10;
            CreateWindowW(L"STATIC", L"传输配置", WS_CHILD|WS_VISIBLE|SS_GRAYFRAME, x, y+5, 420, 1, hWnd, NULL, NULL, NULL); y += 25;
            CREATE_LABEL(L"传输协议:"); HWND hNet = CREATE_COMBO(ID_EDIT_NET); AddComboItem(hNet, L"tcp", TRUE); AddComboItem(hNet, L"ws", FALSE); y += gap;
            CREATE_LABEL(L"伪装类型:"); HWND hType = CREATE_COMBO(ID_EDIT_TYPE); AddComboItem(hType, L"none", TRUE); y += gap;
            CREATE_LABEL(L"伪装域名:"); CREATE_EDIT(ID_EDIT_HOST, ES_AUTOHSCROLL); y += gap;
            CREATE_LABEL(L"请求路径:"); CREATE_EDIT(ID_EDIT_PATH, ES_AUTOHSCROLL); y += gap;
            CREATE_LABEL(L"传输安全:"); HWND hTls = CREATE_COMBO(ID_EDIT_TLS); AddComboItem(hTls, L"none", TRUE); AddComboItem(hTls, L"tls", FALSE); y += gap + 30;
            CreateWindowW(L"BUTTON", L"确定", WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON, 120, y, 100, 32, hWnd, (HMENU)IDOK, NULL, NULL);
            CreateWindowW(L"BUTTON", L"取消", WS_CHILD|WS_VISIBLE, 260, y, 100, 32, hWnd, (HMENU)IDCANCEL, NULL, NULL); y += 80; 
            g_nEditContentHeight = y; g_nEditScrollPos = 0;
            EnumChildWindows(hWnd, EnumSetFont, (LPARAM)hAppFont); if (hAppFont) SendMessage(hWnd, WM_SETFONT, (WPARAM)hAppFont, TRUE);
            LoadNodeToEdit(hWnd, g_editingTag);
            SCROLLINFO si; si.cbSize = sizeof(si); si.fMask = SIF_RANGE | SIF_PAGE; si.nMin = 0; si.nMax = g_nEditContentHeight; si.nPage = 680; SetScrollInfo(hWnd, SB_VERT, &si, TRUE);
            break;
        }
        case WM_SIZE: {
            RECT rc; GetClientRect(hWnd, &rc);
            SCROLLINFO si; si.cbSize = sizeof(si); si.fMask = SIF_RANGE | SIF_PAGE | SIF_POS; si.nMin = 0; si.nMax = g_nEditContentHeight; si.nPage = rc.bottom - rc.top; si.nPos = g_nEditScrollPos;
            SetScrollInfo(hWnd, SB_VERT, &si, TRUE); break;
        }
        case WM_VSCROLL: {
            SCROLLINFO si; si.cbSize = sizeof(si); si.fMask = SIF_ALL; GetScrollInfo(hWnd, SB_VERT, &si);
            int oldPos = si.nPos; int newPos = oldPos;
            switch (LOWORD(wParam)) {
                case SB_TOP: newPos = si.nMin; break;
                case SB_BOTTOM: newPos = si.nMax; break;
                case SB_LINEUP: newPos -= 20; break;
                case SB_LINEDOWN: newPos += 20; break;
                case SB_PAGEUP: newPos -= si.nPage; break;
                case SB_PAGEDOWN: newPos += si.nPage; break;
                case SB_THUMBTRACK: newPos = si.nTrackPos; break;
            }
            if (newPos < 0) newPos = 0; if (newPos > (int)(si.nMax - si.nPage + 1)) newPos = si.nMax - si.nPage + 1;
            if (newPos != oldPos) {
                ScrollWindow(hWnd, 0, oldPos - newPos, NULL, NULL); si.fMask = SIF_POS; si.nPos = newPos;
                SetScrollInfo(hWnd, SB_VERT, &si, TRUE); UpdateWindow(hWnd); g_nEditScrollPos = newPos;
            }
            break;
        }
        case WM_MOUSEWHEEL: {
            int zDelta = GET_WHEEL_DELTA_WPARAM(wParam); int scrollLines = 3; 
            SystemParametersInfo(SPI_GETWHEELSCROLLLINES, 0, &scrollLines, 0);
            for(int i=0; i<scrollLines; i++) SendMessage(hWnd, WM_VSCROLL, zDelta > 0 ? SB_LINEUP : SB_LINEDOWN, 0);
            break;
        }
        case WM_COMMAND:
            if (LOWORD(wParam) == IDOK) {
                SaveEditedNode(hWnd); MessageBoxW(hWnd, L"节点配置已更新", L"操作成功", MB_OK); DestroyWindow(hWnd);
                HWND hMgr = FindWindowW(L"NodeMgr", NULL); if (hMgr) SendMessage(hMgr, WM_REFRESH_NODELIST, 0, 0);
            } else if (LOWORD(wParam) == IDCANCEL) DestroyWindow(hWnd);
            break;
        case WM_CLOSE: DestroyWindow(hWnd); break;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

void OpenNodeEditWindow(const wchar_t* tag) {
    if (!tag || wcslen(tag) == 0) return;
    wcsncpy(g_editingTag, tag, 255); 
    WNDCLASSW wc = {0};
    if (!GetClassInfoW(GetModuleHandle(NULL), L"NodeEdit", &wc)) {
        wc.lpfnWndProc = NodeEditWndProc; wc.hInstance = GetModuleHandle(NULL); wc.lpszClassName = L"NodeEdit"; wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE+1);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW); RegisterClassW(&wc);
    }
    HWND h = CreateWindowW(L"NodeEdit", L"配置节点", WS_VISIBLE|WS_CAPTION|WS_SYSMENU|WS_VSCROLL|WS_THICKFRAME|WS_MINIMIZEBOX, CW_USEDEFAULT, 0, 500, 720, NULL, NULL, GetModuleHandle(NULL), NULL);
    if(h) { ShowWindow(h, SW_SHOW); UpdateWindow(h); }
}

LRESULT CALLBACK LogWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hEdit;
    static HWND hChk;

    switch(msg) {
        case WM_CREATE:
            hChk = CreateWindowW(L"BUTTON", L"开启日志记录 (默认关闭)", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 
                10, 5, 200, 20, hWnd, (HMENU)ID_LOG_CHK, NULL, NULL);
            SendMessage(hChk, BM_SETCHECK, g_enableLog ? BST_CHECKED : BST_UNCHECKED, 0);
            SendMessage(hChk, WM_SETFONT, (WPARAM)hAppFont, 0);

            hEdit = CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|ES_READONLY, 
                0, 30, 0, 0, hWnd, (HMENU)ID_LOGVIEWER_EDIT, NULL, NULL);
            SendMessage(hEdit, WM_SETFONT, (WPARAM)hLogFont, 0); 
            break;

        case WM_SIZE: 
            MoveWindow(hEdit, 0, 30, LOWORD(lParam), HIWORD(lParam) - 30, TRUE); 
            break;

        case WM_COMMAND:
            if (LOWORD(wParam) == ID_LOG_CHK) {
                g_enableLog = (IsDlgButtonChecked(hWnd, ID_LOG_CHK) == BST_CHECKED);
                // [Fix] 切换开关时增加日志提示，给用户反馈
                if (g_enableLog) {
                    log_msg("[System] 日志记录已开启。");
                }
            }
            break;

        case WM_LOG_UPDATE: {
            wchar_t* p = (wchar_t*)lParam; int len = GetWindowTextLength(hEdit);
            if (len > 30000) { SendMessage(hEdit, EM_SETSEL, 0, -1); SendMessage(hEdit, WM_CLEAR, 0, 0); }
            SendMessage(hEdit, EM_SETSEL, 0xffff, 0xffff); SendMessageW(hEdit, EM_REPLACESEL, 0, (LPARAM)p); free(p); break;
        }
        case WM_CLOSE: ShowWindow(hWnd, SW_HIDE); return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

void OpenLogViewer(BOOL bShow) {
    if (hLogViewerWnd && IsWindow(hLogViewerWnd)) {
        if (bShow) { ShowWindow(hLogViewerWnd, SW_SHOW); if (IsIconic(hLogViewerWnd)) ShowWindow(hLogViewerWnd, SW_RESTORE); SetForegroundWindow(hLogViewerWnd); }
        return;
    }
    
    // [Fix] 明确指定背景画刷为 COLOR_BTNFACE+1 (标准灰色背景)
    // 防止背景未绘制导致的黑色或透明视觉残留，以及解决与复选框控件背景色的差异
    WNDCLASSW wc = {0}; 
    if (!GetClassInfoW(GetModuleHandle(NULL), L"LogWnd", &wc)) {
        wc.lpfnWndProc = LogWndProc; 
        wc.hInstance = GetModuleHandle(NULL); 
        wc.lpszClassName = L"LogWnd"; 
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1); // 修复：设置背景色
        RegisterClassW(&wc);
    }
    
    hLogViewerWnd = CreateWindowW(L"LogWnd", L"运行日志", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT,0,600,400, NULL,NULL,GetModuleHandle(NULL),NULL);
    if (bShow) ShowWindow(hLogViewerWnd, SW_SHOW); else ShowWindow(hLogViewerWnd, SW_HIDE);
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_TRAY && LOWORD(lParam) == WM_RBUTTONUP) {
        POINT pt; GetCursorPos(&pt); SetForegroundWindow(hWnd);
        
        // [Lock] 保护 Tray 菜单的生成，防止 nodeTags 变动
        EnterCriticalSection(&g_configLock);
        ParseTags(); 
        
        if (hMenu) DestroyMenu(hMenu); hMenu = CreatePopupMenu(); hNodeSubMenu = CreatePopupMenu();
        if (nodeCount == 0) AppendMenuW(hNodeSubMenu, MF_STRING|MF_GRAYED, 0, L"(无节点)");
        else {
            for(int i=0; i<nodeCount; i++) {
                UINT f = MF_STRING; if(wcscmp(nodeTags[i], currentNode)==0) f|=MF_CHECKED;
                AppendMenuW(hNodeSubMenu, f, ID_TRAY_NODE_BASE+i, nodeTags[i]);
            }
        }
        LeaveCriticalSection(&g_configLock);

        AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hNodeSubMenu, L"切换节点");
        AppendMenuW(hMenu, MF_STRING, ID_TRAY_MANAGE_NODES, L"节点管理");
        AppendMenuW(hMenu, MF_STRING, ID_TRAY_IMPORT_CLIPBOARD, L"节点导入");
        AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
        UINT proxyFlags = MF_STRING; if (IsSystemProxyEnabled()) proxyFlags |= MF_CHECKED;
        AppendMenuW(hMenu, proxyFlags, ID_TRAY_SYSTEM_PROXY, L"系统代理");
        AppendMenuW(hMenu, MF_STRING, ID_TRAY_SETTINGS, L"软件设置");
        AppendMenuW(hMenu, MF_STRING, ID_TRAY_SHOW_CONSOLE, L"查看日志");
        AppendMenuW(hMenu, IsAutorun()?MF_CHECKED:MF_UNCHECKED, ID_TRAY_AUTORUN, L"开机启动");
        if (g_isIconVisible) AppendMenuW(hMenu, MF_STRING, ID_TRAY_HIDE_ICON, L"隐藏图标"); else AppendMenuW(hMenu, MF_STRING, ID_TRAY_HIDE_ICON, L"显示图标");
        AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
        AppendMenuW(hMenu, MF_STRING, ID_TRAY_EXIT, L"退出程序");
        TrackPopupMenu(hMenu, TPM_RIGHTALIGN|TPM_BOTTOMALIGN, pt.x, pt.y, 0, hWnd, NULL);
    }
    else if (msg == WM_COMMAND) {
        int id = LOWORD(wParam);
        if (id == ID_TRAY_EXIT) { 
            Shell_NotifyIconW(NIM_DELETE, &nid); if (IsSystemProxyEnabled()) SetSystemProxy(FALSE); StopProxyCore(); ExitProcess(0); 
        }
        else if (id == ID_TRAY_SYSTEM_PROXY) SetSystemProxy(!IsSystemProxyEnabled());
        else if (id == ID_TRAY_SHOW_CONSOLE) OpenLogViewer(TRUE);
        else if (id == ID_TRAY_MANAGE_NODES) OpenNodeManager();
        else if (id == ID_TRAY_SETTINGS) OpenSettingsWindow();
        else if (id == ID_TRAY_HIDE_ICON) ToggleTrayIcon();
        else if (id == ID_TRAY_AUTORUN) SetAutorun(!IsAutorun());
        else if (id == ID_TRAY_IMPORT_CLIPBOARD) {
            int count = ImportFromClipboard(); 
            if (count > 0) {
                ParseTags();
                HWND hMgr = FindWindowW(L"NodeMgr", L"节点管理 (支持 Ctrl+A 全选/多选)");
                if (hMgr && IsWindow(hMgr)) SendMessage(hMgr, WM_REFRESH_NODELIST, 0, 0);
                wchar_t msgBuf[128]; 
                swprintf_s(msgBuf, 128, L"成功导入 %d 个节点！", count);
                MessageBoxW(hWnd, msgBuf, L"导入成功", MB_OK|MB_ICONINFORMATION);
                
                EnterCriticalSection(&g_configLock);
                if (wcslen(currentNode) == 0 && nodeCount > 0) {
                    LeaveCriticalSection(&g_configLock);
                    SwitchNode(nodeTags[0]); // SwitchNode 内部会加锁
                } else {
                    LeaveCriticalSection(&g_configLock);
                }
            } else MessageBoxW(hWnd, L"剪贴板中未发现支持的链接 (vmess/vless/ss/trojan)", L"导入失败", MB_OK|MB_ICONWARNING);
        }
        else if (id >= ID_TRAY_NODE_BASE && id < ID_TRAY_NODE_BASE + 1000) {
            int idx = id - ID_TRAY_NODE_BASE;
            
            // [Lock] 保护 nodeTags 访问
            EnterCriticalSection(&g_configLock);
            if (idx >= 0 && idx < nodeCount) {
                // 复制 tag，避免 SwitchNode 内部锁与外部锁冲突（SwitchNode 是高层逻辑）
                // 更好的做法是 Copy tag -> Unlock -> SwitchNode
                int len = wcslen(nodeTags[idx]);
                wchar_t* tagCopy = (wchar_t*)malloc((len + 1) * sizeof(wchar_t));
                wcscpy(tagCopy, nodeTags[idx]);
                LeaveCriticalSection(&g_configLock);
                
                SwitchNode(tagCopy);
                free(tagCopy);
            } else {
                LeaveCriticalSection(&g_configLock);
            }
        }
    }
    else if (msg == WM_HOTKEY && wParam == ID_GLOBAL_HOTKEY) ToggleTrayIcon();
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, LPWSTR lpCmdLine, int nShow) {
    srand((unsigned)time(NULL));

    // [Fix] 初始化全局锁 (最早调用)
    InitGlobalLocks();

    wchar_t exePath[MAX_PATH]; GetModuleFileNameW(NULL, exePath, MAX_PATH);
    wchar_t* pDir = wcsrchr(exePath, L'\\'); if (pDir) { *pDir = 0; SetCurrentDirectoryW(exePath); }

    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
    
    // 必须在主线程最开始初始化 OpenSSL 全局表
    init_crypto_global(); 

    INITCOMMONCONTROLSEX ic = {sizeof(INITCOMMONCONTROLSEX), ICC_HOTKEY_CLASS}; InitCommonControlsEx(&ic);
    NONCLIENTMETRICSW ncm = { sizeof(NONCLIENTMETRICSW) };
    if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(NONCLIENTMETRICSW), &ncm, 0)) hAppFont = CreateFontIndirectW(&ncm.lfMenuFont);
    else hAppFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei");
    hLogFont = CreateFontW(14,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,0,0,L"Consolas");
    
    OpenLogViewer(FALSE); 
    GetModuleFileNameW(NULL, g_iniFilePath, MAX_PATH);
    wchar_t* p = wcsrchr(g_iniFilePath, L'\\'); if (p) { *p = 0; wcscat(g_iniFilePath, L"\\set.ini"); } else wcscpy(g_iniFilePath, L"set.ini");
    
    LoadSettings();
    CreateThread(NULL, 0, AutoUpdateThread, NULL, 0, NULL);
    
    WNDCLASSW wc = {0}; wc.lpfnWndProc = WndProc; wc.hInstance = hInst; wc.lpszClassName = L"TrayProxyClass";
    wc.hIcon = LoadIcon(hInst, MAKEINTRESOURCE(1)); if (!wc.hIcon) wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    RegisterClassW(&wc);
    
    hwnd = CreateWindowW(L"TrayProxyClass", L"App", 0, 0,0,0,0, NULL,NULL,hInst,NULL);
    RegisterHotKey(hwnd, ID_GLOBAL_HOTKEY, g_hotkeyModifiers, g_hotkeyVk);
    
    nid.cbSize = sizeof(nid); nid.hWnd = hwnd; nid.uID = 1; nid.uFlags = NIF_ICON|NIF_MESSAGE|NIF_TIP;
    nid.uCallbackMessage = WM_TRAY; nid.hIcon = wc.hIcon; wcscpy(nid.szTip, L"Mandala Client");
    if (g_hideTrayStart == 1) { g_isIconVisible = FALSE; } else { Shell_NotifyIconW(NIM_ADD, &nid); g_isIconVisible = TRUE; }
    
    ParseTags(); // 内部已加锁

    // [修复] 启动时优先使用上次保存的节点
    if (wcslen(currentNode) > 0) {
        SwitchNode(currentNode);
    }
    else if (nodeCount > 0) {
        // [Lock] 保护 nodeTags 访问
        EnterCriticalSection(&g_configLock);
        wchar_t* firstNode = _wcsdup(nodeTags[0]); // 复制一份出来
        LeaveCriticalSection(&g_configLock);
        
        SwitchNode(firstNode);
        free(firstNode);
    }
    
    MSG msg; while(GetMessage(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    
    // 程序退出前清理
    cleanup_crypto_global();
    DeleteGlobalLocks(); // [Fix] 销毁锁
    
    return 0;
}

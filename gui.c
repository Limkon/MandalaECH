#include "gui.h"
#include "proxy.h"
#include "config.h"
#include "utils.h"
#include "common.h"
#include "resource.h"
#include "cJSON.h"
#include <shellapi.h>
#include <commctrl.h>
#include <stdio.h>
#include <process.h>

#pragma comment(lib, "comctl32.lib")

// [Fix] 防止资源头文件缺失定义
#ifndef IDI_ICON1
#define IDI_ICON1 101
#endif

// --- 全局变量 ---
HWND hMainWnd = NULL;
HWND hLogViewerWnd = NULL;
NOTIFYICONDATAW nid;
BOOL g_isIconVisible = FALSE;

#define WM_TRAYICON (WM_USER + 1)
#define ID_TRAY_EXIT 1001
#define ID_TRAY_SHOW 1002
#define ID_TRAY_UPDATE_SUB 1003
#define ID_TRAY_COPY_CMD 1004

static const wchar_t* szWindowClass = L"MandalaProxyClient";
static const wchar_t* szTitle = L"Mandala Client";

void UpdateTrayIconTooltip(const wchar_t* text) {
    if (!g_isIconVisible) return;
    wcsncpy(nid.szTip, text, 127); nid.szTip[127] = 0;
    Shell_NotifyIconW(NIM_MODIFY, &nid);
}

void ShowBalloonTip(const wchar_t* title, const wchar_t* msg) {
    if (!g_isIconVisible) return;
    wcsncpy(nid.szInfo, msg, 255); nid.szInfo[255] = 0;
    wcsncpy(nid.szInfoTitle, title, 63); nid.szInfoTitle[63] = 0;
    nid.uFlags |= NIF_INFO;
    Shell_NotifyIconW(NIM_MODIFY, &nid);
}

LRESULT CALLBACK LogWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE: {
        HWND hEdit = CreateWindowExW(0, L"EDIT", L"", 
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY, 
            0, 0, 600, 400, hWnd, (HMENU)1, GetModuleHandle(NULL), NULL);
        SendMessage(hEdit, WM_SETFONT, (WPARAM)GetStockObject(ANSI_FIXED_FONT), TRUE);
    } break;
    case WM_SIZE: {
        HWND hEdit = GetDlgItem(hWnd, 1);
        RECT rc; GetClientRect(hWnd, &rc);
        MoveWindow(hEdit, 0, 0, rc.right, rc.bottom, TRUE);
    } break;
    case WM_LOG_UPDATE: {
        wchar_t* msg = (wchar_t*)lParam;
        if (msg) {
            HWND hEdit = GetDlgItem(hWnd, 1);
            int len = GetWindowTextLengthW(hEdit);
            if (len > 30000) { 
                SendMessage(hEdit, EM_SETSEL, 0, 10000);
                SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)L"");
                len = GetWindowTextLengthW(hEdit);
            }
            SendMessage(hEdit, EM_SETSEL, len, len);
            SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)msg);
            Proxy_Free(msg, (wcslen(msg) + 1) * sizeof(wchar_t));
        }
    } break;
    case WM_CLOSE: ShowWindow(hWnd, SW_HIDE); return 0;
    default: return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

unsigned __stdcall ManualUpdateThread(void* p) {
    UpdateAllSubscriptions(TRUE);
    HWND h = (HWND)p;
    if (IsWindow(h)) {
        EnterCriticalSection(&g_configLock);
        if (g_isIconVisible) {
            wcsncpy(nid.szInfo, L"Update Check Completed", 255);
            wcsncpy(nid.szInfoTitle, L"Subscription", 63);
            nid.uFlags |= NIF_INFO;
            Shell_NotifyIconW(NIM_MODIFY, &nid);
        }
        LeaveCriticalSection(&g_configLock);
    }
    return 0;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    static UINT s_uTaskbarRestart;
    switch (message) {
    case WM_CREATE:
        s_uTaskbarRestart = RegisterWindowMessageW(L"TaskbarCreated");
        memset(&nid, 0, sizeof(nid));
        nid.cbSize = sizeof(nid);
        nid.hWnd = hWnd;
        nid.uID = 1;
        nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        nid.uCallbackMessage = WM_TRAYICON;
        nid.hIcon = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_ICON1)); 
        if (!nid.hIcon) nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
        wcsncpy(nid.szTip, L"Mandala Client - Ready", 127);
        if (!g_hideTrayStart) { Shell_NotifyIconW(NIM_ADD, &nid); g_isIconVisible = TRUE; }
        RegisterHotKey(hWnd, 1, g_hotkeyModifiers, g_hotkeyVk);
        break;
    case WM_TRAYICON:
        if (lParam == WM_RBUTTONUP) {
            POINT pt; GetCursorPos(&pt);
            HMENU hMenu = CreatePopupMenu();
            HMENU hNodeMenu = CreatePopupMenu();
            EnterCriticalSection(&g_configLock);
            AppendMenuW(hNodeMenu, MF_STRING | (nodeCount == 0 ? MF_GRAYED : 0), 0, L"-- Select Node --");
            for (int i = 0; i < nodeCount; i++) {
                UINT flags = MF_STRING;
                // [Fix] 使用 wcscmp 直接比较宽字符，无需转换 UTF8
                // currentNode 和 nodeTags[i] 都是 wchar_t*
                if (wcscmp(nodeTags[i], currentNode) == 0) flags |= MF_CHECKED;
                AppendMenuW(hNodeMenu, flags, 2000 + i, nodeTags[i]);
            }
            LeaveCriticalSection(&g_configLock);
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hNodeMenu, L"Servers");
            AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
            AppendMenuW(hMenu, MF_STRING, ID_TRAY_UPDATE_SUB, L"Update Subscriptions");
            AppendMenuW(hMenu, MF_STRING, ID_TRAY_COPY_CMD, L"Import from Clipboard");
            AppendMenuW(hMenu, MF_STRING, ID_TRAY_SHOW, L"Show Logs");
            AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
            AppendMenuW(hMenu, MF_STRING, ID_TRAY_EXIT, L"Exit");
            SetForegroundWindow(hWnd);
            int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, hWnd, NULL);
            DestroyMenu(hMenu);
            if (cmd == ID_TRAY_EXIT) DestroyWindow(hWnd);
            else if (cmd == ID_TRAY_SHOW) {
                if (!hLogViewerWnd) {
                    WNDCLASSEXW w = {0}; w.cbSize=sizeof(WNDCLASSEX); w.lpfnWndProc=LogWndProc; w.hInstance=GetModuleHandle(NULL);
                    w.lpszClassName=L"MandalaLogViewer"; w.hIcon=LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_ICON1));
                    w.hCursor=LoadCursor(NULL, IDC_ARROW); w.hbrBackground=(HBRUSH)(COLOR_WINDOW+1); RegisterClassExW(&w);
                    hLogViewerWnd = CreateWindowW(L"MandalaLogViewer", L"Connection Logs", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, 0, 600, 400, NULL, NULL, GetModuleHandle(NULL), NULL);
                }
                ShowWindow(hLogViewerWnd, SW_SHOW); SetForegroundWindow(hLogViewerWnd);
            }
            else if (cmd == ID_TRAY_UPDATE_SUB) _beginthreadex(NULL, 0, ManualUpdateThread, (void*)hWnd, 0, NULL);
            else if (cmd == ID_TRAY_COPY_CMD) {
                int n = ImportFromClipboard();
                wchar_t msg[64]; swprintf_s(msg, 64, L"Imported %d nodes", n); ShowBalloonTip(L"Import", msg);
            }
            else if (cmd >= 2000) {
                int idx = cmd - 2000;
                EnterCriticalSection(&g_configLock);
                if (idx < nodeCount) {
                    wchar_t tagCopy[256]; wcsncpy(tagCopy, nodeTags[idx], 255); tagCopy[255]=0;
                    LeaveCriticalSection(&g_configLock);
                    SwitchNode(tagCopy);
                } else LeaveCriticalSection(&g_configLock);
            }
        }
        else if (lParam == WM_LBUTTONDBLCLK) SendMessage(hWnd, WM_COMMAND, ID_TRAY_SHOW, 0);
        break;
    case WM_HOTKEY: if (wParam == 1) ToggleTrayIcon(); break;
    case WM_DESTROY: StopProxyCore(); Shell_NotifyIconW(NIM_DELETE, &nid); SetSystemProxy(FALSE); PostQuitMessage(0); break;
    default: if (message == s_uTaskbarRestart) Shell_NotifyIconW(NIM_ADD, &nid); return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    Proxy_InitMemPool(); 
    GetModuleFileNameW(NULL, g_iniFilePath, MAX_PATH);
    wchar_t* p = wcsrchr(g_iniFilePath, L'\\'); if (p) *(p+1) = 0;
    wcscat(g_iniFilePath, L"set.ini");
    LoadSettings();
    ParseTags();
    
    WNDCLASSEXW wcex = {0}; wcex.cbSize = sizeof(WNDCLASSEX); wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc; wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1));
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW); wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszClassName = szWindowClass;
    if (!RegisterClassExW(&wcex)) return FALSE;
    
    hMainWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, NULL, NULL, hInstance, NULL);
    if (!hMainWnd) return FALSE;
    
    // [Fix] 使用 wcslen 检查 wchar_t 字符串
    if (wcslen(currentNode) > 0) {
        EnterCriticalSection(&g_configLock);
        char* buffer = NULL; long size = 0;
        if (ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) {
            cJSON* root = cJSON_Parse(buffer);
            Proxy_Free(buffer, size + 1);
            if (root) {
                cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
                char tagUtf8[256]; WideCharToMultiByte(CP_UTF8, 0, currentNode, -1, tagUtf8, 256, NULL, NULL);
                cJSON* node;
                cJSON_ArrayForEach(node, outbounds) {
                    cJSON* t = cJSON_GetObjectItem(node, "tag");
                    if (t && t->valuestring && strcmp(t->valuestring, tagUtf8) == 0) { 
                        ParseNodeConfigToGlobal(node); StartProxyCore(); break; 
                    }
                }
                cJSON_Delete(root);
            }
        }
        LeaveCriticalSection(&g_configLock);
    }
    
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    if (hLogViewerWnd && IsWindow(hLogViewerWnd)) DestroyWindow(hLogViewerWnd);
    Proxy_CleanupMemPool();
    return (int) msg.wParam;
}

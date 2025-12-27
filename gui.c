#include "gui.h"
#include "proxy.h"   // [New] 引入 proxy.h 以使用 Proxy_InitMemPool, Proxy_CleanupMemPool, Proxy_Free
#include "config.h"
#include "utils.h"
#include "common.h"
#include "resource.h"
#include "cJSON.h"   // [New] 用于在启动时解析 config.json 查找默认节点

#include <shellapi.h>
#include <commctrl.h>
#include <stdio.h>
#include <process.h> // [New] for _beginthreadex

// 链接通用控件库，确保界面风格现代化
#pragma comment(lib, "comctl32.lib")

// --- 全局变量定义 ---
HWND hMainWnd = NULL;
HWND hLogViewerWnd = NULL;
NOTIFYICONDATAW nid;
BOOL g_isIconVisible = FALSE;

// 自定义消息与命令 ID
#define WM_TRAYICON (WM_USER + 1)
#define ID_TRAY_EXIT 1001
#define ID_TRAY_SHOW 1002
#define ID_TRAY_UPDATE_SUB 1003
#define ID_TRAY_COPY_CMD 1004

// 窗口类名与标题
static const wchar_t* szWindowClass = L"MandalaProxyClient";
static const wchar_t* szTitle = L"Mandala Client";

// --- 辅助函数实现 ---

// 更新托盘图标的提示文本
void UpdateTrayIconTooltip(const wchar_t* text) {
    if (!g_isIconVisible) return;
    wcsncpy(nid.szTip, text, 127);
    nid.szTip[127] = 0; // 确保截断安全
    Shell_NotifyIconW(NIM_MODIFY, &nid);
}

// 显示托盘气泡提示
void ShowBalloonTip(const wchar_t* title, const wchar_t* msg) {
    if (!g_isIconVisible) return;
    wcsncpy(nid.szInfo, msg, 255);
    nid.szInfo[255] = 0;
    wcsncpy(nid.szInfoTitle, title, 63);
    nid.szInfoTitle[63] = 0;
    nid.uFlags |= NIF_INFO;
    Shell_NotifyIconW(NIM_MODIFY, &nid);
}

// --- 窗口过程回调函数 ---

// 日志窗口的消息处理
LRESULT CALLBACK LogWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE:
        {
            // 创建一个全填充的只读编辑框用于显示日志
            // ID 设为 1以便后续获取
            HWND hEdit = CreateWindowExW(0, L"EDIT", L"", 
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY, 
                0, 0, 600, 400, hWnd, (HMENU)1, GetModuleHandle(NULL), NULL);
            // 设置等宽字体以便于阅读
            SendMessage(hEdit, WM_SETFONT, (WPARAM)GetStockObject(ANSI_FIXED_FONT), TRUE);
        }
        break;

    case WM_SIZE:
        {
            // 窗口大小改变时，调整编辑框填满客户区
            HWND hEdit = GetDlgItem(hWnd, 1);
            RECT rc; GetClientRect(hWnd, &rc);
            MoveWindow(hEdit, 0, 0, rc.right, rc.bottom, TRUE);
        }
        break;

    case WM_LOG_UPDATE:
        {
            // [Core Fix] 接收 utils.c 发来的日志字符串指针
            // lParam 是 wchar_t* 类型，由 Proxy_Malloc 分配
            wchar_t* msg = (wchar_t*)lParam;
            if (msg) {
                HWND hEdit = GetDlgItem(hWnd, 1);
                int len = GetWindowTextLengthW(hEdit);
                
                // 简单的日志滚动限制，防止内存占用过高 (限制约 30000 字符)
                if (len > 30000) { 
                    SendMessage(hEdit, EM_SETSEL, 0, 10000); // 选中前 10000 字符
                    SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)L""); // 删除
                    len = GetWindowTextLengthW(hEdit); // 更新长度
                }
                
                // 追加文本到末尾
                SendMessage(hEdit, EM_SETSEL, len, len);
                SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)msg);
                
                // [Crucial] 释放跨线程传递的内存
                // 必须使用 Proxy_Free 且计算正确的大小 (wchar_t)
                Proxy_Free(msg, (wcslen(msg) + 1) * sizeof(wchar_t));
            }
        }
        break;

    case WM_CLOSE:
        // 拦截关闭消息，改为隐藏窗口
        ShowWindow(hWnd, SW_HIDE);
        return 0;

    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// 手动更新订阅的线程函数
unsigned __stdcall ManualUpdateThread(void* p) {
    // 调用 config.c 中的更新逻辑
    UpdateAllSubscriptions(TRUE);
    
    // 更新完成后通知用户
    HWND h = (HWND)p;
    if (IsWindow(h)) {
        // 由于 ShowBalloonTip 访问全局 nid 且在 UI 线程外，虽然 Shell_NotifyIcon 相对线程安全，
        // 但最好还是确保主窗口句柄有效。
        // 这里为了简化，直接调用 (实际生产中通常 PostMessage 通知主线程弹气泡)
        // 考虑到 nid 是全局变量，这里可能存在竞态，但在单用户操作下风险可控。
        // 为了严格稳定，建议：
        // PostMessage(hMainWnd, WM_USER_UPDATE_DONE, 0, 0); 
        // 但为了保持原功能完整性且不引入新消息定义，直接调用：
        EnterCriticalSection(&g_configLock); // 加锁保护 nid
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

// 主窗口的消息处理
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    // 用于处理 explorer.exe 重启后的托盘图标重建
    static UINT s_uTaskbarRestart;

    switch (message) {
    case WM_CREATE:
        s_uTaskbarRestart = RegisterWindowMessageW(L"TaskbarCreated");
        
        // 初始化托盘图标结构
        memset(&nid, 0, sizeof(nid));
        nid.cbSize = sizeof(nid);
        nid.hWnd = hWnd;
        nid.uID = 1;
        nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        nid.uCallbackMessage = WM_TRAYICON;
        nid.hIcon = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_ICON1)); 
        if (!nid.hIcon) nid.hIcon = LoadIcon(NULL, IDI_APPLICATION); // Fallback
        wcsncpy(nid.szTip, L"Mandala Client - Ready", 127);
        
        // 根据配置决定是否启动时显示托盘
        if (!g_hideTrayStart) {
            Shell_NotifyIconW(NIM_ADD, &nid);
            g_isIconVisible = TRUE;
        }
        
        // 注册全局热键 (默认 Alt+H，具体值由 config 加载)
        RegisterHotKey(hWnd, 1, g_hotkeyModifiers, g_hotkeyVk);
        break;

    case WM_TRAYICON:
        // 处理托盘图标事件
        if (lParam == WM_RBUTTONUP) {
            // 右键菜单
            POINT pt; GetCursorPos(&pt);
            HMENU hMenu = CreatePopupMenu();
            
            // 动态构建节点列表子菜单
            HMENU hNodeMenu = CreatePopupMenu();
            EnterCriticalSection(&g_configLock);
            AppendMenuW(hNodeMenu, MF_STRING | (nodeCount == 0 ? MF_GRAYED : 0), 0, L"-- Select Node --");
            for (int i = 0; i < nodeCount; i++) {
                UINT flags = MF_STRING;
                // 将 wchar_t tag 转为 utf8 对比当前选中节点
                char tagUtf8[256]; 
                WideCharToMultiByte(CP_UTF8, 0, nodeTags[i], -1, tagUtf8, 256, NULL, NULL);
                if (strcmp(tagUtf8, currentNode) == 0) flags |= MF_CHECKED;
                
                // 节点菜单 ID 从 2000 开始
                AppendMenuW(hNodeMenu, flags, 2000 + i, nodeTags[i]);
            }
            LeaveCriticalSection(&g_configLock);

            // 组装主菜单
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hNodeMenu, L"Servers");
            AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
            AppendMenuW(hMenu, MF_STRING, ID_TRAY_UPDATE_SUB, L"Update Subscriptions");
            AppendMenuW(hMenu, MF_STRING, ID_TRAY_COPY_CMD, L"Import from Clipboard");
            AppendMenuW(hMenu, MF_STRING, ID_TRAY_SHOW, L"Show Logs");
            AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
            AppendMenuW(hMenu, MF_STRING, ID_TRAY_EXIT, L"Exit");

            // 弹出菜单 (必须先 SetForegroundWindow)
            SetForegroundWindow(hWnd);
            int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, hWnd, NULL);
            DestroyMenu(hMenu);

            // 处理菜单命令
            if (cmd == ID_TRAY_EXIT) {
                // 发送销毁消息，退出程序
                DestroyWindow(hWnd);
            } else if (cmd == ID_TRAY_SHOW) {
                // 显示/创建日志窗口
                if (!hLogViewerWnd) {
                    WNDCLASSEXW wcex = {0};
                    wcex.cbSize = sizeof(WNDCLASSEX);
                    wcex.lpfnWndProc = LogWndProc;
                    wcex.hInstance = GetModuleHandle(NULL);
                    wcex.lpszClassName = L"MandalaLogViewer";
                    wcex.hIcon = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_ICON1));
                    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
                    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
                    RegisterClassExW(&wcex);
                    
                    hLogViewerWnd = CreateWindowW(L"MandalaLogViewer", L"Connection Logs", WS_OVERLAPPEDWINDOW,
                        CW_USEDEFAULT, 0, 600, 400, NULL, NULL, GetModuleHandle(NULL), NULL);
                }
                ShowWindow(hLogViewerWnd, SW_SHOW);
                SetForegroundWindow(hLogViewerWnd);
            } else if (cmd == ID_TRAY_UPDATE_SUB) {
                // [Core Fix] 使用 _beginthreadex 启动更新线程
                _beginthreadex(NULL, 0, ManualUpdateThread, (void*)hWnd, 0, NULL);
            } else if (cmd == ID_TRAY_COPY_CMD) {
                // 从剪贴板导入
                int n = ImportFromClipboard();
                wchar_t msg[64]; swprintf_s(msg, 64, L"Imported %d nodes", n);
                ShowBalloonTip(L"Import", msg);
            } else if (cmd >= 2000) {
                // 切换节点
                int idx = cmd - 2000;
                EnterCriticalSection(&g_configLock);
                if (idx < nodeCount) {
                    wchar_t* tag = nodeTags[idx]; // 此时持有锁，指针安全
                    // SwitchNode 会重新加锁，所以这里需要先解锁？
                    // SwitchNode 内部有 EnterCriticalSection。这是递归锁吗？
                    // CRITICAL_SECTION 是递归锁，同一个线程可以多次 Enter。
                    // 但为了减少锁持有时间，SwitchNode 需要读取文件，耗时较长。
                    // 我们应该复制 tag 后解锁，再调用 SwitchNode。
                    wchar_t tagCopy[256];
                    wcsncpy(tagCopy, tag, 255); tagCopy[255] = 0;
                    LeaveCriticalSection(&g_configLock);
                    
                    SwitchNode(tagCopy);
                } else {
                    LeaveCriticalSection(&g_configLock);
                }
            }
        }
        else if (lParam == WM_LBUTTONDBLCLK) {
             // 双击托盘显示日志
             SendMessage(hWnd, WM_COMMAND, ID_TRAY_SHOW, 0);
        }
        break;

    case WM_HOTKEY:
        if (wParam == 1) {
            // 热键处理：切换托盘图标显隐
            ToggleTrayIcon();
        }
        break;

    case WM_DESTROY:
        // [Cleanup] 程序退出清理流程
        StopProxyCore(); // 停止代理核心
        Shell_NotifyIconW(NIM_DELETE, &nid); // 删除托盘
        SetSystemProxy(FALSE); // 确保关闭系统代理
        PostQuitMessage(0);
        break;

    default:
        // 处理任务栏重启消息（防止托盘图标消失）
        if (message == s_uTaskbarRestart) {
            Shell_NotifyIconW(NIM_ADD, &nid);
        }
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// --- 程序入口点 ---

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    // 1. 初始化核心内存管理
    // 这也会初始化 g_configLock 和内存池锁
    Proxy_InitMemPool(); 
    
    // 2. 确定配置文件路径
    // 默认使用 exe 同目录下的 set.ini
    GetModuleFileNameW(NULL, g_iniFilePath, MAX_PATH);
    wchar_t* p = wcsrchr(g_iniFilePath, L'\\');
    if (p) *(p+1) = 0;
    wcscat(g_iniFilePath, L"set.ini");

    // 3. 加载设置与节点列表
    LoadSettings();
    ParseTags(); // 解析 config.json 中的节点列表到内存
    
    // 4. 注册并创建主窗口（隐藏）
    WNDCLASSEXW wcex = {0};
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1));
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszClassName = szWindowClass;
    
    if (!RegisterClassExW(&wcex)) return FALSE;

    hMainWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, NULL, NULL, hInstance, NULL);

    if (!hMainWnd) return FALSE;
    
    // 5. 自动启动代理核心 (Auto-Start)
    // 检查是否有上次选中的节点 (currentNode)
    if (strlen(currentNode) > 0) {
        EnterCriticalSection(&g_configLock);
        
        char* buffer = NULL; long size = 0;
        // 读取 config.json 查找对应节点的详细配置
        if (ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) {
            cJSON* root = cJSON_Parse(buffer);
            // 释放 buffer (使用 Proxy_Free)
            Proxy_Free(buffer, size + 1);
            
            if (root) {
                cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
                char tagUtf8[256]; 
                WideCharToMultiByte(CP_UTF8, 0, currentNode, -1, tagUtf8, 256, NULL, NULL);
                
                cJSON* node;
                cJSON_ArrayForEach(node, outbounds) {
                    cJSON* t = cJSON_GetObjectItem(node, "tag");
                    if (t && t->valuestring && strcmp(t->valuestring, tagUtf8) == 0) { 
                        // 找到节点，解析到 g_proxyConfig
                        ParseNodeConfigToGlobal(node); 
                        // 启动代理核心线程
                        StartProxyCore();
                        break; 
                    }
                }
                cJSON_Delete(root);
            }
        }
        LeaveCriticalSection(&g_configLock);
    }
    
    // 6. 消息循环
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // 7. 全局资源清理
    if (hLogViewerWnd && IsWindow(hLogViewerWnd)) DestroyWindow(hLogViewerWnd);
    Proxy_CleanupMemPool(); // 销毁内存池和锁
    
    return (int) msg.wParam;
}

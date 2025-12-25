#ifndef GUI_H
#define GUI_H

#include "common.h"

// 托盘图标 ID
#define ID_TRAY_EXIT            9001
#define ID_TRAY_SYSTEM_PROXY    9002
#define ID_TRAY_SHOW_CONSOLE    9003
#define ID_TRAY_MANAGE_NODES    9004
#define ID_TRAY_HIDE_ICON       9005
#define ID_TRAY_SETTINGS        9006
#define ID_TRAY_AUTORUN         9007
#define ID_TRAY_IMPORT_CLIPBOARD 9008
#define ID_TRAY_NODE_BASE       10000

// 窗口管理
void OpenLogViewer(BOOL bShow);
void OpenSettingsWindow();
void OpenSubWindow();
void OpenNodeManager();
void OpenNodeEditWindow(const wchar_t* tag);

// 托盘操作
void ToggleTrayIcon();

// 消息处理回调
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// 列表视图句柄 (供订阅更新刷新用)
extern HWND hSubList;

#endif // GUI_H


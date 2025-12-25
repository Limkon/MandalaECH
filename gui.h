#ifndef GUI_H
#define GUI_H

#include "common.h"

// [修复] 删除了 ID_TRAY_EXIT 等重复宏定义
// 这些 ID 已在 common.h 中统一管理，此处保留原有的函数声明

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

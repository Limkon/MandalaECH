#ifndef GUI_H
#define GUI_H

#include "common.h"

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

// 列表视图句柄
extern HWND hSubList;

#endif // GUI_H

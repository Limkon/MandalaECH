#ifndef GUI_H
#define GUI_H

#include "common.h"

void OpenLogViewer(BOOL bShow);
void OpenNodeManager();
void OpenNodeEditWindow(const wchar_t* tag);
void OpenSettingsWindow();
void ToggleTrayIcon();

#endif // GUI_H
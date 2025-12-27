#ifndef COMMON_H
#define COMMON_H

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <shellapi.h> // [Fix] for NOTIFYICONDATAW

// --- 基础配置 ---
#define CONFIG_FILE L"config.json"
#define MAX_SUBS 64
#define MAX_TOTAL_MEMORY_USAGE (512 * 1024 * 1024)

// --- 自定义消息与常量 ---
#define WM_LOG_UPDATE (WM_USER + 2) // [Fix] Added missing definition
#define REG_PATH_PROXY L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" // [Fix] Added missing definition

// 订阅结构定义
typedef struct {
    char url[512];
    int enabled;
} Subscription;

// --- 全局变量声明 ---

// 1. 路径与日志
extern wchar_t g_iniFilePath[MAX_PATH];
extern int g_enableLog;

// 2. 当前选中节点
extern wchar_t currentNode[64];

// 3. 动态节点列表
extern wchar_t** nodeTags;
extern int nodeCount;

// 4. ECH 配置
extern char g_echConfigServer[256];
extern char g_echPublicName[256];
extern int g_enableECH;

// 5. Crypto/分片/Padding 参数
extern int g_enableFragment;
extern int g_fragSizeMin;
extern int g_fragSizeMax;
extern int g_fragDelayMs;

extern int g_enablePadding;
extern int g_padSizeMin;
extern int g_padSizeMax;

extern int g_enableChromeCiphers;
extern int g_enableALPN;

// 6. User Agent
extern char g_userAgentStr[512];
extern int g_uaPlatformIndex;
extern const char* UA_TEMPLATES[];

// 7. 热键
extern unsigned int g_hotkeyModifiers;
extern unsigned int g_hotkeyVk;

// 8. GUI 状态 (供 config.c 使用) [Fix] Expose GUI globals
extern NOTIFYICONDATAW nid;
extern BOOL g_isIconVisible;

#endif // COMMON_H

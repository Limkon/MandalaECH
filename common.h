#ifndef COMMON_H
#define COMMON_H

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

// --- 基础配置 ---
#define CONFIG_FILE L"config.json"
#define MAX_SUBS 64

// 订阅结构定义
typedef struct {
    char url[512];
    int enabled;
} Subscription;

// --- 全局变量声明 ---

// 1. 路径与日志
extern wchar_t g_iniFilePath[MAX_PATH];
extern int g_enableLog;

// 2. 当前选中节点 (修复为 wchar_t 以匹配 config.c 的处理)
extern wchar_t currentNode[64];

// 3. 动态节点列表 (GUI与Config共享)
extern wchar_t** nodeTags;
extern int nodeCount;

// 4. ECH 配置 (全局共享)
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

// 注意：ProxyConfig, g_proxyConfig, g_proxyRunning 等已移动至 proxy.h
// 请勿在此处重复声明，否则会导致冲突。

#endif // COMMON_H

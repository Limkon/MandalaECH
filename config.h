#ifndef CONFIG_H
#define CONFIG_H

#include "common.h"
#include "cJSON.h"

// 注意：原有的全局变量 (g_localPort, g_proxyConfig 等) 已在 common.h 中声明
// 我们直接使用它们，不再重复声明

// --- 新增：订阅管理系统 ---
#define MAX_SUBS 20

typedef struct {
    BOOL enabled;   // 是否启用
    char url[512];  // 订阅地址
} Subscription;

extern Subscription g_subs[MAX_SUBS];
extern int g_subCount;

// 函数声明
void LoadSettings();
void SaveSettings();
void SetAutorun(BOOL enable);
BOOL IsAutorun();
void ParseTags();
void SwitchNode(const wchar_t* tag);
void ParseNodeConfigToGlobal(cJSON *node);
void DeleteNode(const wchar_t* tag);
BOOL AddNodeToConfig(cJSON* newNode);

// 协议解析辅助函数
cJSON* ParseVmess(const char* link);
cJSON* ParseShadowsocks(const char* link);
cJSON* ParseVlessOrTrojan(const char* link);
cJSON* ParseSocks(const char* link);

int ImportFromClipboard();
void ToggleTrayIcon();

// --- 新增：更新所有订阅 ---
int UpdateAllSubscriptions(BOOL forceMsg);

#endif // CONFIG_H

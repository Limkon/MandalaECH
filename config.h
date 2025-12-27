#ifndef CONFIG_H
#define CONFIG_H

#include "common.h"
#include "cJSON.h"

// --- 全局变量声明 (特定于 Config 模块) ---
extern Subscription g_subs[]; // 大小在 common.h 中定义
extern int g_subCount;

extern int g_subUpdateMode;
extern int g_subUpdateInterval;
extern long long g_lastUpdateTime;

// --- 函数声明 ---

void LoadSettings();
void SaveSettings();
void SetAutorun(BOOL enable);
BOOL IsAutorun();

void ParseTags(); // 从配置文件解析节点列表
void ParseNodeConfigToGlobal(cJSON *node);

void SwitchNode(const wchar_t* tag);
void DeleteNode(const wchar_t* tag);
BOOL AddNodeToConfig(cJSON* newNode); // 将单个节点写入 config.json

int ImportFromClipboard();
int UpdateAllSubscriptions(BOOL forceMsg);

void ToggleTrayIcon();

#endif // CONFIG_H

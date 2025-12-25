#ifndef CONFIG_H
#define CONFIG_H

#include "common.h"
#include "cJSON.h"

// 订阅更新模式常量
#define UPDATE_MODE_DAILY  0
#define UPDATE_MODE_WEEKLY 1
#define UPDATE_MODE_CUSTOM 2

// 订阅结构体
typedef struct {
    BOOL enabled;
    char url[512];
} Subscription;

#define MAX_SUBS 20
extern Subscription g_subs[MAX_SUBS];
extern int g_subCount;

// 自动更新配置
extern int g_subUpdateMode;
extern int g_subUpdateInterval;
extern long long g_lastUpdateTime;

// --- 配置加载与保存 ---
void LoadSettings();
void SaveSettings();

// --- 节点操作 ---
// 切换当前使用的节点
void SwitchNode(const wchar_t* tag);
// 将新节点添加到配置文件
BOOL AddNodeToConfig(cJSON* newNode);
// 删除指定节点
void DeleteNode(const wchar_t* tag);
// 解析配置文件中的所有 Tag (用于填充列表)
void ParseTags();
// 解析单个节点配置到全局变量 (用于连接)
void ParseNodeConfigToGlobal(cJSON *node);

// --- 导入与更新 ---
// 从剪贴板导入节点
int ImportFromClipboard();
// 更新所有订阅 (forceMsg=TRUE 时弹出提示框，否则静默)
int UpdateAllSubscriptions(BOOL forceMsg);

// --- 协议解析器 (内部使用，但也暴露以备测试) ---
cJSON* ParseVmess(const char* link);
cJSON* ParseShadowsocks(const char* link);
cJSON* ParseVlessOrTrojan(const char* link);
cJSON* ParseSocks(const char* link);
cJSON* ParseMandala(const char* link);

// --- 系统设置 ---
void SetAutorun(BOOL enable);
BOOL IsAutorun();

#endif // CONFIG_H

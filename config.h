#ifndef CONFIG_H
#define CONFIG_H

#include "common.h"

void LoadSettings();
void SaveSettings();
void SetAutorun(BOOL enable);
BOOL IsAutorun();

void ParseTags();
void ParseNodeConfigToGlobal(cJSON *node);
void SwitchNode(const wchar_t* tag);
void DeleteNode(const wchar_t* tag);
int ImportFromClipboard();
BOOL AddNodeToConfig(cJSON* newNode);
char* GetUniqueTagName(cJSON* outbounds, const char* type, const char* base_name);

// 解析函数
cJSON* ParseSocks(const char* link);
cJSON* ParseVmess(const char* link);
cJSON* ParseVlessOrTrojan(const char* link);
cJSON* ParseShadowsocks(const char* link);


#endif // CONFIG_H

extern char g_subUrl[512];
int UpdateNodesFromSubscription(const char* url);

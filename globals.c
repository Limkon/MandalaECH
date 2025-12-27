#include "common.h"
#include <stddef.h>

// --- 全局变量定义 ---

// 配置文件路径
wchar_t g_iniFilePath[MAX_PATH] = {0};

// 日志开关
int g_enableLog = 1;

// 当前选中的节点 Tag (修复类型错误: char -> wchar_t)
wchar_t currentNode[64] = {0};

// 动态节点列表缓存
wchar_t** nodeTags = NULL;
int nodeCount = 0;

// ECH 配置
char g_echConfigServer[256] = "https://cloudflare-dns.com/dns-query";
char g_echPublicName[256] = "";
int g_enableECH = 0;

// Crypto 参数
int g_enableFragment = 0;
int g_fragSizeMin = 10;
int g_fragSizeMax = 100;
int g_fragDelayMs = 2;

int g_enablePadding = 0;
int g_padSizeMin = 100;
int g_padSizeMax = 500;

int g_enableChromeCiphers = 1;
int g_enableALPN = 1;

// UA
char g_userAgentStr[512] = "";
int g_uaPlatformIndex = 0;

// 热键
unsigned int g_hotkeyModifiers = 0; 
unsigned int g_hotkeyVk = 0;      

// UA 模板
const char* UA_TEMPLATES[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
};

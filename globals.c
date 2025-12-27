#include "common.h"
#include <stddef.h>

// --- 全局变量定义 ---
// 注意：大多数特定模块的全局变量已移动到对应的 .c 文件中
// 这里保留的是真正通用的、跨模块共享的基础配置变量

// 配置文件路径
wchar_t g_iniFilePath[MAX_PATH] = {0};

// 日志开关 (默认开启，可在 config.c LoadSettings 中被修改)
int g_enableLog = 1;

// 当前选中的节点 Tag (用于 GUI 显示和配置保存)
char currentNode[64] = {0};

// 动态节点列表缓存 (由 config.c 解析和管理，GUI 读取)
wchar_t** nodeTags = NULL;
int nodeCount = 0;

// ECH 配置 (由于涉及 config.c 读取 和 proxy.c/crypto.c 使用，定义在此或 config.c 均可)
// 为了保持 crypto.c 的独立性，我们在此处定义，由 config.c 填充
char g_echConfigServer[256] = "https://cloudflare-dns.com/dns-query";
char g_echPublicName[256] = "";
int g_enableECH = 0;

// 碎片化与混淆参数 (核心 Crypto 参数)
int g_enableFragment = 0;
int g_fragSizeMin = 10;
int g_fragSizeMax = 100;
int g_fragDelayMs = 2;

int g_enablePadding = 0;
int g_padSizeMin = 100;
int g_padSizeMax = 500;

// Chrome 指纹模拟
int g_enableChromeCiphers = 1;
int g_enableALPN = 1;

// 用户代理
char g_userAgentStr[512] = "";
int g_uaPlatformIndex = 0;

// 热键配置 (由 GUI 注册，Config 加载)
unsigned int g_hotkeyModifiers = 0; // MOD_CONTROL | MOD_ALT
unsigned int g_hotkeyVk = 0;        // 'H'

// --- 预定义的 UA 模板 (常量) ---
const char* UA_TEMPLATES[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
};

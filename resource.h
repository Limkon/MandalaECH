#ifndef RESOURCE_H
#define RESOURCE_H

// --- 图标资源 ---
#define IDI_APP_ICON 1

// --- 设置窗口控件 ID (SettingsWnd) ---
#define ID_HOTKEY_CTRL      1101
#define ID_PORT_EDIT        1102
#define ID_CHK_CIPHERS      1103
#define ID_CHK_ALPN         1104
#define ID_CHK_FRAG         1105
#define ID_EDIT_FRAG_MIN    1106
#define ID_EDIT_FRAG_MAX    1107
#define ID_EDIT_FRAG_DLY    1108
#define ID_CHK_PADDING      1109
#define ID_EDIT_PAD_MIN     1110
#define ID_EDIT_PAD_MAX     1111
#define ID_COMBO_PLATFORM   1112
#define ID_EDIT_UA_STR      1113

// --- 节点编辑窗口控件 ID (NodeEditWnd) ---
// 注意：gui.c 中已经定义了 ID_EDIT_ECH_SNI (2050)
#define ID_EDIT_TAG         2201
#define ID_EDIT_ADDR        2202
#define ID_EDIT_PORT        2203
#define ID_EDIT_USER        2204
#define ID_EDIT_PASS        2205
#define ID_EDIT_NET         2206
#define ID_EDIT_TYPE        2207
#define ID_EDIT_HOST        2208
#define ID_EDIT_PATH        2209
#define ID_EDIT_TLS         2210

// --- 节点管理窗口控件 ID (NodeMgrWnd) ---
// 注意：gui.c 中已经定义了 ID_NODEMGR_SUB (2003)
#define ID_NODEMGR_LIST     3001
#define ID_NODEMGR_EDIT     3002
#define ID_NODEMGR_DEL      3003

// --- 日志窗口控件 ID (LogWnd) ---
#define ID_LOG_CHK          4001
#define ID_LOGVIEWER_EDIT   4002

#endif // RESOURCE_H

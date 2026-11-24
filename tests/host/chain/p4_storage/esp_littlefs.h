#pragma once
#include "esp_flash.h"
enum { ESP_FAIL = -1 };
struct esp_vfs_littlefs_conf_t { const char *partition_label, *base_path; bool format_if_mount_failed; };
bool esp_littlefs_mounted(const char *label);
int esp_vfs_littlefs_register(const esp_vfs_littlefs_conf_t *);

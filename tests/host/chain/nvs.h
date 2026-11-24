// NVS surface used by the phone and CLI storage tests.
#pragma once
#include <stdlib.h>
#include <stdint.h>
using nvs_handle_t = uint32_t;
using esp_err_t = int;
enum nvs_type_t { NVS_TYPE_U8 = 1, NVS_TYPE_U32 = 4, NVS_TYPE_BLOB = 0x42 };
int nvs_find_key(nvs_handle_t, const char *, nvs_type_t *);
struct nvs_stats_t { size_t used_entries, free_entries, available_entries, total_entries, namespace_count; };
int nvs_get_stats(const char *, nvs_stats_t *);
enum { NVS_READONLY = 0, NVS_READWRITE = 1, ESP_OK = 0, ESP_ERR_NVS_NOT_FOUND = 0x1102, ESP_ERR_NVS_TYPE_MISMATCH = 0x1103 };
int nvs_open(const char *, int, nvs_handle_t *);
void nvs_close(nvs_handle_t);
int nvs_commit(nvs_handle_t);
int nvs_set_blob(nvs_handle_t, const char *, const void *, size_t);
int nvs_get_blob(nvs_handle_t, const char *, void *, size_t *);
int nvs_get_u8(nvs_handle_t, const char *, uint8_t *);
int nvs_get_u32(nvs_handle_t, const char *, uint32_t *);
int nvs_set_u32(nvs_handle_t, const char *, uint32_t);

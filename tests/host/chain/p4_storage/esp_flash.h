#pragma once
#include <cstddef>
#include <cstdint>

struct esp_flash_t {};
struct esp_partition_t { esp_flash_t *flash_chip; uint32_t address, size; };
enum { ESP_PARTITION_TYPE_DATA = 1, ESP_PARTITION_SUBTYPE_DATA_LITTLEFS = 0x83 };
const esp_partition_t *esp_partition_find_first(int type, int subtype, const char *label);
int esp_partition_read(const esp_partition_t *, size_t offset, void *out, size_t size);
int esp_flash_get_physical_size(esp_flash_t *, uint32_t *size);
int esp_flash_get_size(esp_flash_t *, uint32_t *size);

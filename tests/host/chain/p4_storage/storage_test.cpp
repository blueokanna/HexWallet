// Drive the Board 7 backend through the token registry. Only the platform APIs are replaced.
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <mbedtls/platform_util.h>
#include "CryptoPrimitives.h"
#include "WalletCustomTokens.h"
#include "esp_littlefs.h"
#include "nvs.h"
#include "unistd.h"

namespace fs = std::filesystem;
using namespace hexwallet;
namespace {
#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "storage test line %d: %s\n", __LINE__, #expr); exit(1); } } while (0)
esp_flash_t chip;
esp_partition_t partition{&chip, 0x800000, 0x1800000};
uint32_t physical = 0x2000000, addressable = physical;
enum class Fault { None, PartitionRead, ShortWrite, Sync, Close, Replace };
Fault fault = Fault::None;
bool mounted, formatted, dirty_last_byte;
unsigned formats, nvs_reads;
size_t scanned;
std::vector<uint8_t> legacy;
fs::path scratch;
const uint8_t contract[20]{1};
fs::path local(const char *path) {
  CHECK(!strcmp(path, "/assets/tokens") || !strcmp(path, "/assets/tokens.tmp"));
  return scratch / (path + strlen("/assets/"));
}
bool reboot() { mounted = false; return custom_tokens_nvs_begin(); }
CustomTokenError update(const char *symbol) {
  return custom_token_add("eth", contract, sizeof(contract), symbol, "Test token", 18);
}
void expect(const char *symbol) {
  CHECK(custom_token_count() == 1);
  const auto *record = custom_token_find("eth", contract, sizeof(contract));
  CHECK(record && !strcmp(record->symbol, symbol) && record->decimals == 18);
}
}

const esp_partition_t *esp_partition_find_first(int type, int subtype, const char *label) {
  CHECK(type == ESP_PARTITION_TYPE_DATA && subtype == ESP_PARTITION_SUBTYPE_DATA_LITTLEFS && !strcmp(label, "assets"));
  return &partition;
}
int esp_partition_read(const esp_partition_t *p, size_t offset, void *out, size_t size) {
  CHECK(p == &partition && offset == scanned && size <= partition.size - offset);
  if (fault == Fault::PartitionRead) return ESP_FAIL;
  memset(out, 0xff, size);
  scanned += size;
  if (dirty_last_byte && scanned == partition.size) static_cast<uint8_t *>(out)[size-1] = 0;
  return ESP_OK;
}
int esp_flash_get_physical_size(esp_flash_t *p, uint32_t *size) { CHECK(p == &chip); *size = physical; return ESP_OK; }
int esp_flash_get_size(esp_flash_t *p, uint32_t *size) { CHECK(p == &chip); *size = addressable; return ESP_OK; }
bool esp_littlefs_mounted(const char *label) { CHECK(!strcmp(label, "assets")); return mounted; }
int esp_vfs_littlefs_register(const esp_vfs_littlefs_conf_t *conf) {
  CHECK(!strcmp(conf->base_path, "/assets") && !strcmp(conf->partition_label, "assets"));
  if (conf->format_if_mount_failed) { CHECK(scanned == partition.size && !dirty_last_byte); ++formats; formatted = true; }
  mounted = formatted;
  return mounted ? ESP_OK : ESP_FAIL;
}
int nvs_open(const char *name, int mode, nvs_handle_t *h) {
  CHECK(!strcmp(name, "hxctok") && mode == NVS_READONLY);
  *h = 1;
  return ESP_OK;
}
int nvs_get_blob(nvs_handle_t h, const char *key, void *out, size_t *size) {
  CHECK(h == 1 && !strcmp(key, "table") && *size >= legacy.size());
  ++nvs_reads;
  if (legacy.empty()) return ESP_ERR_NVS_NOT_FOUND;
  memcpy(out, legacy.data(), legacy.size());
  *size = legacy.size();
  return ESP_OK;
}
void nvs_close(nvs_handle_t h) { CHECK(h == 1); }

namespace hexwallet {
const NetworkProfile *find_network_profile(const char *id) {
  static const NetworkProfile eth{"eth", "ETH", "Ethereum", 60, 60, 44, {}, AddressEncoding::Evm};
  return !strcmp(id, "eth") ? &eth : nullptr;
}
void secure_zero(void *data, size_t size) { mbedtls_platform_zeroize(data, size); }
FILE *fopen(const char *path, const char *mode) { return ::_wfopen(local(path).c_str(), fs::path(mode).c_str()); }
int open(const char *path, int flags, int) {
  return ::_wopen(local(path).c_str(), flags | _O_BINARY, _S_IREAD | _S_IWRITE);
}
ssize_t write(int fd, const void *data, size_t size) {
  return ::_write(fd, data, static_cast<unsigned>(fault == Fault::ShortWrite ? size / 2 : size));
}
int fsync(int fd) { return fault == Fault::Sync ? -1 : ::_commit(fd); }
int close(int fd) { int status = ::_close(fd); return fault == Fault::Close ? -1 : status; }
int rename(const char *from, const char *to) {
  return fault != Fault::Replace && MoveFileExW(local(from).c_str(), local(to).c_str(), MOVEFILE_REPLACE_EXISTING) ? 0 : -1;
}
}

int main(int argc, char **argv) {
  if (argc == 2 && !strcmp(argv[1], "8mb")) {
    physical = addressable = 0x800000;
    partition.address = 0x7d0000;
    partition.size = 0x20000;
  } else {
    CHECK(argc == 1);
  }
  scratch = fs::temp_directory_path() / ("hexwallet-assets-" + std::to_string(GetCurrentProcessId()));
  CHECK(fs::create_directory(scratch));
  physical /= 2;
  CHECK(!reboot());
  physical *= 2;
  addressable /= 2;
  CHECK(!reboot());
  addressable *= 2;
  CHECK(scanned == 0 && formats == 0);
  fault = Fault::PartitionRead;
  CHECK(!reboot());
  fault = Fault::None;
  dirty_last_byte = true;
  CHECK(!reboot() && scanned == partition.size && formats == 0);
  CHECK(update("ERR") == CustomTokenError::StorageFailure);
  dirty_last_byte = false;
  scanned = 0;
  CHECK(reboot() && formats == 1 && custom_token_count() == 0);

  // Historical v1 layout: network, contract, symbol, name, decimals, truncated SHA-256.
  legacy.resize(6 + 16 + 20 + 12 + 24 + 1 + 8);
  memcpy(legacy.data(), "HXCT\1\1eth", 9);
  memcpy(legacy.data() + 22, contract, sizeof(contract));
  memcpy(legacy.data() + 42, "OLD", 3);
  memcpy(legacy.data() + 54, "Legacy token", 12);
  legacy[78] = 18;
  uint8_t digest[32];
  CHECK(crypto_sha256(legacy.data(), legacy.size() - 8, digest));
  memcpy(legacy.data() + legacy.size() - 8, digest, 8);
  CHECK(reboot());
  expect("OLD");
  fault = Fault::Replace;
  CHECK(update("NEW") == CustomTokenError::StorageFailure);
  CHECK(reboot());
  expect("OLD");
  fault = Fault::None;
  CHECK(update("NEW") == CustomTokenError::Ok);
  const unsigned reads_after_migration = nvs_reads;
  for (auto failure : {Fault::ShortWrite, Fault::Sync, Fault::Close, Fault::Replace}) {
    fault = failure;
    CHECK(update("LOST") == CustomTokenError::StorageFailure);
    expect("NEW");
    CHECK(reboot());
    expect("NEW");
  }
  fault = Fault::None;
  CHECK(custom_token_remove("eth", contract, sizeof(contract)) == CustomTokenError::Ok);
  CHECK(reboot() && custom_token_count() == 0 && nvs_reads == reads_after_migration);
  std::ofstream(local("/assets/tokens"), std::ios::binary | std::ios::trunc) << "incomplete";
  CHECK(!reboot() && update("ERR") == CustomTokenError::StorageFailure);
  CHECK(nvs_reads == reads_after_migration && formats == 1);
  fs::remove(local("/assets/tokens"));
  fs::remove(local("/assets/tokens.tmp"));
  CHECK(fs::remove(scratch));
  puts("p4-token-storage=pass (legacy NVS, first commit, four failed replacements, remount and corruption)");
}

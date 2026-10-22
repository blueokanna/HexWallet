# Arduino 工程布局

用 Arduino IDE 打开根目录的 HexWallet.ino。草图文件夹应命名为 HexWallet。

`src/generated/` 保存七个编译时包含的 `.inc` 文件。它们不是独立编译单元，由根目录 `.cpp` 使用 `#include "src/generated/文件名.inc"` 引入。请保留整个 src 目录；Arduino 打包时可随工程携带它。

`tools/` 是维护工具：币种目录生成、参考测试向量、UTXO 核验以及手机链路参考客户端。它不烧录进固件，但开发和 CI 需要，不能整体删除。

`tests/` 保存主机验证与交叉编译检查，不是链上交易验收的替代品。`build/`、对象文件和测试可执行文件属于可重新生成的构建产物。

主控为 ESP32-P4NRW32X。等 PCB 确定后，在 WalletBoardPins.h 的板级配置中填写真实 PN7161 SPI、IRQ、VEN 引脚，并提供屏幕/触控配置；不要使用测试里的合成引脚连接硬件。

功能完成度与未关闭的问题见根目录 AUDIT.md。

地址编码测试向量位于 `tests/fixtures/WalletForkAddressVectors.inc`，使用公开私钥 1，禁止收款。仅 HEXWALLET_HOST_TEST 构建包含该文件，设备固件不包含它。

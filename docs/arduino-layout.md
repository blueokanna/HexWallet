# Arduino 工程布局

用 Arduino IDE 打开根目录的 HexWallet.ino。草图文件夹应命名为 HexWallet。

`src/generated/` 保存编译时包含的数据文件。生产目录使用普通 `.inc` 名称，测试向量统一使用 `*Test.inc`。它们不是独立编译单元，由根目录 `.cpp` 显式包含；Arduino 打包时请保留整个 src 目录。

`tools/` 是维护工具：币种目录生成、参考测试向量、UTXO 核验以及手机链路参考客户端。它不烧录进固件，但开发和 CI 需要，不能整体删除。

已删除被固定版本参考构建取代的 `tests/reference/bp_plus_inputs.py` 和旧 `bp_plus_reference.ps1`。其他 Python 文件仍用于目录生成、链路测试、向量转换或审计，保留它们不会给设备增加网络功能。测试向量中的地址、掩码和秘密都是公开测试材料，禁止用于接收真实资产。

同时删除未被构建或测试引用的 `_masari_probe.py`：它是临时探针，使用普通 Base58 而非 CryptoNote 的分块编码，不适合作为地址正确性的依据。

`tests/` 保存主机验证与交叉编译检查，不是链上交易验收的替代品。`build/`、对象文件和测试可执行文件属于可重新生成的构建产物。

主控为 ESP32-P4NRW32X。等 PCB 确定后，在 WalletBoardPins.h 的板级配置中填写真实 PN7161 SPI、IRQ、VEN 引脚，并提供屏幕/触控配置；不要使用测试里的合成引脚连接硬件。

功能完成度与未关闭的问题见根目录 AUDIT.md。

地址编码测试向量位于 `tests/fixtures/WalletForkAddressVectorsTest.inc`，使用公开私钥 1，禁止收款。仅 HEXWALLET_HOST_TEST 构建包含该文件，设备固件不包含它。

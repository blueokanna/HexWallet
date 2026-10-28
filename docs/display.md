# HexWallet - display

## EPD 与 LVGL 刷新

*Merged from docs/epd-lvgl.md.*

### 已验证的硬件

`HEXWALLET_BOARD_T_DECK_MAX` 使用 Good Display **GDEQ031T10**（UC8253，240×320，
**黑白**，SPI）。仓库里的 GxEPD2 后端和 1bpp 转换只针对这个面板；不要把同名的“三色/
四色”面板当作已验证硬件。

### 刷新策略

- LVGL 使用 `LV_DISPLAY_RENDER_MODE_DIRECT` 全帧 RGB565 缓冲。一次屏幕重绘的所有
  `flush_cb` 只把帧标记为 dirty，不直接写屏。
- `board_display_service()` 在 `lv_timer_handler()` 之后调用 `eink_service()`；只有
  120 ms 内没有新的 flush 才提交一帧，避免页面切换触发多次慢刷新。
- 每次提交都是完整刷新（`refresh(false)`），不使用快速局刷。地址、金额和审批按钮的残影
  比刷新时间更重要；局刷只适合临时菜单，不适合本钱包的签名审阅页。
- 写屏前显式 `powerOn()`，刷新后 `powerOff()`；SPI 总线与 SD/LoRa 共享时由面板类保持 CS。
- RGB565 先按 `LV_COLOR_16_SWAP` 还原字节序，再转亮度；4×4 Bayer 阈值 8..248 做 1bpp
  抖动，避免小字号文字整块丢失。

### 三色/四色面板

`board_display_colors()` 返回 1/3/4，UI 主题据此选择红色/黄色强调色；但**当前
`WalletBoardPort.cpp` 只有 1bpp 写屏路径**。如果定义了
`-DHEXWALLET_EPD_COLORS=3` 或 `4` 而没有对应的 GxEPD2 3C/4C 驱动类，初始化会明确失败，
不会把彩色面板按黑白类驱动。

要接入三色/四色面板，必须提供：

1. 面板型号、控制器（例如 UC8253/UC8151）、有效分辨率、颜色排列（黑/白/红或
   黑/白/红/黄）与 BUSY 极性；
2. 对应的 GxEPD2 驱动类（3C/4C 模板）或完整初始化/LUT 序列；
3. 实际排线：SCK/MOSI/CS/DC/RST/BUSY，以及是否与 SD/LoRa 共用 SPI；
4. 面板要求的全刷/局刷时序和最小刷新间隔。

没有这些证据时，代码只能保持黑白路径并 fail-closed。当前没有把任何三色/四色面板标记为
已验证。

## Arduino 工程布局

*Merged from docs/arduino-layout.md.*

用 Arduino IDE 打开根目录的 HexWallet.ino。草图文件夹应命名为 HexWallet。

`src/generated/` 保存编译时包含的数据文件。生产目录使用普通 `.inc` 名称，测试向量统一使用 `*Test.inc`。它们不是独立编译单元，由根目录 `.cpp` 显式包含；Arduino 打包时请保留整个 src 目录。

`tools/` 是维护工具：币种目录生成、参考测试向量、UTXO 核验以及手机链路参考客户端。它不烧录进固件，但开发和 CI 需要，不能整体删除。

已删除被固定版本参考构建取代的 `tests/reference/bp_plus_inputs.py` 和旧 `bp_plus_reference.ps1`。其他 Python 文件仍用于目录生成、链路测试、向量转换或审计，保留它们不会给设备增加网络功能。测试向量中的地址、掩码和秘密都是公开测试材料，禁止用于接收真实资产。

同时删除未被构建或测试引用的 `_masari_probe.py`：它是临时探针，使用普通 Base58 而非 CryptoNote 的分块编码，不适合作为地址正确性的依据。

`tests/` 保存主机验证与交叉编译检查，不是链上交易验收的替代品。`build/`、对象文件和测试可执行文件属于可重新生成的构建产物。

主控为 ESP32-P4NRW32X。等 PCB 确定后，在 WalletBoardPins.h 的板级配置中填写真实 PN7161 SPI、IRQ、VEN 引脚，并提供屏幕/触控配置；不要使用测试里的合成引脚连接硬件。

功能完成度与未关闭的问题见根目录 AUDIT.md。

地址编码测试向量位于 `tests/fixtures/WalletForkAddressVectorsTest.inc`，使用公开私钥 1，禁止收款。仅 HEXWALLET_HOST_TEST 构建包含该文件，设备固件不包含它。


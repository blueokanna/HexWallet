# EPD 与 LVGL 刷新

## 已验证的硬件

`HEXWALLET_BOARD_T_DECK_MAX` 使用 Good Display **GDEQ031T10**（UC8253，240×320，
**黑白**，SPI）。仓库里的 GxEPD2 后端和 1bpp 转换只针对这个面板；不要把同名的“三色/
四色”面板当作已验证硬件。

## 刷新策略

- LVGL 使用 `LV_DISPLAY_RENDER_MODE_DIRECT` 全帧 RGB565 缓冲。一次屏幕重绘的所有
  `flush_cb` 只把帧标记为 dirty，不直接写屏。
- `board_display_service()` 在 `lv_timer_handler()` 之后调用 `eink_service()`；只有
  120 ms 内没有新的 flush 才提交一帧，避免页面切换触发多次慢刷新。
- 每次提交都是完整刷新（`refresh(false)`），不使用快速局刷。地址、金额和审批按钮的残影
  比刷新时间更重要；局刷只适合临时菜单，不适合本钱包的签名审阅页。
- 写屏前显式 `powerOn()`，刷新后 `powerOff()`；SPI 总线与 SD/LoRa 共享时由面板类保持 CS。
- RGB565 先按 `LV_COLOR_16_SWAP` 还原字节序，再转亮度；4×4 Bayer 阈值 8..248 做 1bpp
  抖动，避免小字号文字整块丢失。

## 三色/四色面板

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

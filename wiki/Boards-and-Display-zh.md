# 板卡与显示

[English](Boards-and-Display) · [首页](Home-zh)

当前图库包含 66 个状态、132 张独立 296 × 128 PNG，均由主机上的 LVGL 9.5.0 和固件面板转换代码生成。HTML 页可按语言筛选。审计记录列出了镜像摘要和待实测项目。[中英文逐格图库](UI-Gallery) · [HTML 图库](ui-gallery/index.html) · [本轮界面审计](UI-Audit-2026-11-24-zh)

引脚表在 `WalletBoardPins.h`，一块板一段，每个值都来自原理图或厂家引脚图。不根据板名猜引脚。

## 板型

| Id | 板子 | 面板 | 输入 | 说明 |
| --- | --- | --- | --- | --- |
| 1 | LilyGO T-Display S3 AMOLED | 240×536 RM67162，SPI | CST816S 触摸 | ESP32-S3，默认配置 |
| 2 | T-Display S3 AMOLED Plus | 同面板 | CST816S | AXP313A 电源管理，microSD 走第二条 SPI |
| 3 | T-Display S3 | 170×320 ST7789，8 位并口 | CST816S | 面板可用前必须拉高 `HEXWALLET_PIN_POWER_ON` |
| 4 | T-Deck Max | 240×320 GDEQ031T10 / UC8253，SPI | 未验证 | 只有 BOOT 键可用；触摸挂在 XL9555 后面，没有接线 |
| 5 | T-Echo Lite Kit | 176×192，SPI | TCA8418 键盘 | 只有 nRF52840 引脚表，本仓库没有 nRF52 编译目标 |
| 6 | 无屏 | 无 | BOOT：S3 GPIO0，P4 GPIO35 | 串口 CLI；默认拒绝缺少可信本地显示的签名批准 |
| 7 | HexWallet P4 rev A | 296×128 横屏，SSD1680 SPI | 确定、上一个、下一个、返回 | SE051C2HQ1 走 I²C，PN7161 走共享 SPI |

7 号板取自 EasyEDA 工程 `c26102103`；每个引脚注释都写明封装焊盘，上电前可以从 P4 数据手册重新推出 GPIO 列。
面板和 PN7161 共用 GPIO7（SCK）、GPIO8（MOSI）和 GPIO9（MISO）。面板只写，片选为 GPIO16；PN7161 的片选为 GPIO13，时钟为 1 MHz。两个驱动从同一入口初始化 SPI。墨水屏任务在等待 BUSY 时释放总线，NFC 可在显示传输之间通信。黑白屏按字节对齐转换 LVGL 重绘区域，跳过相同帧，连续 30 秒没有画面变化后休眠。

这份 rev A 主 PCB 的 USB1 D−、D+ 分别经 `DM`、`DP` 网络接到 U1 封装焊盘 24、25，U1 符号将它们映射为 GPIO22、GPIO23。P4 默认 USB Serial/JTAG 使用 GPIO24、GPIO25，高速 PHY 使用封装焊盘 49、50。这两对焊盘均未接到 USB1。要从这个接口使用原生 USB 枚举或 ROM USB 下载，需要改板接线。[乐鑫 USB PHY 引脚表](https://docs.espressif.com/projects/esp-iot-solution/en/latest/usb/usb_overview/usb_phy.html)

默认 ROM UART0 则在板上引出。标为 `TX` 的焊盘连接 U1 焊盘 69（GPIO37），`RX` 连接 U1 焊盘 70（GPIO38）。复位开关的器件位号为 `SW1`（EN），下载绑带开关为 `SW2`（GPIO35）。四个界面按键的器件位号是 `按键1` 至 `按键4`，它们使用的网络名恰好也叫 `SW1` 至 `SW4`。串口适配器需使用 3.3 V 逻辑、共地和收发交叉接线。[乐鑫 P4 硬件设计指南](https://docs.espressif.com/projects/esp-hardware-design-guidelines/en/latest/esp32p4/schematic-checklist-esp32p4.html)

## 墨水屏档位

2.9 寸是对角线，不是协议。P4 板必须显式选档：

| `HEXWALLET_EPD_PROFILE` | 面板 | 刷新 |
| --- | --- | --- |
| 0（默认） | SSD1680 黑白 128×296 | 全刷；局刷走控制器自带 OTP 波形 |
| 1 | SSD1683 类四色 128×296 | 2bpp，仅全刷，BUSY 低有效 |
| 2 | SSD1680 黑白 V2 | 局刷走 OTP，BUSY 高有效 |

驱动强制的规则：

- 需要调波形的板子在 pin 头里定义 159 字节 `HEXWALLET_EPD_PARTIAL_LUT`；前 153 字节写 `0x32`，
  后面依次是 EOPT、VGH、VSH1/VSH2/VSL、VCOM。只给波形不给电压的表会被拒绝——那是残影最常见的原因。
- 四色档必须提供 `HEXWALLET_EPD_COLOR_INIT` 初始化表。没提供时 `begin()` 直接失败并打印
  `ERR: e-paper panel did not initialise`，不会退化成一块看起来能用的灰屏。
- 全刷建立旧/新 RAM 基线，局刷结束后同步旧帧。首次更新，或八次局刷预算用完，强制全刷。
  局刷窗口必须按字节对齐。
- 黑白帧 1 表示黑，发给 SSD1680 RAM 时反转。传输失败会让面板状态失效，而不是留下半张图。
- 刷新超时是全刷 45 秒、局刷 4 秒。这是故障边界，不是实测耗时。

批准屏障只在刷新成功之后释放。BUSY 超时或 SPI 失败永远不算"交易已经显示"。

按屏幕在左、面向四个应用键的方向，PCB 背面从左至右为按键4（GPIO30，确定）、按键3（GPIO31，上一个）、按键2（GPIO32，下一个）、按键1（GPIO33，返回）。上一个和下一个可以滚动超过一屏的字段。确定先选中拒绝，切换到批准后需另行按住确定 750 毫秒，返回可直接拒绝。独立的 BOOT 键（GPIO35）负责运行时长按切换 USB 数据。实体装配方向有待实板核验。

板级初始化负责 `lv_init()`、LVGL 9 的毫秒时钟回调、显示设备和按键组。电子纸使用原生 RGB565 持久帧缓冲，彩屏使用 `RGB565_SWAPPED` 传输格式；禁用全局字节交换，避免局部刷新修改帧缓冲中未重绘的像素。初始化失败时释放已分配资源，重试不累积缓冲区。

## 摄像头

OV9281 是 MIPI CSI-2 传感器，控制走 SCCB。树里只有控制侧：`camera_probe()` 读 chip-id 寄存器，
返回四种状态之一——`NotConfigured`、`NoResponse`、`WrongSensor`、`PresentUnverified`。
没有"已支持"这种状态。

工程 c26102103 中位号为 `OV9281` 的接口与 U2、RTC 共用 GPIO10/11，接口的 2、3 脚分别接 SDA、SCL。CSI 时钟和两对数据线通过 R32–R37 接入接口。7 号板固件当前返回 `NotConfigured`。传感器上电、CSI 采集以及从实拍图像解码二维码仍待实板联调。

## QR 码

`QrCode.cpp` 是自带的编码器 + 1bpp 渲染器：byte 模式、版本 1–10（21×21…57×57）、ECC L/M/Q/H、
最多 271 字节，超出直接拒绝，不截断。钱包策略按 H → Q → M 降级，从不使用 L；连 M 都放不下时，
屏幕改为显示文本。

自检会解码自己的输出（格式信息、去掩码、去交织、RS 校验子、载荷逐字节一致）。这只能证明自洽，
不能证明扫得出来。另一个 host 检查会把每个版本/等级/掩码的矩阵与固定提交的 nayuki/QR-Code-generator
逐位比较——格式信息写反的码能骗过自检，骗不过手机。

收款页在横屏左侧、竖屏上方固定二维码，只允许详情区域滚动。二维码保留四模块静区，使用整数像素缩放。中英页面在原尺寸、缩小到 148×64，以及缩小到 222×96 后加 0.4 像素高斯模糊的测试中，ZXing 均读回完整的示例 ETH 地址。实机读距取决于取景、对焦和屏幕反光。[界面图库](UI-Gallery.md)

## 界面素材

- `CoinIcons` 将 166 份来源图标编译为 32×32 单色位图。网络别名共用图标，全部 214 个资产目录条目均验证过符号匹配。[图标来源和摘要](../assets/icons/sources.json)
- DeepSeek 伙伴在自己的页面内走动，可喂食、抚摸和玩耍。墨水屏按刷新就绪状态更新动作，空闲 30 秒后停更。P4 使用 PIE 复制对齐的精灵帧。较大的黑白屏更新走 PPA 分条旋转并使用 2D-DMA，初始化时用已知像素逐点校验，校验或传输失败时切回 CPU。
- LVGL 9.5.0，`lv_conf.h` 放在 sketch 根目录。必须定义 `LV_CONF_INCLUDE_SIMPLE`，否则 LVGL 不读它，
  界面用到的控件根本不会被编译进去。

## 许可证提示

4 号板链接 GxEPD2，而 GxEPD2 是 GPL-3.0。这和 `LICENSE` 的非商业条款存在真实冲突：4 号板的镜像是组合作品，
必须满足 GPL-3.0。P4 那条路径没有这个问题，因为它用的是仓库内的 SSD1680 驱动。详见 `NOTICE`。

## 尚未验证

冷屏首次全刷耗时、四色模拟参数、多次局刷后的残影、低温下的 BUSY 行为、休眠唤醒恢复、
PN7161 射频链路，都需要在实物上做台架测试。编译通过不等于屏幕能用。

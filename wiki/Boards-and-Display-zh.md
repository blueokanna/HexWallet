# 板卡与显示

[English](Boards-and-Display) · [首页](Home-zh)

引脚表在 `WalletBoardPins.h`，一块板一段，每个值都来自原理图或厂家引脚图。不根据板名猜引脚。

## 板型

| Id | 板子 | 面板 | 输入 | 说明 |
| --- | --- | --- | --- | --- |
| 1 | LilyGO T-Display S3 AMOLED | 240×536 RM67162，SPI | CST816S 触摸 | ESP32-S3，默认配置 |
| 2 | T-Display S3 AMOLED Plus | 同面板 | CST816S | AXP313A 电源管理，microSD 走第二条 SPI |
| 3 | T-Display S3 | 170×320 ST7789，8 位并口 | CST816S | 面板可用前必须拉高 `HEXWALLET_PIN_POWER_ON` |
| 4 | T-Deck Max | 240×320 GDEQ031T10 / UC8253，SPI | 未验证 | 只有 BOOT 键可用；触摸挂在 XL9555 后面，没有接线 |
| 5 | T-Echo Lite Kit | 176×192，SPI | TCA8418 键盘 | 只有 nRF52840 引脚表，本仓库没有 nRF52 编译目标 |
| 6 | 无屏 | 无 | 无 | 串口 CLI；签名需要打开主机确认的编译开关 |
| 7 | HexWallet P4 rev A | 128×296 SSD1680，SPI | 4 个按键（SW1–SW4） | SE051C2HQ1 走 I²C，PN7161 走共享 SPI |

7 号板取自 EasyEDA 工程 `c26102103`；每个引脚注释都写明封装焊盘，上电前可以从 P4 数据手册重新推出 GPIO 列。
面板和 PN7161 共用 SCK/MOSI/MISO，各自独立片选。

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

## 摄像头

OV9281 是 MIPI CSI-2 传感器，控制走 SCCB。树里只有控制侧：`camera_probe()` 读 chip-id 寄存器，
返回四种状态之一——`NotConfigured`、`NoResponse`、`WrongSensor`、`PresentUnverified`。
没有"已支持"这种状态。

rev A 上摄像头**没有接**：CSI 焊盘经过串联电阻，另一侧悬空；相机 FPC 所有焊盘都没有网络。
所以 `HEXWALLET_CAMERA_*` 一个都没定义，探测返回 `NotConfigured`。下一版只需在板级配置里补 SCCB 引脚，
探测就能用；CSI 收流仍然需要厂商寄存器表，树里没有，也不会去编。

## QR 码

`QrCode.cpp` 是自带的编码器 + 1bpp 渲染器：byte 模式、版本 1–10（21×21…57×57）、ECC L/M/Q/H、
最多 271 字节，超出直接拒绝，不截断。钱包策略按 H → Q → M 降级，从不使用 L；连 M 都放不下时，
屏幕改为显示文本。

自检会解码自己的输出（格式信息、去掩码、去交织、RS 校验子、载荷逐字节一致）。这只能证明自洽，
不能证明扫得出来。另一个 host 检查会把每个版本/等级/掩码的矩阵与固定提交的 nayuki/QR-Code-generator
逐位比较——格式信息写反的码能骗过自检，骗不过手机。

## 界面素材

- `CoinIcons` —— 32×32 1bpp 图标，从 CC0 素材打包，固件里没有图片解码器。
- `Mascot` / `MaidSprite` —— 审查界面的精灵动画，帧由 `tools/pack_maid_sprite.ps1` 打包。
- LVGL 9.5.0，`lv_conf.h` 放在 sketch 根目录。必须定义 `LV_CONF_INCLUDE_SIMPLE`，否则 LVGL 不读它，
  界面用到的控件根本不会被编译进去。

## 许可证提示

4 号板链接 GxEPD2，而 GxEPD2 是 GPL-3.0。这和 `LICENSE` 的非商业条款存在真实冲突：4 号板的镜像是组合作品，
必须满足 GPL-3.0。P4 那条路径没有这个问题，因为它用的是仓库内的 SSD1680 驱动。详见 `NOTICE`。

## 尚未验证

冷屏首次全刷耗时、四色模拟参数、多次局刷后的残影、低温下的 BUSY 行为、休眠唤醒恢复、
PN7161 射频链路，都需要在实物上做台架测试。编译通过不等于屏幕能用。

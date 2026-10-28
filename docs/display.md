# HexWallet - display

## EPD 与 LVGL 刷新

*Merged from docs/epd-lvgl.md.*

### 硬件事实（先把总线说清楚）

2.9 寸 128×296 墨水屏是 **SPI** 器件（SSD1680 及 UC8151 兼容批次），没有 MIPI DSI
接口。本项目里走 MIPI DSI 的是彩色屏（RM67162 / ST7789 那条路径）。如果新板子把墨水屏
挂在 MIPI 桥后面，只需要替换 `EinkBus` 的四个回调（command / reset / busy / delay），
命令序列一行都不用改。

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

## EinkPanel：2.9" 128×296 的独立驱动层

`EinkPanel.h/.cpp` 是与板级代码解耦的一层，命令序列、窗口算术、BUSY 超时和损坏区域
策略都在这里，`WalletBoardPort` 只提供四条总线回调。

### 为什么局刷要由板级配置决定

局刷不是“换个命令”那么简单：它需要一份**该批次面板的波形 LUT**（153 字节，每字节都
影响灰阶与残影），不同厂家/不同批次不能互换。所以 `EinkPanelConfig::partial_lut` 是板级
常量：

- 给了 LUT：`partial_refresh()` 先写 LUT（0x32），再设窗口、只推窗口内的数据、用
  `0x22=0xFF` + `0x20` 触发局刷。
- 没给 LUT：直接返回 `PartialUnsupported`，**绝不**降级成“假装局刷、实际全刷”——那会
  让上层以为局刷可用，从而把高频小区域刷新放到屏上，最终拖慢整个审阅流程。

拿不到 LUT 之前，全刷是唯一诚实的路径。

### 失败必须是失败

- BUSY 在超时内不释放 → `BusyTimeout`，上层必须把 `g_display_ready` 置 false；一张
  没画完的地址页不能允许按 APPROVE。
- 窗口不合法、起点不按字节对齐、缓冲区不足 → 直接拒绝，不推半帧。
- 局刷预算（默认 8 次）用尽后 `full_refresh_due()` 为 true，由上层安排一次全刷清鬼影。

### 损坏区域（EinkDamage）

LVGL 每次只告诉我们哪块被重绘。`EinkDamage` 累积这些矩形并给出并集：

- 并集面积超过面板的阈值（默认 15%）→ `prefers_full_refresh()` 为真，局刷已经省不下时间；
- 矩形超过 16 个 → 直接塌缩成整屏，宁可全刷也不丢更新；
- 所有矩形都裁剪到面板边界，越界不会写到缓冲区之外（自检里覆盖了贴边裁剪）。

## ESP32-P4 板（`HEXWALLET_BOARD=7`）

引脚不是猜的，是从 EasyEDA Pro 工程 `c26102103`
（`ProPrj_c26102103_2026-10-28.epro2`，按 zip 解开后读 `.epru` 里的 `PAD_NET` 与网络名）
导出来的。网络名与封装焊盘号可以逐条核对；**GPIO 编号在工程文件里并不存在**，是按
ESP32-P4 数据手册的焊盘表换算的，第一次上电前请对照手册再确认一遍。

| 功能 | 网络 | 焊盘 | 引脚 |
| --- | --- | --- | --- |
| 墨水屏 SCK | SPI_CLK | 7 | GPIO7 |
| 墨水屏 MOSI | SPI_MOSI | 8 | GPIO8 |
| 共享 MISO（PN7161 用） | SPI_MISO | 10 | GPIO9 |
| 墨水屏 CS | EINK_CS | 17 | GPIO16 |
| 墨水屏 DC | EINK_DC | 20 | GPIO19 |
| 墨水屏 RST | EINK_RST | 18 | GPIO17 |
| 墨水屏 BUSY | EINK_BUSY | 19 | GPIO18 |
| SE051 SDA | 050_SDA | 11 | GPIO10 |
| SE051 SCL | 050_SCL | 12 | GPIO11 |
| SE051 RST | 050_RST | 13 | GPIO12 |
| PN7161 NSS | SPI_NSS | 14 | GPIO13 |
| PN7161 IRQ | IRQ | 15 | GPIO14 |
| PN7161 VEN | VEN | 16 | GPIO15 |
| 按键 SW1..SW4 | SW1..SW4 | 64/63/61/60 | GPIO33/32/31/30 |
| 电池采样 | BAT_ADC | 22 | GPIO20 |

必须说清楚的硬件事实：

- **MIPI DSI 没接**。工程里 ESP32-P4 的 DSI 焊盘（35–40）一个网络都没有；墨水屏走 SPI，
  所以这块板不存在“MIPI 墨水屏”路径，也没有为它写任何代码。
- 2.9 寸裸屏排线（26 pin）上的 `GDR` / `RESE` / `PREVGH` / `PREVGL` 只连到无源网络，没有
  任何 GPIO。板上没有可软件控制的升压/栅极使能，代码里也就不会虚构一个。
- 面板与 PN7161 共用 SCK/MOSI/MISO、各自独立 CS；`epd_write_command()` 把一次“命令+数据”
  包在同一个 `SPI.beginTransaction()` 里，CS 全程拉低，不会和 NFC 抢总线。
- SE051 走独立的 `Wire1`，且先拉 `050_RST` 复位：热复位后的卡可能停在上一次会话的状态里，
  一个“能应答 ATR 但状态不对”的卡不算可用。
- 电池分压 R11/R12 在工程里是同一个器件 id（等值），所以共用的 1:2 换算对这块板成立。

### 局刷在这块板上的真实状态
`HEXWALLET_EPD_PARTIAL_LUT` 目前**没有定义**，所以 `EinkPanel` 对这块板返回
`PartialUnsupported`，每次提交都是全刷。这不是没写完：缺的是一份只能由面板批次提供的
153 字节波形 LUT。拿到后在板级配置里加一行
`#define HEXWALLET_EPD_PARTIAL_LUT <symbol>`，局刷路径（只推窗口数据、预算内局刷、超预算
自动全刷清鬼影）立刻生效；`EinkDamage` 已经按 LVGL 的脏矩形并集算好了窗口和“该不该全刷”。

## 摄像头 OV9281（SCCB 探测到位，CSI 流未实现）

OMNIVISION OV9281 是 **MIPI CSI-2** 器件（1280×800 全局快门，8/10-bit RAW），
寄存器走 **SCCB**（OmniVision 的 I2C 变体，写地址 0x60）。它能做的事分两层：

| 层 | 状态 |
| --- | --- |
| SCCB 读寄存器、读 chip ID（0x300A/0x300B → 0x9281） | **已实现**，`CameraPort.cpp`，主机自检覆盖 ACK/NAK/错型号/缺回调 |
| CSI-2 收流、ISP、解 QR | **未实现**。需要模组厂商的寄存器表 + `esp_cam_ctlr` CSI 配置 |

第二层没有写，是因为没有寄存器表就只能编一张，编出来的相机返回噪声；把噪声当“扫到的
地址”比明确说“没有相机”危险得多。`camera_probe()` 的返回值和 NFC/SE 一样是四分状态：
`NotConfigured` / `NoResponse` / `WrongSensor` / `PresentUnverified`，**没有**“已支持”这种
说法。

### 这块板子上的摄像头接了吗

没有。工程 `c26102103` 里可以逐条对上：

- ESP32-P4 的 CSI 焊盘 42–48 有网络，但都只接到串联电阻 R31–R37，电阻另一侧没有连接器；
- 板上的相机 FPC（26 pad，位号 `be25a532e5d3def2`）**所有焊盘都没有网络**；
- OV9281 只出现在丝印/文本层（`Designator: OV9281`），没有 SCCB、没有 MCLK、没有
  RST/PWDN 连到 P4。

所以 `HEXWALLET_CAMERA_*` 一个都没定义，`board_camera_probe()` 在这块板上返回
`NotConfigured`。等下一版把 SCCB 与 CSI 接出来以后，只需要在板级配置里补
`HEXWALLET_CAMERA_SCCB_SDA/SCL`，探测路径立刻可用；CSI 收流仍需要厂商寄存器表。

## QR 码

`QrCode.h/.cpp` 自带编码器与 1bpp 渲染器，不依赖第三方库：

| 项目 | 支持范围 |
| --- | --- |
| 版本 | 1–10（21×21 … 57×57） |
| 纠错 | L、M |
| 模式 | byte（地址、xpub 指纹、配对码） |
| 容量 | v1-L 17 字节 … v10-L 271 字节（v10-M 213） |
| 拒绝 | 空载荷、超出容量（绝不截断）、版本不在表内 |

**为什么要做到 v10，而不是停在 v3。** v3-L 只有 53 字节，Kaspa 地址
（`kaspa:q…`，70+ 字符）、IOTA bech32、带 memo 的 URI 全部放不进去。真机地址里最长的一类
必须能编码，否则“支持 QR”只是对小字符串成立。v4 起有多 RS 块，v7 起要写版本信息块，
这两块都在这里实现了，没有跳过。

块结构与交织是最容易写错的地方，所以校验分两层：

1. **自检**（设备与主机都跑）：读回矩阵 → 重解两份格式信息 → 反掩码、反 zigzag →
   **反交织**成各块的数据+EC → 每块 RS 校验子必须为零 → 解析 byte 模式头并把载荷逐字节
   比对。v1–v10 × L/M 每个组合都用“刚好装满容量”的载荷跑一遍，还要证明多一个字节会被拒绝。
2. **交叉校验**（`tests/host/qr_cross_check.ps1`）：自检只能证明“编码器和自己的解码器
   一致”，而**格式信息两份写反**这种 bug 恰恰是自洽但扫不出来的。这个脚本把
   `QrCode.cpp` 与 nayuki/QR-Code-generator（固定 commit）编进同一个二进制，逐个模块
   比对 v1–v10 × L/M × mask 0–7 共 160 个矩阵。当前结果：`cases=160 mismatches=0`。

这一步真的抓到过东西：此前 v1–v3 的实现把格式信息第一份的纵向/横向两半调换了，符号
“看起来像 QR 码”，实际扫不出来。修法是把 bit 0–5 放到 8 列（列 8 向下），bit 9–14 放到
第 8 行向左——参考实现就是这么摆的。

**仍然没有验证的事情**：真机扫描器。上线前必须用手机扫一张屏上的码——这一步只能你在
台面上做，我不会写成“已验证”。

### 屏上的 QR 是怎么画的

`nothing_qr()` 把矩阵写进 LVGL 的 **I1（1bpp）canvas**，调色板只有纸色和墨色两项，
再用**整数倍** `lv_image_set_scale` 放大：非整数缩放会让模块落在半像素上，在墨水屏上
就是一片灰糊，扫不出来。canvas 的 stride 用 `lv_draw_buf_width_to_stride()` 取，不自己
猜对齐规则。像素缓冲与 `QrCode`（3.3 KiB）都是静态的——一个屏幕只有一个码，不该为此
在栈上再开一份。

地址超长或编码失败时**不画半截图**，而是显示 `QR UNAVAILABLE - USE ADDRESS`：宁可让用户
手抄地址，也不能给出一个扫出来是别的内容的码。


## 视觉语言（1bpp 下的 "Nothing" 风格）

墨水屏只有黑白，不能靠渐变或半透明表达层次。可用的手法只有三种，规则也就三条：

1. **纯黑 #000 / 纯白 #FFF**，没有第三种颜色。层次靠留白和线宽，不靠灰。
2. **点阵装饰**：标题下方用 1 像素点阵带（`• • • •`），与 Nothing 的点阵字形同构；
   点阵密度就是“层级”。
3. **分段计量条**：金额、进度用等宽分段（例如 12 段），段与段之间留 1 像素白缝。
   它在 1bpp 下没有抗锯齿问题，比实心条更清晰。

字体只用两档：地址/金额用等宽（逐字符核对），标签用无衬线大写 + 字距加宽。不要用
斜体，1bpp 斜体在 128 像素宽上会糊成一团。

### 代码里的三个原语

`WalletUi.cpp` 把这套语言收敛成三个函数，屏幕代码只组合它们，不各自发明样式：

| 原语 | 作用 |
| --- | --- |
| `nothing_dot_band(parent, n)` | 标题上方的点阵带，圆点直径与间距都走 `sc()` |
| `nothing_rule(parent)` | 1 px 分隔线，用来断开“标题 / 内容” |
| `nothing_micro_label(parent, text, accent)` | 大写小标签，字距 `sc(2)`，强调色只给必要的一处 |

地址还有两条硬规则：

- **每 4 个字符插一个空格**（`nothing_group_address()`）。地址本身不变，但人眼核对
  时分组比一整行 62 个字符快得多，也更容易发现抄错的位置。
- 地址块用 1 px 强调色边框单独框起来，禁止省略号与横向滚动——被截断的地址是资金事故。

审阅页同样是点阵带 + 强调色标题 + 1 px 分隔线的组合，金额和地址各自独占整行宽度，
不让长金额把目标地址挤掉。

## LVGL 许可

LVGL 从 v8 起就是 **MIT**：可以商用、可以闭源分发、个人开发者不需要购买任何授权。
`lvgl.io/open` 讲的是他们的商业模式（开源版 + 可选商业支持），不改变 MIT 的授权事实；
仓库里使用的 LVGL 9.5 就是 MIT 版本。只要保留版权与许可声明即可，没有 per-seat 费用。

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

`tools/` 只剩三份数据快照（`fork_registry.json`、`miningpoolstats_coin_list.json`、
`miningpoolstats_graveyard.json`），由 `tests/host/policy_check.ps1` 读取，不烧进固件。
仓库里没有 Python/Node 工具链：目录生成和策略校验都是 PowerShell 加 C++ 自检，CI 同样
不需要它们。

测试向量里的地址、掩码和秘密都是公开测试材料，禁止用于接收真实资产。`tests/` 保存主机
验证与交叉编译检查，不是链上交易验收的替代品；`build/`、对象文件和测试可执行文件属于
可重新生成的构建产物。

主控为 ESP32-P4NRW32X。PN7161 的 SPI/IRQ/VEN 引脚已按工程网络写进板级配置（见本文的
引脚表），不要用测试里的合成引脚去连硬件；合成引脚只用于让 NFC 代码在主机上被编译到。
功能完成度与未关闭的缺口见 [chain-support.md](chain-support.md) 与 [security.md](security.md)。

地址编码测试向量位于 `tests/fixtures/WalletForkAddressVectorsTest.inc`，使用公开私钥 1，禁止收款。仅 HEXWALLET_HOST_TEST 构建包含该文件，设备固件不包含它。


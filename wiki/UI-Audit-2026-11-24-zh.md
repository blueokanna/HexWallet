# 2026-11-24 · 7 号板双语界面审计

[English](UI-Audit-2026-11-24) · [逐格图库](UI-Gallery) · [板卡与显示](Boards-and-Display-zh)

7 号板的 296 × 128 横屏图库包含 **66 个状态、132 张主机渲染图**。LVGL 9.5.0 运行固件 `WalletUi.cpp`，再由 `eink_pack_landscape()` 转换为控制器帧。创建与恢复画面使用公开样例和模拟托管。生产会话仍返回 `CustodyUnavailable`。

## 画面与交互

每个状态均有独立的中英文 296 × 128、1 bpp 原图。HTML 页可按语言筛选，Markdown 页可查看逐屏原图和九张总览。[HTML 图库](ui-gallery/index.html) · [Markdown 图库](UI-Gallery)

BIP39 画面覆盖选择词表和词数、抄写、重输、附加密码选择及本地确认。比特币备份画面覆盖选网络、输入、后台处理、核对地址及 NFC 读标签提示。图库还包含主页、设置、资产布局、伙伴互动、收款、交易审阅与决定、配对和动态验证码。收款与审阅各有滚动位置可供对照。

屏幕在左时，应用键按确定、上一个、下一个、返回排列；位号 SW1、SW2 与电源开关不参与应用操作。菜单当前项为黑底白字。交易和配对先聚焦正文，上下键滚动；确定先进入拒绝选项，切换至批准后须另行长按确定 750 ms，返回可拒绝。显示未提交时不能交付批准回调，同一回调最多交付一次。

主页的 `Language / 语言` 允许切换 English 和简体中文。偏好只保存在 RAM，重启默认英文；活动审阅、配对、OTP 或待处理决定期间拒绝切换。收款地址、金额、指纹、memo、calldata、账户名及代币符号保持原文。只有明确标为固件标签的归属字段才翻译，外部账户即使恰好名为 `EXTERNAL` 也不会被改成“外部收款”。

## 已发现并修复

| 问题 | 修复与检查 |
| --- | --- |
| 英文主页按钮可用高度 14 px，小于字体行高 15 px | 菜单按钮改为 22 px；逐标签检查按钮内容区高度。主页菜单只显示完整的三行。 |
| 配对指纹经固定缓冲区可能截断 | 完整指纹直接交给换行标签；220 字符回归及滚动检查。 |
| 串口确认码页和配对正文缺少四键阅读焦点 | 加入正文焦点与滚动，确认码和校验码可到达底部。 |
| 批准回调可重复触发，刷新未完成时决定可能过早交付 | 一次性交付、等待显示提交，短按、长按、返回及重复长按回归。 |
| 新审阅输入无效时可能遗留旧画面 | 改为拒绝画面并撤销旧授权；超长字段、过多输出、随机源失败均不能授权。 |
| 缺失字形、无效 UTF-8 或方向控制符可让所见与原文不符 | 构造审阅校验码前核对全部被纳入审阅的文字；不可完整渲染时禁止授权。无效配对数据也拒绝。 |
| 资产点击只有短状态，长名称和空目录导航不足 | 可滚动详情、名称换行、分页边界保护和空态焦点。Ryo/Zano 截图夹具按发布门控显示签名不可用。 |
| 长状态挤占正文，超长地址无 QR 时留下空占位 | 普通长状态移入滚动正文；无 QR 时移除其空列，保留完整地址和派生路径。 |
| 显示接口失败后 OTP 内存未清除 | 清零验证码并清除显示与授权状态。 |
| 通用签名审阅入口将超限输出数截至数组大小 | 改为拒绝完整请求，禁止只展示部分输出。 |
| 收款二维码占屏面积偏小 | 使用完整屏高、四模块留白和整数模块；优先较大模块，拒绝单像素模块；保留完整地址及派生路径滚动。 |
| 资产图标共用可变缓冲区 | 每个 canvas 独立分配并释放 LVGL draw buffer。测试核对图标隔离和连续 16 次页面重建，目录策略逐项检查图标查找结果。 |
| 横屏伙伴操作缺失 | 主页提供伙伴入口，可喂食、抚摸、玩耍和吹泡泡，复用角色精灵。 |

## 已执行的验证

| 验证层 | 结果与范围 |
| --- | --- |
| MSVC Release，真实 LVGL | 中英文导航、两套画面、P4 两种 SPI 初始化顺序、S3 显示生命周期及 PN7161 Type 4 读取，共 **8/8 通过**。 |
| Clang 21 / Swift 6.4.2，ASan + UBSan | C 与 C++ 使用 `-fsanitize=address,undefined -fno-sanitize-recover=all`，共 **8/8 通过**。 |
| 帧一致性 | 两套构建的 132 个 PBM 逐字节一致。布局检查覆盖字形、标签宽度、按钮文字高度、正文高度与水平溢出。 |
| 独立二维码读回 | ZXing-C++ 从中英收款页首、中、末共六帧读回 `0x70997970C51812dc3A010C7d01b50e0d17dc79C8`。每帧均通过原尺寸、222 × 96 加高斯模糊及 148 × 64 三种采样。 |
| Chromium 图库检查 | 132 张图均按原尺寸解码。360、768、1366 px 三种视口下，筛选分别显示英文 66 张、中文 66 张及全部 132 张，均无水平溢出。 |
| 字库复现 | 固定 Noto 源与 `lv_font_conv@1.5.3` 重建了 7,538 个中文字形及标点。生成字体及字符清单逐字节一致。 |
| 比特币备份与 BIP39 | 原生测试使用真实 scrypt、AES 及 secp256k1。9 个 BIP38 官方恢复向量通过，含 Unicode 与嵌入 NUL 的密码。直接加密复现 5 个官方备份串。BIP39 三套词表、五种长度的词句和种子均与 ethers 一致。 |
| NFC 标签输入 | 实际 PN7161 驱动在模拟 SPI/NCI 控制器上分块读取 NFC-A Type 4、mapping v2 的 NDEF Text，移卡后清除已收数据并恢复手机 APDU 服务。支持的文本内容为 BIP38、WIF 和十六进制私钥。 |
| 签名相关主机回归 | 重建 `chain_probe`、`production_policy`；安全回归、`signing-audit all`、生产托管拒绝策略及协议 SDK 对照通过。EVM 62 配置的 82 个原生转账签名匹配 ethers；另有 Solana、Cosmos 和广播适配器检查。该轮没有重新提交节点交易。 |
| 7 号板固件 | Arduino-ESP32 3.3.13、P4 post-v3、32 MiB Flash、LVGL 9.5.0 构建成功，芯片版本、分区、组件偏移与 ELF 摘要通过脚本检查。 |

UI 测试使用模拟的显示提交标志、随机源和 review seal；协议探针使用真实密码实现但模拟显示与批准。两者不能替代端到端实板绑定、实卡签名或侧信道测量。测试允许用户主动切换至决定区，没有证明用户读过每一行。

编译器报告程序空间 2,248,800 字节，静态内存 245,496 字节，运行时分配前的内部内存余额为 82,184 字节。两个 OTA 槽各 3,932,160 字节，后 24 MiB 为 `assets`。ELF 含 P4 PIE 精灵复制、PPA 旋转及 SDK 的 `dma2d_start`。调用次数、独立 2D-DMA 使用及性能收益仍需实测。

| 产物 | 字节数 | SHA-256 |
| --- | ---: | --- |
| `HexWallet.ino.merged.bin` | 8,388,608 | `624f5a27c9cd144aa031172dc03cac2b2a38690cf6710435b65c49c5944d5998` |
| `HexWallet.ino.bin` | 2,249,536 | `9bf81d695d1dc2c8fff16b99c6f7f1bcb826592cc5dc5b47bf023b37baba39d2` |
| `HexWallet.ino.elf` | 22,189,732 | `6c100550cca3e9dcac25c4155e924f6a7a89ce5eb49767da555cd96e34106ae8` |
| [图片摘要清单](ui-gallery/manifest.json) | 41,349 | `fad6a54c53170563f89bd1811687d675d6b93d918c3d39fbc1424efe85ba79a0` |

这是本地未提交工作区的产物标识；尚未刷机或发布。旧 `P4-Review.png` 是此前十二幅画面的历史证据，当前 UI 以新图库为准。

## 复现

在仓库根目录执行，先按 `assets/fonts/README.md` 准备固定字库源和转换器：

```powershell
python tools/generate_ui_font.py --check
powershell -ExecutionPolicy Bypass -File tests/host/ui_check.ps1
python -m pip install Pillow==12.3.0 zxing-cpp==2.3.0
python tests/host/ui/export_panel.py build/ui-test/panel-frames wiki/ui-gallery --markdown wiki/UI-Gallery.md
```

本轮实际构建目录为 `build/audit-ui` 与 `build/audit-ui-sanitized`；导出时加 `--compare build/audit-ui-sanitized/panel-frames` 核对两套帧。Windows clang-cl 需让编译器资源目录中的 `lib/x86_64-unknown-windows-msvc` 可用于链接及 DLL 查找，测试前将其加入 `PATH`。这轮使用 MSVC 开发者环境、Ninja Multi-Config 和该目录下的 ASan DLL。

UI 日志位于 `build/audit-ui/Testing/Temporary/LastTest.log` 与 `build/audit-ui-sanitized/Testing/Temporary/LastTest.log`。上表的 32 MiB 固件构建记录在 `build/audit-logs/nfc-backup-p4.log`。将 `tests/host/protocol-oracles/node_modules` 加入 `NODE_PATH` 后，执行 `node tests/host/key_backup_check.cjs build/audit-native/Release/chain_probe.exe` 可复现备份向量、工作任务取消和分配失败检查。探针在释放 scrypt 工作区前逐字节检查清零。中英文 UI 测试均提交了五种长度的公开英文词句，并覆盖任务完成后锁屏或显示故障。

文档检查发现四张旧需求原图在当前工作区缺失，已在能力核对页注明文件名并保留逐项核对记录；没有用新绘制的 UI 图片代替原图。图库发布脚本已加入 `ui-gallery` 附件目录复制，本轮未执行发布。

## 尚未达到的要求

| 范围 | 当前状态 |
| --- | --- |
| 全部界面内容双语 | 横屏菜单、备份输入和伙伴动作均有中英文。部分协议详情、长警告及竖屏文案仍为英文。字库覆盖随附拼音字典和中文助记词表，账户名仍可能含缺失字形。 |
| 独立创建、恢复及扫码 | 主机以模拟托管测试四键 BIP39 创建及恢复。本地比特币备份流程可返回 P2PKH 地址或加密备份。SE051 签名凭据导入、NFC 初配以及 CSI 取帧和解码仍待贯通。 |
| SE051C2HQ1 与凭据存储 | I²C 移植层通过主机测试及 P4 编译。固定版本 SDK 的扩展 PBKDF2 受 `SSS_HAVE_SE05X_VER_GTE_07_02` 控制。实卡 applet、权限、不可导出的 BIP32 派生及各链签名仍需验证。此镜像的 SDK 关闭了 Secure Boot、Flash Encryption 及 NVS Encryption，`board_credential_storage_ready()` 拒绝生产凭据存储。 |
| 实物操作和性能 | COM6 枚举为 Espressif USB JTAG/serial debug unit（`303A:1001`）。以 115200 波特率被动读取三秒，收到完整行数为零。板型、按键安装方向、残影、相机、NFC 射频、共享总线时序、电流、运行时内存及手机到卡签名再广播仍待实测。 |
| 全链安全 | 目录 214/214 是地址派生及登记证据，不是所有交易、卡内签名或节点验收的通过数；逐链缺口见[能力核对](Capability-Review-zh)。 |

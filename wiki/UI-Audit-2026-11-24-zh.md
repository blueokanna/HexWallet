# 2026-11-24 · 7 号板双语界面审计

[English](UI-Audit-2026-11-24) · [逐格图库](UI-Gallery) · [板卡与显示](Boards-and-Display-zh)

本轮完成了 7 号板 296 × 128 横屏界面的修改和主机验证，交付 44 个状态、88 张独立 PNG。所有画面来自固件 `WalletUi.cpp` 的 LVGL 9.5.0 绘制，再经过 `eink_pack_landscape()` 的墨水屏帧转换。它们使用公开测试夹具，不是实物照片。**这次验收不代表钱包全部功能、全部链或实卡签名已经完成。**

## 画面与交互

[打开 HTML 筛选图库](ui-gallery/index.html)；[Markdown 逐格图库](UI-Gallery) 为每个中英文画面保留独立单元格，适合在仓库或 wiki 中浏览。原始 PNG 为 296 × 128、1 bpp。六张总览各有明确边框、间隔及中英标题：[1](ui-gallery/overview-1.png) · [2](ui-gallery/overview-2.png) · [3](ui-gallery/overview-3.png) · [4](ui-gallery/overview-4.png) · [5](ui-gallery/overview-5.png) · [6](ui-gallery/overview-6.png)。

覆盖主页及语言入口、语言选择、按键说明、创建与恢复的方式选择及说明页、扫码不可用、目录翻页与空态、资产详情、收款与长地址、交易审阅与决定、串口确认码、错误及拒签、配对、动态验证码、忙碌和长状态。滚动状态包含部分字段的首屏、滚动中与底部；44 个状态不等于 44 个独立功能。

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

## 已执行的验证

| 验证层 | 结果与范围 |
| --- | --- |
| MSVC Release，真实 LVGL | `ui`、`ui_zh`、`ui_frames_en`、`ui_frames_zh`、P4 两种 SPI 初始化顺序及 S3 显示生命周期，共 **7/7 通过**。 |
| Clang 21 / Swift 6.4.2，ASan + UBSan | C 与 C++ 均使用 `-fsanitize=address,undefined -fno-sanitize-recover=all`，同样 **7/7 通过**。 |
| 帧一致性 | 两套构建的全部 88 个 PBM 逐字节一致，再导出独立 PNG。逐标签检查字形、标签宽度、按钮文字高度、正文高度与水平溢出。 |
| 独立二维码读回 | ZXing-C++ 从中英文收款首屏均读回 `0x70997970C51812dc3A010C7d01b50e0d17dc79C8`。 |
| Chromium 图库检查 | 88 张图片均加载且原始尺寸正确；筛选分别显示英文 44 张、中文 44 张或全部 88 张。360、768、1366 px 视口下均无水平溢出。 |
| 字库复现 | 固定 Noto 字体与 `lv_font_conv@1.5.3` 重新生成 304 字形，`--check` 逐字节匹配生成文件和字符清单；OFL 许可证及来源已保存。 |
| 签名相关主机回归 | 重建 `chain_probe`、`production_policy`；安全回归、`signing-audit all`、生产托管拒绝策略及协议 SDK 对照通过。EVM 62 配置的 82 个原生转账签名匹配 ethers；另有 Solana、Cosmos 和广播适配器检查。该轮没有重新提交节点交易。 |
| 7 号板固件 | Arduino-ESP32 3.3.13、P4 post-v3、32 MiB Flash、LVGL 9.5.0 构建成功，芯片版本、分区、组件偏移与 ELF 摘要通过脚本检查。 |

UI 测试使用模拟的显示提交标志、随机源和 review seal；协议探针使用真实密码实现但模拟显示与批准。两者不能替代端到端实板绑定、实卡签名或侧信道测量。测试允许用户主动切换至决定区，没有证明用户读过每一行。

构建器报告程序空间 1,513,240 字节，最终应用文件含封装共 1,513,984 字节。静态内存 242,904 字节，报告的剩余内部内存 84,776 字节；它不是运行时可用堆、栈裕量或长期稳定性的测量。两个 OTA 槽各 3,932,160 字节，后 24 MiB 为 `assets`。

| 产物 | 字节数 | SHA-256 |
| --- | ---: | --- |
| `HexWallet.ino.merged.bin` | 8,388,608 | `2f4f1f140a4113b79b742c4e3ddbf523b54d39f8ba5a4ee6c6db242ccc9f1106` |
| `HexWallet.ino.bin` | 1,513,984 | `4a71e5b82dcfb7d3f2dc8d19458b879417195123d728640aa34506c6f8fa6a0c` |
| `HexWallet.ino.elf` | 20,759,136 | `9d477cd1c7358ec369f374b4dabd53c78c015e01fa8c043a5130d555e5a37d84` |
| [图片摘要清单](ui-gallery/manifest.json) | — | `31f1dce7c7968e172f9796999eaa58a05e0e98fb590bd58934e549234e57d9f9` |

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

日志位于 `build/audit-logs/`：`ui-bilingual-release.log`、`ui-bilingual-sanitized.log`、`p4-ui-bilingual-build.log`、`ui-native-security.log`、`ui-native-signing.log`、`ui-production-policy.log`、`ui-protocol-sdk.log`。

文档检查发现四张旧需求原图在当前工作区缺失，已在能力核对页注明文件名并保留逐项核对记录；没有用新绘制的 UI 图片代替原图。图库发布脚本已加入 `ui-gallery` 附件目录复制，本轮未执行发布。

## 尚未达到的要求

| 范围 | 当前状态 |
| --- | --- |
| 全部界面内容双语 | 横屏固定界面及常见状态已双语；各协议动态详情、部分长警告、非横屏目录及角色互动仍有英文。304 字形子集不支持任意中文账户名。 |
| 独立创建、恢复、BIP38、扫码 | 当前为如实说明不可用的页面。生产安全托管创建／恢复、BIP38 导入导出、CSI 采集与扫码未贯通。 |
| SE051C2HQ1 | applet 能力、权限、PBKDF2 实卡结果、不可导出派生及各链签名仍待验证；生产安全托管门控保持开启。 |
| 实物操作和性能 | 本机枚举到 0 个串口。按键安装方向、局刷残影、相机、NFC、共享总线、电流、双核响应、堆与栈、长期运行和手机端到端广播均未实测。 |
| 全链安全 | 目录 214/214 是地址派生及登记证据，不是所有交易、卡内签名或节点验收的通过数；逐链缺口见[能力核对](Capability-Review-zh)。 |

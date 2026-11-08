# 2026-11-09 显示与设备构建复核

这次工作继续修复设备启动、显示刷新、物理批准和构建配置。前一轮密码实现、解析器及 token 元数据检查保留在[代码审计记录](Audit-2026-11-09-zh.md)。两份记录对应先后两个源码状态，早期构建尺寸不能用于当前镜像。

## 修复内容

| 位置 | 确认的问题 | 当前行为 |
| --- | --- | --- |
| `WalletBoardPort.cpp`、`lv_conf.h` | 板级代码未初始化 LVGL；旧版 `LV_TICK_CUSTOM` 配置没有接入 LVGL 9 时钟。 | 初始化显示前调用 `lv_init()`，使用 `lv_tick_set_cb()` 接入毫秒时钟；成功初始化可重复调用。 |
| `WalletBoardPort.cpp` | 已实现的物理按键读取函数没有注册为输入设备。 | 创建 keypad 和默认焦点组，接入去抖后的真实按键回调。 |
| `WalletUi.cpp` | P4 按键缺少长审阅正文的滚动路径。 | SW1/SW2 滚动正文，SW3 进入决定区并先选中拒绝；再次独立按键才执行决定，SW4 可拒绝。 |
| `WalletBoardPort.cpp` | 页面切换时的长按、多键组合、未释放就换键可能把导航动作带入批准按钮。 | 新审阅等待释放；组合键和换键进入释放等待；初始化与恢复后的首次输入同样要求先释放。 |
| `WalletBoardPort.cpp`、`lv_conf.h` | 全局 RGB565 字节交换会修改电子纸 DIRECT 模式保留帧，后续局部重绘可能破坏未重绘区域。 | 电子纸保留原生 RGB565，彩屏单独使用 `RGB565_SWAPPED` 传输格式。 |
| `WalletBoardPort.cpp`、`WalletUi.cpp` | 审阅曾经显示过后，后续刷新尚未完成或面板故障仍可能沿用旧的“已显示”状态。 | 每次电子纸重绘都关闭刷新屏障；每次授权重新检查当前面板是否已成功提交画面。 |
| `WalletBoardPort.cpp` | 显示注册及面板初始化失败时存在分配资源未释放的路径。 | 统一回收输入设备、焦点组、显示对象及缓冲区；失败后的初始化重试不累积这些资源。 |
| `WalletBoardPort.cpp` | S3 AMOLED 设置为横屏，LVGL 和触摸却使用 240×536 竖屏坐标；触摸读取未拒绝越界和不完整数据。 | 统一为竖屏；只接受单触点、完整读数和有效坐标。 |
| `WalletBoardPins.h` | 无屏配置把 P4 BOOT 误设为 GPIO0。 | S3 使用 GPIO0，P4 使用 GPIO35，保留显式引脚覆盖。 |
| `tools/prepare_lvgl.ps1` | 实际绘制阴影时，UBSan 检出 LVGL 9.5.0 通过不兼容函数指针调用遮罩回调。 | 五个回调的声明与定义统一为接口要求的 `void *` 参数，在函数内部转为具体类型，移除函数指针强制转换。 |
| CI、构建文档 | 完整显示镜像超出默认应用槽；显示配置没有显式启用板载 PSRAM。 | 四个完整构建组合使用 `min_spiffs`；P4 显示使用 `PSRAM=enabled`，S3 AMOLED 使用 `PSRAM=opi`，无屏保持禁用。 |

LVGL 修复限定为 `v9.5.0`。准备脚本对换行归一化后的源码校验 SHA-256，未知源码不会被修改，重复执行会验证已有补丁。原始文件散列为 `e1f852a16219644ae2d8a08c8bb49865a6f5af1bb3e2115ec3e423de46675c22`，修复后为 `5a4827156b8f77655089515c6bbe51a2044f949bb1cee47523f99c3174031996`。已实际验证首次应用、重复执行和拒绝未知改动三种情况。

## 回归验证

三个测试程序在 MSVC Release 和 Clang ASan/UBSan 下均通过，没有关闭 sanitizer 检查：

- `ui_test` 使用真实 LVGL 布局与渲染，覆盖 16 个输出、71 行审阅绑定、超长字段滚动、独立批准按键、页面切换、一次性授权、OTP 清理及对象生命周期。
- `board_p4_eink_test` 编译实际板级驱动，覆盖初始化、时钟、RGB565 保留帧的局部重绘、物理按键去抖、跨页长按、组合键、BUSY 超时和初始化失败重试。
- `board_s3_display_test` 覆盖初始化、时钟、RGB565 传输字节序、面板方向，以及触摸坐标边界、不完整读数和异常触点数。

这些测试使用真实 LVGL 和本项目板级代码，SPI/I2C、GPIO、时间由测试替身控制。`ui_test` 的审阅密封函数也是测试替身；它验证界面和授权调用关系，不能替代前一轮的密码实现与安全策略测试，更不能证明物理屏幕或安全芯片已经正常工作。

六个板型的 `WalletBoardPort.cpp` / `WalletUi.cpp` 条件分支编译检查通过，NFC 两种引脚配置和摄像头控制分支也通过。这项检查使用 Xtensa 编译器与真实 LVGL 头文件，不做链接；T-Echo 的结果不代表已经提供 nRF52 完整固件。固件策略检查重新通过。CI YAML 已通过解析器语法检查；远端 GitHub Actions 本轮没有执行。

本地证据保存在 `build/audit-logs`：

- `audit-ui-final-runtime.log`、`audit-ui-sanitized-final-runtime.log`：最终三项运行时回归结果。
- `ui-sanitizer-before-mask-fix.log`：修复前 LVGL 回调类型错误。
- `lvgl-prepare-tests-final.log`：依赖补丁幂等性与拒绝未知源码的验证。
- `policy-display-final.log`：固件策略门禁。
- `board-port-final.log`：板级条件分支编译检查。
- `device-discovery.json`：设备枚举返回 `detected_ports: []`。
- `final-staged-source-check.json`：四个构建目录各 262 个根目录 C++/头文件与当前源码一致；比较时仅去除 Arduino 生成的首行 `#line` 指令并归一化换行。
- `display-source-hashes.json`：本轮显示、输入与测试源码的 SHA-256 快照。
- `final-firmware-manifest.json`：四组构建参数、尺寸和应用镜像、ELF、bootloader、分区表、合并镜像的 SHA-256。

`build/` 不纳入版本控制。归档源码或交付镜像时须同时保存构建日志和散列记录。

## 构建配置与复现

使用 Arduino CLI 1.5.1、ESP32 core 3.3.10 和 LVGL 9.5.0，LVGL 提交固定为 `85aa60d18b3d5e5588d7b247abf90198f07c8a63`，并应用上面的受校验补丁。P4 显示配置明确指向 **7 号板、128×296 SSD1680 黑白电子纸、默认 profile 0**，不包含其他 P4 显示模块。

以下均为本轮最终源码的完整 Arduino 编译与链接，退出码均为 0：

| 配置 | 板号 | PSRAM | 程序占用（字节） | 静态 RAM（字节） | 构建目录 |
| --- | --- | --- | ---: | ---: | --- |
| ESP32-P4 黑白电子纸 | 7 | enabled | 1,399,558 | 234,668 | `build/audit-device-p4-eink` |
| ESP32-S3 无屏 | 6 | disabled | 998,923 | 223,724 | `build/audit-device-s3-headless` |
| ESP32-S3 AMOLED | 1 | opi | 1,331,514 | 230,388 | `build/audit-device-s3-display` |
| ESP32-P4 无屏 | 6 | disabled | 1,065,262 | 224,584 | `build/audit-device-p4-headless` |

对应日志为 `validated-p4-final-source.log`、`validated-headless-s3-headless.log`、`validated-psram-s3-display.log`、`validated-headless-p4-headless.log`。S3 显示版链接时，工具链 `libgcc` 对象 `_floatdidf.o` 报告缺少 `.note.GNU-stack`；本轮保留了该警告，没有通过关闭诊断掩盖它。上述结果不等于“零警告”或对运行时可执行内存权限的验收。

`min_spiffs` 是 core 的 4 MB 布局，两个应用槽各 1,966,080 字节。P4 RGB565 完整帧需 75,776 字节，显示缓冲优先分配到 PSRAM；静态 RAM 数字不能代表启动后可用堆空间。实际板卡仍需核验 PSRAM 容量、初始化状态、最小空闲堆和任务栈高水位。

完整可执行的编译命令、PSRAM 参数、分区选择和上传说明见[编译与刷机](Build-and-Flash-zh.md)。本轮命令保留 core 默认 UART 配置；原生 USB CDC 属于另一组显式构建参数，不能混同为已验收的接口。

## 尚未完成的生产功能

设备端密钥托管仍是具体的实现缺口。`WalletSession.cpp` 的非 host 分支将创建、导入、加载主节点和加载种子返回为 `CustodyUnavailable`；当前钱包 API 使用 MCU 内种子或私钥，尚未接通贯穿派生和签名的安全芯片句柄路径。SE051 的 I2C 传输、SCP03 和 APDU 模块存在，不等于该路径已经实现。

要闭合这项功能，需要确认实际 SE051 型号、applet/固件版本和个人化状态，再实现经认证的持久密钥对象管理、对应链的安全派生与签名，以及断电恢复和锁定清理。现有多链算法不能仅凭“芯片支持 ECDSA/Ed25519”就全部标记为具备硬件托管能力。芯片型号、版本和配置状态足够用于下一步分析，不应提交 PIN、SCP03 密钥或助记词。

本轮未枚举到连接的板卡，因此没有实屏、实卡签名或断电恢复的验收结果，也未发送真实资产交易。本轮结果是上述代码修复、软件回归和指定构建配置的验证；真实资产使用条件仍须完成密钥托管与硬件验收。

构建保留了默认 `HEXWALLET_REQUIRE_VERIFIED_BOOT=0` 和 `HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION=0`。本轮没有配置安全启动或烧写 eFuse；无屏镜像编译成功也不表示可以在默认策略下批准资产签名。

## 上游依据

- [LVGL 9.5.0 遮罩回调源码](https://github.com/lvgl/lvgl/blob/85aa60d18b3d5e5588d7b247abf90198f07c8a63/src/draw/sw/lv_draw_sw_mask.c)：依赖修复针对的固定版本。
- [Espressif P4 启动模式说明](https://docs.espressif.com/projects/esptool/en/latest/esp32p4/advanced-topics/boot-mode-selection.html)：GPIO35 启动引脚。
- [LilyGO AMOLED 官方板级配置](https://github.com/Xinyuan-LilyGO/T-Display-S3-AMOLED/blob/main/boards/lilygo-t-amoled.json)：OPI PSRAM 配置依据。
- [NXP SE05x 功能说明](https://www.nxp.com/docs/en/application-note/AN12973.pdf)与[官方 Plug & Trust SDK](https://github.com/NXP/plug-and-trust)：安全芯片集成需逐项核对的接口和能力。

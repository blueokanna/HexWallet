# HexWallet（BETA 版）- [English Readme](https://github.com/blueokanna/HexWallet/blob/main/README.md)

面向 ESP32 和 LVGL 的离线加密货币硬件钱包固件基础。本仓库目前是实验性工程，不能用于保存真实资产。

## 当前架构

- `WalletSecurity.*`：BIP39 English 助记词验证与种子派生、BIP32 私钥/公钥派生、路径解析和扩展密钥序列化。
- `WalletAddresses.*`：由网络参数驱动的 Bitcoin P2PKH、BIP13 P2SH-P2WPKH 与 BIP173 P2WPKH 地址编码。
- `WalletUi.*`：不保留秘密材料的 LVGL 9 锁定界面。
- `WalletBoardPort.*`：唯一允许放置屏幕、按键、总线和电源相关代码的板级边界。

启动路径不会通过串口输出助记词、种子、私钥、链码或扩展私钥。默认板级端口会失败停止；必须为实际屏幕和输入硬件实现 `WalletBoardPort.cpp` 后才会初始化界面。

## Arduino IDE

安装 Espressif ESP32 开发板支持包 3.x 或更新版本、LVGL 9.x，以及与实际屏幕控制器匹配的驱动库。随后在 `WalletBoardPort.cpp` 中实现对应的 GPIO、总线、LVGL 绘制缓冲区、刷新回调、按键/触控和供电时序。

参见 [HARDWARE_PORTING.md](HARDWARE_PORTING.md)，其中包含 LVGL 9 彩屏端口模板、电子墨水屏限制和发布前安全检查项。

## 安全状态

工程尚未实现安全元件集成、加密秘密存储、PIN 重试策略、交易解析、签名策略、可信屏幕上的完整交易审核流程和经认证的固件更新。上述功能需要独立实现并经过安全审计后，才可考虑真实资产使用。

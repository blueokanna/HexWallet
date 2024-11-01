## HexWallet - ESP32-S3 加密硬件钱包的开源版本（BETA 版）- [English Readme](https://github.com/blueokanna/HexWallet/blob/main/README.md)

### :warning: HexWallet 免责声明:
```
版权所有 (c) 2024 Blueokanna
此软件 HexWallet 由 Blueokanna 和其他贡献者开发，并根据 Apache 2.0 获得许可。以下免责声明适用：

1. 使用风险：
使用 HexWallet，即表示您同意对与其使用相关的任何风险承担全部责任。HexWallet 的作者对因使用、修改或分发此软件而造成的任何损害或损失概不负责。

2. 无担保：
HexWallet 不作任何明示或暗示的担保，包括但不限于适销性、适用于特定用途和非侵权的暗示担保。作者不保证 HexWallet 将满足您的要求，也不保证其运行不会中断或无错误。

3. 知识产权：
HexWallet 的作者不保证使用该软件不会侵犯第三方的权利。您有责任确保您拥有使用 HexWallet 中包含的任何第三方软件或内容所需的权限。

4. 责任限制：
在任何情况下，HexWallet 的作者均不对任何直接、间接、偶然、特殊、惩戒性或后果性损害（包括但不限于采购替代商品或服务；使用、数据或利润损失；或业务中断）负责，无论其原因如何，基于何种责任理论，无论是合同、严格责任还是侵权行为（包括疏忽或其他），即使已被告知存在此类损害的可能性。

5. 第三方内容：
HexWallet 可能包含受其自身许可和免责声明约束的第三方软件或库。您有责任审查并遵守任何此类第三方许可。

6. 免责声明的变更：
本免责声明可能会不时更新，恕不另行通知。您有责任定期检查本免责声明是否有任何变更。
使用 HexWallet，即表示您理解并接受本免责声明。如果您不同意本免责声明，则不得继续使用 HexWallet。
```

<br>


## 💰: HexWallet 项目

| 序号 | 项目部分 | 说明 |
| :-------------: | :-------------: | :----- |
| :one: | 项目名称e | 	:vhs: HexWallet |
| :two: | 项目版本  | 🕸 Version 0.0.1 - beta |
| :three: | 支持的虚拟货币| ![Bitcoin](https://raw.githubusercontent.com/ErikThiart/cryptocurrency-icons/master/16/bitcoin.png "Bitcoin (BTC)") ![Ethereum](https://raw.githubusercontent.com/ErikThiart/cryptocurrency-icons/master/16/ethereum.png "Ethereum (ETH)") ![Dash](https://raw.githubusercontent.com/ErikThiart/cryptocurrency-icons/master/16/dash.png "Dash (DASH)") ![Bitcoin Gold](https://raw.githubusercontent.com/ErikThiart/cryptocurrency-icons/master/16/bitcoin-gold.png "Bitcoin Gold (BTG)") ![Litecoin](https://raw.githubusercontent.com/ErikThiart/cryptocurrency-icons/master/16/litecoin.png "Litecoin (LTC)") ![Ravencoin](https://raw.githubusercontent.com/ErikThiart/cryptocurrency-icons/master/16/ravencoin.png "Ravencoin (RVN)") ![TRON](https://raw.githubusercontent.com/ErikThiart/cryptocurrency-icons/master/16/tron.png "TRON (TRX)") ![XRP](https://raw.githubusercontent.com/ErikThiart/cryptocurrency-icons/master/16/xrp.png "XRP (XRP)")|
| :four: | 是否支持网页 | :globe_with_meridians: No |
| :five: | 是否支持移动设备 | 📱 No |

<br>

## :question: 问答项

### 1. 如何使用?
首先，确保已下载并安装 Arduino IDE。继续全面配置必要的电路板支持包。然后，安装项目所需的 Arduino 库。值得注意的是，您可能需要安装 **ArduinoJson** 库，该库可通过 **Arduino 库管理器** 找到并下载。安装完所有必要库后，继续从 GitHub 下载项目代码。使用 Arduino IDE 打开代码，并尝试将其上传到 ESP32-S3 板。

### 2. 为什么项目无法使用?
请尝试在 Arduino IDE 中更新 **ESP32 板管理器**，并验证所有更新是否正常运行。请注意，当前版本是**beta 版本**。如果遇到任何问题，请随时在 GitHub 的 **Issue** 上报告。个人会在后期持续更新，并及时解决您的问题。我希望邀请所有贡献者 fork 并提交拉取请求，以增强项目的稳健性。

### 3.如何获取地址? 地址如何验证?
要通过串行端口与 ESP32 板（ESP32-S3）连接，应配置串行监视器，以 115200 的波特率读取数据。通过这种方式，您将能够检索到助记符、种子以及扩展公钥（xpub）和私钥（xprv），包括针对某些加密货币的相应 “z ”对应密钥。为便于验证，您可以使用 .NET Framework 2.0 中的工具验证生成的地址： 
```
https://iancoleman.io/bip39/
```
请注意，比特币地址是根据 BIP84 (segwit) 协议生成的，而其他加密货币通常遵守 BIP44 规范。如果您选择使用这些地址，并因此遭受任何资产损失，请注意我们的免责声明中所述条款。

<br>

## 💵 支持我 (USDT & USDC)

| ![Tether](https://raw.githubusercontent.com/ErikThiart/cryptocurrency-icons/master/16/tether.png "Tether (USDT)") **USDT** : Arbitrum One Network: **0x4051d34Af2025A33aFD5EacCA7A90046f7a64Bed** | ![USD Coin](https://raw.githubusercontent.com/ErikThiart/cryptocurrency-icons/master/16/usd-coin.png "USD Coin (USDC)") **USDC**: Arbitrum One Network: **0x4051d34Af2025A33aFD5EacCA7A90046f7a64Bed** |
|------------------------------------------------------------------------------------|------------------------------------------------------------------------------------|

| ![0x4051d34Af2025A33aFD5EacCA7A90046f7a64Bed](https://github.com/user-attachments/assets/608c5e0d-edfc-4dee-be6f-63d40b53a65f) | ![0x4051d34Af2025A33aFD5EacCA7A90046f7a64Bed (1)](https://github.com/user-attachments/assets/87205826-1f76-4724-9734-3ecbfbfb729f) |
|------------------------------------------------------------------------------------|------------------------------------------------------------------------------------|


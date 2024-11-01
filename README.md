## HexWallet - The open source for ESP32-S3 crypto hardware wallet 

### :warning: Disclaimer for HexWallet:
```
Copyright (c) 2024 Blueokanna
This software, HexWallet, is developed by Blueokanna and other contributors, and is licensed under the Apache 2.0. The following disclaimer applies:

1. Risk of Use:
By using HexWallet, you agree to take full responsibility for any risks associated with its use. The authors of HexWallet shall not be liable for any damages or losses incurred as a result of using, modifying, or distributing this software.

2. No Warranties:
HexWallet is provided "as is" without any express or implied warranties, including, but not limited to, the implied warranties of merchantability, fitness for a particular purpose, and non-infringement. The authors do not guarantee that HexWallet will meet your requirements or that its operation will be uninterrupted or error-free.

3. Intellectual Property:
The authors of HexWallet do not warrant that the use of the software will not infringe on the rights of third parties. It is your responsibility to ensure that you have the necessary permissions to use any third-party software or content included in HexWallet.

4. Limitation of Liability:
Under no circumstances shall the authors of HexWallet be liable for any direct, indirect, incidental, special, exemplary, or consequential damages (including, but not limited to, procurement of substitute goods or services; loss of use, data, or profits; or business interruption) however caused and on any theory of liability, whether in contract, strict liability, or tort (including negligence or otherwise) arising in any way out of the use of this software, even if advised of the possibility of such damage.

5. Third-Party Content:
HexWallet may include third-party software or libraries that are subject to their own licenses and disclaimers. You are responsible for reviewing and complying with any such third-party licenses.

6. Changes to Disclaimer:
This disclaimer may be updated from time to time and at any time without notice. It is your responsibility to check this disclaimer periodically for changes.
By using HexWallet, you are acknowledging your understanding and acceptance of this disclaimer. If you do not agree with this disclaimer, you are not allowed to use HexWallet.
```

<br>


## 💰: HexWallet Project

| Number | Parts | Description |
| :-------------: | :-------------: | :----- |
| :one: | Project Name | 	:vhs: HexWallet |
| :two: | Version  | 🕸 Version 0.0.1 |
| :three: | Support Crypto| ![Bitcoin](https://raw.githubusercontent.com/ErikThiart/cryptocurrency-icons/master/16/bitcoin.png "Bitcoin (BTC)") ![Ethereum](https://raw.githubusercontent.com/ErikThiart/cryptocurrency-icons/master/16/ethereum.png "Ethereum (ETH)") ![Dash](https://raw.githubusercontent.com/ErikThiart/cryptocurrency-icons/master/16/dash.png "Dash (DASH)") ![Bitcoin Gold](https://raw.githubusercontent.com/ErikThiart/cryptocurrency-icons/master/16/bitcoin-gold.png "Bitcoin Gold (BTG)") ![Litecoin](https://raw.githubusercontent.com/ErikThiart/cryptocurrency-icons/master/16/litecoin.png "Litecoin (LTC)") ![Ravencoin](https://raw.githubusercontent.com/ErikThiart/cryptocurrency-icons/master/16/ravencoin.png "Ravencoin (RVN)") ![TRON](https://raw.githubusercontent.com/ErikThiart/cryptocurrency-icons/master/16/tron.png "TRON (TRX)") ![XRP](https://raw.githubusercontent.com/ErikThiart/cryptocurrency-icons/master/16/xrp.png "XRP (XRP)")|
| :four: | Support Web | :globe_with_meridians: No |
| :five: | Support Mobile | 📱 No |
| :six: | Is Beta Version | :snowflake: Yes |

<br>

## :question: Q&A

### 1. How to use?
Firstly, ensure that you have downloaded and installed the Arduino IDE. Proceed to configure the necessary board support packages comprehensively. Subsequently, install the required Arduino libraries for the project. Notably, you will likely need to install the **ArduinoJson** library, which can be located and downloaded via the Arduino Library Manager. Once all essential libraries have been installed, proceed to download the project code from GitHub. Open the code using the Arduino IDE and attempt to upload it to your ESP32-S3 board.

### 2. Why it doesn't work?
Please attempt to update the **ESP32 Board Manager** within the Arduino IDE and verify that all updates function correctly. Bear in mind that the current version is a **beta release**. Should you encounter any issues, feel free to report them on GitHub. I will monitor the repository and address your concerns promptly. I warmly invite all contributors to fork and submit pull requests to enhance the robustness of my project.

### 3. How can I get address and verify it?
To interface with your ESP32 board (ESP32-S3) via the serial port, you should configure your serial monitor to read the data at a baud rate of 115200. By doing so, you will be able to retrieve the mnemonic, seed, as well as the extended public key (xpub) and private key (xprv), including their respective ‘z’ counterparts for certain cryptocurrencies. For verification purposes, you can validate the generated addresses using the tool at : 
```
https://iancoleman.io/bip39/
```
Please be advised that Bitcoin addresses are generated according to the BIP84 (segwit) protocol, while other cryptocurrencies generally adhere to the BIP44 specification. Should you opt to utilize these addresses and experience any asset loss as a result, please be aware that our actions are governed by the terms outlined in our disclaimer.

<br>

## 💵 Donations (USDT & USDC)

| ![Tether](https://raw.githubusercontent.com/ErikThiart/cryptocurrency-icons/master/16/tether.png "Tether (USDT)") **USDT** : Arbitrum One Network: **0x4051d34Af2025A33aFD5EacCA7A90046f7a64Bed** | ![USD Coin](https://raw.githubusercontent.com/ErikThiart/cryptocurrency-icons/master/16/usd-coin.png "USD Coin (USDC)") **USDC**: Arbitrum One Network: **0x4051d34Af2025A33aFD5EacCA7A90046f7a64Bed** |
|------------------------------------------------------------------------------------|------------------------------------------------------------------------------------|

| ![0x4051d34Af2025A33aFD5EacCA7A90046f7a64Bed](https://github.com/user-attachments/assets/608c5e0d-edfc-4dee-be6f-63d40b53a65f) | ![0x4051d34Af2025A33aFD5EacCA7A90046f7a64Bed (1)](https://github.com/user-attachments/assets/87205826-1f76-4724-9734-3ecbfbfb729f) |
|------------------------------------------------------------------------------------|------------------------------------------------------------------------------------|


> TOTP implementation record. Current documentation: [Security-Model](Security-Model) / [Security-Model-zh](Security-Model-zh).

# 设备端 TOTP

`Totp` 负责 RFC 4226/6238 算法与单调时钟，`TotpAccounts` 负责 URI 校验和账户内存，
`WalletTotp` 负责设备批准、锁定和显示期限。验证码只出现在设备屏幕，串口不返回验证码。

解锁 CLI 后使用：

```text
totp time <unix-seconds>
totp add <otpauth://totp/...>
totp list
totp show <slot>
totp remove <slot>
```

校时、导入、删号和显示都先进入设备审阅页，再由本机按键/触摸批准。批准绑定实际提交的
屏幕，120 秒失效，只能使用一次。主机只能看到请求已排队；操作结果显示在设备上。
`totp time` 不带参数时读取当前时间。旧的 `totp <base32>` 串口出码命令已移除。

账户最多八个，编号 0–7。URI 接受 SHA1/SHA256/SHA512、6/8 位、1–3600 秒周期，默认
SHA1/6 位/30 秒。标签目前只支持可打印 ASCII；不能完整显示的内容拒绝导入。重复参数、
冲突的 issuer、未知参数、非规范 Base32 尾位和超长输入都会被拒绝，同名账户不会被覆盖。
导入页面显示 issuer、账户、算法、位数和周期；密钥不回显。

账户是**会话内存储**。锁定、USB 窗口关闭、超时和重启会清除账户及时间锚点。没有把密钥
明文写进 NVS，也没有用固定编译密钥做所谓加密存储。注册服务时必须保留该服务的恢复方式。

时钟使用 `esp_timer_get_time()` 的 64 位单调毫秒，不依赖 32 位 `millis()` 长期计时。
检测到时钟倒退或整数溢出即失效。校时值来自已经认证的主机，并要求本机确认；这不是独立
可信 RTC。掉电保持、RTC 漂移与安全芯片中的长期账户存储仍未接通。

显示页给出验证码的绝对到期时间。到期时清除代码文本并提交替换页面；不会逐秒全刷四色屏。
墨水屏断电会保留最后图像，刷新失败也可能留下旧图像，因此屏幕到期时间必须保留。
四色全刷可能占去一个 30 秒周期的大部分时间，需要实机测量后确定该面板是否适合显示 TOTP。

验证入口：`tests/host/auth` 覆盖 RFC 向量、URI 错误、账户边界、设备批准、锁定和过期；
`tests/host/ui_check.ps1` 使用真实 LVGL 检查代码清除及交易页互斥。

规范：[RFC 6238](https://www.rfc-editor.org/rfc/rfc6238)、
[RFC 4648](https://www.rfc-editor.org/rfc/rfc4648)、
[Google Key URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)。
# 参与开发

[English](Contributing) · [首页](Home-zh)

## 动手之前

- 先看 [准入策略](Admission-Policy-zh)。加一个 `SIGN` 能力却不在同一个提交里带测试，不管是什么链，都会被拒。
- 先看 [测试](Testing-zh)，跑 `tests/host/build.ps1` 和 `tests/host/policy_check.ps1`。两个都过了才值得评审。
- 许可证是个人非商业授权。提交贡献即表示按 LICENSE 第 7 节授权给版权持有人；不要提交你无权这样授权的代码。

## 不可商量的代码规则

| 规则 | 原因 |
| --- | --- |
| 固件里不用 `String`、不用 STL 容器、不用异常、不用 RTTI | 堆碎片和异常表会吃掉钱包没有的 DRAM |
| 每个边界都用定长缓冲 + 显式长度 | 每个解析器都能被不可信输入触达 |
| 用 `chain_copy_text()` / 有界 `snprintf`，禁止无界拷贝 | 超过基线 `policy_check.ps1` 会让构建失败 |
| 类型化错误枚举，不用哨兵整数 | 调用方不该能编出一个"成功" |
| 秘密只放 `SensitiveValue<T>` | 提前 return 和栈复用是最常见的泄漏方式 |
| 宁可拒绝，绝不截断 | 被截断的地址或金额就是丢钱 bug |
| 新网络、新依赖必须钉死版本 | 可复现性就是全部意义 |

## 好的改动长什么样

1. 一个提交只做一件事。改链要同时动配置、策略、解析器和向量；只改注释的提交不要顺手改别的。
2. 测试和代码一起进。优先补畸形输入的拒绝测试，而不是再加一条好路径。
3. 生成表只重新生成，不手改。`--check` 必须过。
4. 声称某能力的文档在同一个提交里更新；过期声明就是 bug。
5. 没在硬件上验证过的行为，在代码注释和文档里都要写明。

## 发布这个 wiki

GitHub wiki 是另一个 git 仓库里的一堆扁平 `.md`，不支持子目录；`_Sidebar.md` / `_Footer.md` 是特殊文件。
这里的结构就按这个来：

- `Page.md` 是英文，`Page-zh.md` 是中文，两边开头都有语言切换。
- `Home.md` / `Home-zh.md` 是入口；`_Sidebar.md` 同时列两种语言。
- `record-*` 和带日期的文件是记录，不要改写。

先在 GitHub 网页上创建第一个页面，然后：

```powershell
powershell -ExecutionPolicy Bypass -File tools/publish_wiki.ps1 -DryRun
powershell -ExecutionPolicy Bypass -File tools/publish_wiki.ps1
```

脚本会把 `HexWallet.wiki.git` 克隆到 `build/wiki-publish`，复制根目录所有 `*.md`，提交并推送。
克隆失败就拒绝推送，所以空 wiki 必须先手工建一页。

## 报告安全问题

漏洞不要开公开 issue。发邮件到 `blueokanna@gmail.com`，写清受影响文件、最小复现和预期影响。
没有漏洞赏金计划。

## 评审清单

- 这次改动有没有改变"签什么"，却没有改变"显示什么"？
- 新代码路径能不能被一个解析器没有限制的长度触达？
- 失败路径会不会把密钥、缓冲区或批准留在原地？
- 有没有在没测试、没拒绝清单的情况下扩大能力位？
- 文档和代码还对得上吗？

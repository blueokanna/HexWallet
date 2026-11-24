# Chinese UI font / 中文界面字库

The firmware embeds a 14 px, 1 bpp subset of Noto Sans CJK SC Regular. It falls back to LVGL's Montserrat 12 for ASCII. Both use a 16 px Chinese line box with baseline 3. Font data is licensed under [SIL OFL 1.1](OFL.txt); the original font's copyright name record reads `© 2014-2021 Adobe (http://www.adobe.com/).` No runtime font download is required.

固件内置 14 px、1 bpp 的 Noto Sans CJK SC Regular 子集；ASCII 回退至 LVGL Montserrat 12。中文行高统一为 16 px、基线为 3。字库按 [SIL OFL 1.1](OFL.txt) 分发，运行时无需下载。当前包含 304 个中文及标点字形，只覆盖固件固定文案；不是任意中文输入字库。无法完整显示的交易审阅禁止批准。

- Source / 来源: [NotoSansCJKsc-Regular.otf](https://raw.githubusercontent.com/notofonts/noto-cjk/523d033d6cb47f4a80c58a35753646f5c3608a78/Sans/OTF/SimplifiedChinese/NotoSansCJKsc-Regular.otf)
- Revision / 固定提交: `523d033d6cb47f4a80c58a35753646f5c3608a78`
- SHA-256: `2c76254f6fc379fddfce0a7e84fb5385bb135d3e399294f6eeb6680d0365b74b`
- Converter / 转换器: `lv_font_conv@1.5.3` (its npm package bundles its dependencies)
- Characters / 字符清单: [ui-characters.txt](ui-characters.txt), derived from `WalletUi.cpp` and `src/UiText.inc`
- Output / 生成文件: `src/generated/UiChineseFont.inc`, compiled through `WalletUiFont.cpp`

Run from the repository root. / 在仓库根目录执行：

```powershell
New-Item -ItemType Directory -Force build/ui-font | Out-Null
Invoke-WebRequest 'https://raw.githubusercontent.com/notofonts/noto-cjk/523d033d6cb47f4a80c58a35753646f5c3608a78/Sans/OTF/SimplifiedChinese/NotoSansCJKsc-Regular.otf' -OutFile build/ui-font/NotoSansCJKsc-Regular.otf
npm install --prefix build/ui-font --save-exact --ignore-scripts lv_font_conv@1.5.3
python tools/generate_ui_font.py --check
```

`--check` verifies the source SHA-256 and converter version, regenerates into a temporary directory, and requires a byte-for-byte match with both the committed font and character list. Omit `--check` to regenerate after changing fixed UI text, then rerun the English and Chinese LVGL tests. Building the firmware uses the generated file without Node or the original OTF.

`--check` 核对源字体摘要和转换器版本，在临时目录重新生成，并逐字节比较现有字库与字符清单。修改固定文案后，去掉 `--check` 重新生成，再执行中英文 LVGL 测试。普通固件编译直接使用生成文件，无需 Node 或原始 OTF。

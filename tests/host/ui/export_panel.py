"""Validate real LVGL panel frames; export individual PNGs and a bilingual gallery."""
import argparse
import hashlib
import html
import json
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont
import zxingcpp

SCREENS = [
    ("home", "Home", "主页"),
    ("home-language", "Home / language selected", "主页 / 语言入口"),
    ("language", "Language", "语言选择"),
    ("settings", "Settings", "设置"),
    ("layout", "Asset layout", "资产布局"),
    ("keyboard", "Search / four-button keyboard", "搜索 / 四键键盘"),
    ("keyboard-candidates", "Pinyin / character selection", "拼音 / 候选字"),
    ("catalog-grid", "GridView", "网格视图"),
    ("catalog-card", "CardView", "卡片视图"),
    ("companion", "DeepSeek companion", "DeepSeek 伙伴"),
    ("companion-feed", "Companion / feed", "伙伴 / 喂食"),
    ("companion-bubbles", "Companion / blow bubbles", "伙伴 / 吹泡泡"),
    ("controls", "Button guide", "按键说明"),
    ("controls-scroll", "Button guide / scroll", "按键说明 / 滚动"),
    ("create", "Create / backup type", "创建 / 备份方式"),
    ("create-words", "Create / BIP39 unavailable", "创建 / BIP39 尚未开放"),
    ("create-key", "BIP38 / locked", "BIP38 / 已锁定"),
    ("recover", "Recover / backup type", "恢复 / 备份方式"),
    ("recover-words", "Recover / BIP39 unavailable", "恢复 / BIP39 尚未开放"),
    ("recover-key", "Recover / card import status", "恢复 / 卡内导入状态"),
    ("backup-network", "Bitcoin backup / network", "比特币备份 / 网络"),
    ("backup-password", "BIP38 backup / password", "BIP38 备份 / 密码"),
    ("backup-working", "Bitcoin backup / cancel", "比特币备份 / 取消"),
    ("backup-address", "Bitcoin backup / address check", "比特币备份 / 核对地址"),
    ("backup-tag", "NFC backup / present tag", "NFC 备份 / 放置标签"),
    ("mnemonic-language", "Simulated custody / word list", "模拟托管 / 词表"),
    ("mnemonic-count", "Simulated custody / word count", "模拟托管 / 词数"),
    ("mnemonic-backup", "Public BIP39 fixture / write down words", "公开 BIP39 样例 / 抄写助记词"),
    ("mnemonic-retype", "Simulated custody / verify backup", "模拟托管 / 重输助记词"),
    ("mnemonic-passphrase", "Simulated custody / passphrase choice", "模拟托管 / 附加密码选择"),
    ("mnemonic-create-confirm", "Simulated custody / confirm creation", "模拟托管 / 确认创建"),
    ("mnemonic-recover", "Simulated custody / enter recovery words", "模拟托管 / 输入恢复助记词"),
    ("mnemonic-recover-confirm", "Simulated custody / confirm recovery", "模拟托管 / 确认恢复"),
    ("scan", "Camera unavailable", "摄像头尚未开放"),
    ("catalog", "Asset directory / first page", "资产目录 / 首页"),
    ("catalog-next", "Asset directory / next selected", "资产目录 / 下一页选中"),
    ("catalog-last", "Asset directory / last page", "资产目录 / 末页"),
    ("catalog-empty", "Asset directory / empty fixture", "资产目录 / 空目录测试"),
    ("asset", "Asset details", "资产详情"),
    ("asset-scroll", "Asset details / scroll", "资产详情 / 滚动"),
    ("receive", "Receive / address and QR", "收款 / 地址与二维码"),
    ("receive-scroll", "Receive / full address and path", "收款 / 完整地址与路径"),
    ("receive-bottom", "Receive / verification reminder", "收款 / 核对提醒"),
    ("receive-long", "Receive / long address fixture", "收款 / 长地址测试"),
    ("receive-long-bottom", "Receive / long address end", "收款 / 长地址末尾"),
    ("review", "Transaction / start", "交易审阅 / 开始"),
    ("scroll", "Transaction / scroll", "交易审阅 / 滚动"),
    ("decision", "Transaction / reject selected", "交易审阅 / 拒绝选中"),
    ("approval", "Transaction / hold to approve", "交易审阅 / 长按批准"),
    ("approved", "Approval / collection notice", "批准 / 领取提示"),
    ("review-code", "Serial review / confirmation code", "串口审阅 / 确认码"),
    ("review-code-scroll", "Serial review / scroll", "串口审阅 / 滚动"),
    ("review-code-bottom", "Serial review / code and seal", "串口审阅 / 确认码与校验码"),
    ("review-error", "Review / entropy failure", "审阅 / 随机源失败"),
    ("refused", "Refusal / fee policy", "拒签 / 费用限制"),
    ("wrong-network", "Refusal / wrong chain", "拒签 / 网络不符"),
    ("pairing", "Phone pairing / code and fingerprint", "手机配对 / 码与指纹"),
    ("pairing-scroll", "Phone pairing / scroll", "手机配对 / 滚动"),
    ("pairing-reject", "Phone pairing / reject selected", "手机配对 / 拒绝选中"),
    ("pairing-approve", "Phone pairing / hold to pair", "手机配对 / 长按配对"),
    ("otp", "Authenticator / code", "动态验证 / 验证码"),
    ("otp-scroll", "Authenticator / expiry", "动态验证 / 到期时间"),
    ("otp-bottom", "Authenticator / session notice", "动态验证 / 会话提示"),
    ("busy", "Processing", "正在处理"),
    ("status-long", "Long status / scrollable", "长状态 / 可滚动"),
    ("port-error", "Display port error", "显示接口错误"),
]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("frames", type=Path, help="CTest panel-frames containing en/ and zh/")
    parser.add_argument("destination", type=Path, help="Gallery directory")
    parser.add_argument("--compare", type=Path, help="Require byte-identical sanitizer PBM frames")
    parser.add_argument("--font", type=Path, default=Path("build/ui-font/NotoSansCJKsc-Regular.otf"))
    parser.add_argument("--markdown", type=Path, help="Optional wiki page with each PNG in a separate table cell")
    args = parser.parse_args()
    args.destination.mkdir(parents=True, exist_ok=True)
    font = ImageFont.truetype(str(args.font), 16)
    frames, manifest, cards = {}, [], []
    expected = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    for number, (name, en, zh) in enumerate(SCREENS, 1):
        for lang in ("en", "zh"):
            source = args.frames / lang / f"{name}.pbm"
            if args.compare and source.read_bytes() != (args.compare / lang / source.name).read_bytes():
                raise ValueError(f"Release/sanitizer pixel mismatch: {lang}/{name}")
            with Image.open(source) as image:
                if image.size != (128, 296) or image.mode != "1" or image.getextrema() != (0, 255):
                    raise ValueError(f"Invalid monochrome frame: {source}")
                frame = image.transpose(Image.Transpose.ROTATE_90)
            frames[lang, name] = frame
            if name in ("receive", "receive-scroll", "receive-bottom"):
                grayscale = frame.convert("L")
                reduced = grayscale.resize((222, 96), Image.Resampling.BOX).filter(ImageFilter.GaussianBlur(0.4))
                for sample in (grayscale, reduced, grayscale.resize((148, 64), Image.Resampling.BOX)):
                    decoded = zxingcpp.read_barcodes(sample)
                    if [item.text for item in decoded] != [expected]:
                        raise ValueError(f"{lang}/{name} at {sample.size} failed to decode the fixture address")
            dest = args.destination / f"{lang}-{name}.png"
            frame.save(dest, format="PNG")
            manifest.append(dict(language=lang, state=name, file=dest.name, width=296, height=128,
                                 panel_sha256=digest(source), png_sha256=digest(dest)))
            cards.append(f'<figure data-language="{lang}"><figcaption><b>{number:02} · {html.escape(zh)}</b>'
                         f'<span>{html.escape(en)} · {lang.upper()}</span></figcaption>'
                         f'<a href="{dest.name}"><img src="{dest.name}" width="592" height="256" '
                         f'alt="{html.escape(zh)} / {html.escape(en)} / {lang}" loading="lazy"></a>'
                         f'<a class="download" href="{dest.name}" download>PNG · 296 × 128 · {lang.upper()}</a></figure>')
    (args.destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    # Each sheet is intentionally short: separate boxes, generous gaps, explicit
    # bilingual captions. PNGs above contain only the exact native display pixels.
    for start in range(0, len(SCREENS), 8):
        subset = SCREENS[start:start + 8]
        sheet = Image.new("RGB", (1248, 38 + len(subset) * 340), "#eef0f2")
        draw = ImageDraw.Draw(sheet)
        draw.text((24, 8), "HEX WALLET / LVGL 主机绘制 / ENGLISH + 简体中文", font=font, fill="#171717")
        for row, (name, en, zh) in enumerate(subset):
            for col, lang in enumerate(("en", "zh")):
                x, y = 16 + col * 624, 38 + row * 340
                draw.rectangle((x, y, x + 607, y + 323), fill="white", outline="#c3c7cd", width=1)
                draw.text((x + 8, y + 6), f"{start + row + 1:02} · {zh} · {lang.upper()}", font=font, fill="#171717")
                draw.text((x + 8, y + 28), en, font=font, fill="#455365")
                sheet.paste(frames[lang, name].convert("RGB").resize((592, 256), Image.Resampling.NEAREST), (x + 8, y + 58))
        sheet.save(args.destination / f"overview-{start // 8 + 1}.png")
    document = '''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>HexWallet · 双语界面审计 / UI audit</title><style>
*{box-sizing:border-box}body{margin:0;background:#eef0f2;color:#19212b;font:16px/1.6 system-ui,sans-serif}main{max-width:1320px;margin:auto;padding:32px 16px}h1{margin:0;font-size:28px}p{max-width:1000px}nav{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:24px 0}select{font:inherit;padding:6px 12px;border:1px solid #adb5bf;border-radius:6px;background:white}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:24px}figure{margin:0;padding:12px;background:white;border:1px solid #c3c7cd;border-radius:8px;overflow:hidden}figcaption{display:flex;flex-direction:column;margin-bottom:14px}figcaption span,.download{font-size:13px;color:#455365}img{display:block;width:296px;max-width:100%;height:auto;margin:auto;image-rendering:pixelated;outline:1px solid #d4d8dd}.download{display:inline-block;margin-top:10px}body[data-language="en"] figure[data-language="zh"],body[data-language="zh"] figure[data-language="en"]{display:none}@media(max-width:760px){.grid{grid-template-columns:1fr}}@media(min-width:1300px){img{width:592px}}@media(min-width:650px) and (max-width:760px){img{width:592px}}a{color:#174b82}a:focus-visible,select:focus-visible{outline:3px solid #174b82;outline-offset:4px}</style>
<main><h1>HexWallet · 双语界面审计 / UI audit</h1><p>每格为独立图片，来自实际 LVGL 绘制及墨水屏帧转换。原始尺寸 296 × 128，点击可打开原图；中英文按同一状态逐格对照。</p>
<p lang="en">Each cell is a separate 296 × 128 PNG from the firmware's LVGL renderer and panel conversion. English and Simplified Chinese are paired by state. Click any image for its native pixels.</p>
<p>画面由主机使用公开测试数据绘制。BIP38 地址核对可在解锁后操作。生产钱包创建与恢复依赖卡内密钥托管。实物屏幕、相机和实卡签名仍待验证。</p>
<p lang="en">The host renders public test fixtures. An unlocked session can check a BIP38 backup address. Production wallet setup requires card-backed custody. Physical display, camera and card-signing checks are pending.</p>
<nav><label for="language">显示 / Show</label><select id="language"><option value="all">中英对照 / Both</option><option value="zh">简体中文</option><option value="en">English</option></select><a href="manifest.json">SHA-256 清单 / Manifest</a></nav><div class="grid">'''
    document += "\n".join(cards)
    document += '</div></main><script>document.getElementById("language").addEventListener("change",e=>document.body.dataset.language=e.target.value)</script></html>'
    (args.destination / "index.html").write_text(document, encoding="utf-8")
    if args.markdown:
        import os
        base = Path(os.path.relpath(args.destination, args.markdown.parent)).as_posix()
        sheets = [f"[{i // 8 + 1}]({base}/overview-{i // 8 + 1}.png)" for i in range(0, len(SCREENS), 8)]
        markdown = ["# 双语界面逐格图库 / Bilingual UI gallery", "",
                    f"{len(SCREENS)} 个状态，每个中英文格子均为独立 PNG，点击查看原始 296 × 128 像素。",
                    f"{len(SCREENS)} states, with a separate PNG in every English and Chinese cell. Click to open the native pixels.", "",
                    "画面由主机 LVGL 使用公开测试数据绘制。BIP38 可核对备份地址。生产卡内托管与相机采集仍待打通。",
                    "Host LVGL renders public fixtures, including BIP38 backup address checks. Production card custody and camera capture are pending.", "",
                    f"[HTML 筛选图库 / Filterable gallery]({base}/index.html) · [SHA-256]({base}/manifest.json)", "",
                    "总览 / Overviews  " + " · ".join(sheets), "",
                    "| 状态 / State | English | 简体中文 |", "| --- | --- | --- |"]
        for number, (name, en, zh) in enumerate(SCREENS, 1):
            images = [f"[![{zh} / {en} / {lang}]({base}/{lang}-{name}.png)]({base}/{lang}-{name}.png)" for lang in ("en", "zh")]
            markdown.append(f"| {number:02} · {zh}<br>{en} | {images[0]} | {images[1]} |")
        args.markdown.write_text("\n".join(markdown) + "\n", encoding="utf-8")
    print(f"{args.destination}: {len(manifest)} individual PNGs, {len(SCREENS)} states × 2 languages; both QR codes decoded" +
          ("; every frame byte-identical to sanitizer output" if args.compare else ""))


if __name__ == "__main__":
    main()

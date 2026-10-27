#!/usr/bin/env python3
"""Kurage Security Watch のデモのOGP画像 1200x630（マスコット入り・数字は焼き込まない）。
  /usr/bin/python3 demo/make_ogp.py  → demo/ksecwatch-ogp.png
"""
import base64
import pathlib

from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parent.parent
import sys
OUT = ROOT / "demo" / "ksecwatch-ogp.png"


def data_uri(path, mime):
    return f"data:{mime};base64," + base64.b64encode(pathlib.Path(path).read_bytes()).decode()


MASCOT = data_uri("/home/kojima/work/kurage_web/images/kurage-mascot-cutout.png", "image/png")
LOGO = data_uri("/home/kojima/work/exbridge_jp/images/logo-mark-128.png", "image/png")

HTML = f"""<!doctype html><html lang="ja"><head><meta charset="utf-8"><style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{width:1200px;height:630px;font-family:"Noto Sans CJK JP",sans-serif;background:#f4f7fb;color:#1b2a3a;position:relative;overflow:hidden}}
.top{{position:absolute;left:0;right:0;top:0;height:10px;background:linear-gradient(90deg,#1f4e8c,#0a9a8f)}}
.l{{position:absolute;left:64px;top:66px;width:840px}}
.name{{font-size:30px;font-weight:900;color:#1f4e8c}}
h1{{font-size:56px;line-height:1.3;font-weight:900;margin:16px 0 24px}}
h1 em{{font-style:normal;color:#1f4e8c}}
.chips{{display:flex;gap:12px;flex-wrap:wrap}}
.chips div{{background:#fff;border:2px solid #dde5ef;border-radius:16px;padding:12px 18px;line-height:1.35}}
.chips b{{display:block;font-size:26px;color:#1f4e8c}}
.chips span{{font-size:16px;color:#5d6b7a;font-weight:700}}
.sub{{margin-top:22px;font-size:22px;font-weight:700;color:#3d5066}}
.m{{position:absolute;right:40px;bottom:40px;width:250px;height:auto;object-fit:contain}}
.foot{{position:absolute;left:64px;bottom:30px;display:flex;align-items:center;gap:10px;font-size:20px;color:#5d6b7a;font-weight:700}}
.foot img{{width:34px;height:34px}}
</style></head><body><div class="top"></div>
<div class="l">
  <div class="name">Kurage Security Watch</div>
  <h1>レンタルサーバーの<br><em>改ざん</em>を毎時見張る</h1>
  <div class="chips">
    <div><b>全ファイル</b><span>サーバーの中で差分</span></div>
    <div><b>自社の更新</b><span>と見分ける</span></div>
    <div><b>マルウェア</b><span>YARAで検査</span></div>
    <div><b>メール</b><span>見つけたら知らせる</span></div>
  </div>
  <div class="sub">管理者の権限は不要／PHPとFTPが使えれば置ける</div>
</div>
<img class="m" src="{MASCOT}">
<div class="foot"><img src="{LOGO}">株式会社エクスブリッジ</div>
</body></html>"""

with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width": 1200, "height": 630})
    pg.set_content(HTML, wait_until="load")
    pg.wait_for_timeout(300)
    pg.screenshot(path=str(OUT))
    b.close()
print(OUT)

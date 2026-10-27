#!/usr/bin/env python3
"""デモページ（https://proto.exbridge.jp/ksecwatch/）を作って置く。中身は架空の会社のサイトの見張りの記録（demo/make_sample_db.py）。
  /usr/bin/python3 demo/build_demo.py [--store https://kappstore.exbridge.jp/app.php?id=…] [--deploy]
製品本体の報告ページ（scripts/make_report.py の render）をそのまま使い、デモの説明・届くメールの例・共有ボタンを足す。"""
import argparse, ftplib, html, json, os, pathlib, sqlite3, subprocess, sys, urllib.parse

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / 'scripts'))
import make_report  # noqa: E402

URL = 'https://proto.exbridge.jp/ksecwatch/'
NAME = 'Kurage Security Watch'
TITLE = 'Kurage Security Watch｜レンタルサーバーの改ざん監視'
DESC = ('レンタルサーバーに置いたホームページが書き換えられていないか、怪しいファイルが置かれていないかを毎時見張り、'
        '見つけたらメールで知らせるシステムです。サーバーの中で全ファイルを2秒ほどで比べ、変わったPHPだけを当社側でマルウェア検査にかけます。')
SHARE = (f'【{NAME}】\nレンタルサーバーに置いたホームページが、書き換えられていないか・怪しいファイルが置かれていないかを毎時見張り、'
         '見つけたらメールで知らせるシステムです。自社の更新とは見分けるので、知らせが来たときだけ確かめれば済みます。\n#セキュリティ #改ざん検知\n')
FAQ = [
    ('どんなサーバーで使えますか', 'PHP が動き、FTP（FTPS）でファイルを置けるレンタルサーバーで使えます。管理者の権限は要りません。見張り役の PHP を公開フォルダの外に置き、呼び出し口だけを公開フォルダに置きます。'),
    ('サーバーに負担はかかりませんか', '見張り役は、ファイルの大きさ・更新日時・権限を台帳と比べるだけで、中身の指紋は変わったファイルだけ取り直します。17万ファイルのサイトで1回2秒ほどです。マルウェアの判定はサーバーではしません。'),
    ('自社でサイトを更新したときも知らせが来ますか', '来ません。手元の公開用のファイルと中身が同じものは「自社の更新」として分けます。サーバー自身が書き換えるデータのファイルは、先頭の実行を止める1行が崩れていないかだけを確かめます。'),
    ('第三者に呼び出されることはありませんか', '呼び出し口は、合言葉で作った署名と時刻が合うときだけ動き、それ以外は「ページが無い」と答えます。同じ署名は二度使えません。'),
    ('何をもってマルウェアと判断しますか', '変わったファイルの中身を当社側（導入先のサーバー）でもらい、オープンソースの検査規則 php-malware-finder（YARA）にかけます。誤検知しやすい規則は外し、確かめたものは「確認済み」にできます。'),
]


def h(s):
    return html.escape(str(s))


def build(store):
    db = HERE / 'sample.sqlite'
    subprocess.run([sys.executable, str(HERE / 'make_sample_db.py'), str(db)], check=True)
    report = make_report.render(sqlite3.connect(db), now='2026-10-28 09:00:00')
    share_url = URL + '#ref=copy-ksw'
    copy = SHARE + share_url
    xurl = 'https://x.com/intent/post?' + urllib.parse.urlencode({'text': SHARE + URL + '#ref=x-share-ksw'})
    ld = {'@context': 'https://schema.org', '@graph': [
        {'@type': 'WebApplication', 'name': NAME, 'url': URL, 'applicationCategory': 'SecurityApplication', 'operatingSystem': 'Linux',
         'description': DESC, 'publisher': {'@type': 'Organization', 'name': '株式会社エクスブリッジ', 'url': 'https://exbridge.jp/'}},
        {'@type': 'WebSite', 'name': NAME, 'url': URL},
        {'@type': 'FAQPage', 'mainEntity': [{'@type': 'Question', 'name': q, 'acceptedAnswer': {'@type': 'Answer', 'text': a}} for q, a in FAQ]}]}
    mail = '''【Kurage Security Watch】不正なプログラムの疑い（scan・10/26 03:00）

■ 不正なプログラムの疑い 2件（YARA: php-malware-finder）
  https://www.example.jp/wp-content/uploads/2026/10/class-wp-cache.php  ObfuscatedPhp:$eval DodgyPhp:$at_eval,$execution
  https://www.example.jp/wp-includes/load.php  ObfuscatedPhp:$eval

■ 自社の更新ではない変化 3件（PHP・JavaScript・.htaccess など。手元に同じ中身のファイルが無い）
  増えた  www.example.jp/wp-content/uploads/2026/10/class-wp-cache.php  2026-10-26 02:47:12 権限644
  変わった  www.example.jp/.htaccess  2026-10-26 02:47:15 権限644
  変わった  www.example.jp/wp-includes/load.php  2026-10-26 02:47:15 権限644

（ほかに記録だけしたもの：データ入れの PHP（止めの1行を確認済み） 1件）'''
    store_btn = (f'<a class="btn main" href="{h(store)}#ref=ksw-demo-store">この製品を導入する（商品ページ）</a>' if store else '')
    css = make_report.CSS + '''
.hero{display:flex;gap:16px;align-items:center;margin:8px 0 6px}.hero img{width:96px;height:auto;flex:none}
.hero h1{font-size:26px;line-height:1.4;margin:0}.lead{margin:6px 0 0;color:var(--sub)}
.pshare{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:10px 0 4px}
.btn{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--ink);background:#fff;color:var(--ink);border-radius:999px;padding:8px 16px;font-weight:700;text-decoration:none;font-size:14px;cursor:pointer;font-family:inherit}
.btn.xb{background:#111;border-color:#111;color:#fff}.btn.main{background:var(--teal);border-color:var(--teal);color:#fff}
.sample{background:#fff6dc;border:1px solid #f0d58a;border-radius:12px;padding:10px 14px;font-size:14px;margin:14px 0}
pre.mail{white-space:pre-wrap;word-break:break-all;background:#f3f6f8;border-radius:10px;padding:12px 14px;font-size:13px;margin:0}
.how{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.how>*{min-width:0}
.how div{background:#f3f9f8;border-radius:12px;padding:12px 14px}.how b{display:block;margin-bottom:4px}
dl.faq dt{font-weight:700;margin-top:10px}dl.faq dd{margin:4px 0 0}
footer{color:var(--sub);font-size:13px;text-align:center;padding:24px 16px}
@media (max-width:640px){.hero h1{font-size:21px}.hero img{width:64px}.how{grid-template-columns:minmax(0,1fr)}}
'''
    how = [('サーバーの中で比べる', '見張り役の PHP が、全ファイルの大きさ・更新日時・ctime・権限を台帳と比べ、違いだけを返します。FTP で一覧を取るより速く、接続を重ねて遮断されることもありません。'),
           ('自社の更新と見分ける', '手元の公開用のファイルと中身が同じなら「自社の更新」。知らせが来るのは、自社が置いていない変化だけです。'),
           ('中身をマルウェア検査', '増えた・変わった PHP などは中身をもらい、php-malware-finder の規則（YARA）にかけます。判定はサーバーの外でするので、共有サーバーの CPU を使いません。'),
           ('日時を戻す手口も見る', '更新日時は戻せても ctime は戻せません。中身が変わったのに日時が古いままのファイルも知らせ、1日1回は全部の指紋を取り直します。')]
    body = f'''<div class="hero"><img src="mascot.png" alt="Kurage" width="96" height="96">
<div><h1>レンタルサーバーのサイトが書き換えられたら、1時間以内に知らせる</h1>
<p class="lead">{h(NAME)}：自社の更新とは見分けて、置かれた覚えのない PHP や .htaccess の変化だけをメールで知らせます。</p></div></div>
<div class="pshare"><a class="btn xb" target="_blank" rel="noopener" href="{h(xurl)}">Xで共有</a>
<button class="btn cp" type="button" data-copy="{h(copy)}">紹介文とURLをコピー</button><span class="ok" hidden>コピーしました</span></div>
<p class="sample"><b>これはデモです。</b>下は架空の会社（www.example.jp・shop.example.jp）の14日分の見張りの記録です。10月26日の深夜に、画像を置くフォルダへ PHP が置かれ、.htaccess と WordPress の本体が書き換えられた想定です。</p>
{report}
<section class="card"><h2>届くメールの例</h2><pre class="mail">{h(mail)}</pre>
<p class="muted">同じ中身のものは2回知らせません。確かめたものは「確認済み」にでき、中身がまた変わればもう一度知らせます。</p></section>
<section class="card"><h2>しくみ</h2><div class="how">{''.join(f"<div><b>{h(a)}</b>{h(b)}</div>" for a, b in how)}</div></section>
<section class="card"><h2>よくある質問</h2><dl class="faq">{''.join(f"<dt>{h(q)}</dt><dd>{h(a)}</dd>" for q, a in FAQ)}</dl></section>
<section class="card"><h2>導入について</h2><p>見張り役（PHP）は御社のレンタルサーバーに、見張りの実行と検査は御社のサーバー（Linux・Python）に置きます。サイトの中身や記録を当社に送ることはありません。</p>
<div class="pshare">{store_btn}<a class="btn" href="https://exbridge.jp/contact.php?subject={urllib.parse.quote(NAME + 'について')}#ref=ksw-demo-contact">相談する</a></div></section>'''
    page = f'''<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{h(TITLE)}</title><meta name="description" content="{h(DESC)}"><link rel="canonical" href="{URL}">
<meta property="og:type" content="website"><meta property="og:site_name" content="{h(NAME)}"><meta property="og:title" content="{h(TITLE)}">
<meta property="og:description" content="{h(DESC)}"><meta property="og:url" content="{URL}"><meta property="og:locale" content="ja_JP">
<meta property="og:image" content="{URL}ksecwatch-ogp.png"><meta property="og:image:width" content="1200"><meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image"><meta name="twitter:image" content="{URL}ksecwatch-ogp.png">
<link rel="icon" href="mascot.png"><script type="application/ld+json">{json.dumps(ld, ensure_ascii=False)}</script>
<style>{css}</style>
<script src=https://kurage.exbridge.jp/partner-bar.js defer></script>
<script>(function(){{var s=document.createElement('script');s.src='https://kurage.exbridge.jp/simpletrack.php?url='+encodeURIComponent(location.href)+'&ref='+encodeURIComponent(document.referrer);s.async=true;document.head.appendChild(s)}})();</script>
</head><body><div class="wrap">{body}</div>
<footer>{h(NAME)}・提供：<a href="https://exbridge.jp/#ref=ksw-demo-footer">株式会社エクスブリッジ</a></footer>
<script>
document.querySelectorAll('.cp').forEach(function(b){{b.addEventListener('click',function(){{
  var t=b.getAttribute('data-copy'),ok=b.parentNode.querySelector('.ok');
  function done(){{if(ok){{ok.hidden=false;setTimeout(function(){{ok.hidden=true}},2000)}}}}
  function fb(){{var a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();try{{document.execCommand('copy');done()}}catch(e){{}}document.body.removeChild(a)}}
  if(navigator.clipboard&&navigator.clipboard.writeText){{navigator.clipboard.writeText(t).then(done,fb)}}else{{fb()}}
}})}});
</script></body></html>'''
    out = HERE / 'out'
    out.mkdir(exist_ok=True)
    (out / 'index.html').write_text(page, encoding='utf-8')
    (out / 'robots.txt').write_text(f'User-agent: *\nAllow: /\nSitemap: {URL}sitemap.xml\n', encoding='utf-8')
    (out / 'sitemap.xml').write_text(f'<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>{URL}</loc><lastmod>2026-10-28</lastmod></url></urlset>\n', encoding='utf-8')
    (out / 'llms.txt').write_text(f'# {NAME}\n\n> {DESC}\n\n- デモ: {URL}（架空の会社のサイトの記録）\n- 対象: PHP が動き FTP で置けるレンタルサーバー（管理者権限不要）\n- 判定: php-malware-finder（YARA・LGPL-3.0）を導入先のサーバーで使う\n- 改ざん「検知」であり、侵入を防ぐ WAF ではない\n- 提供: 株式会社エクスブリッジ https://exbridge.jp/\n', encoding='utf-8')
    print('built', out / 'index.html')
    return out


def deploy(out):
    for ln in open('/home/kojima/work/aixec/.env', encoding='utf-8'):
        if '=' in ln and not ln.startswith('#'):
            k, v = ln.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    f = ftplib.FTP(os.environ['FTP_HOST'], timeout=120)
    f.login(os.environ['FTP_USER'], os.environ['FTP_PASS'])
    root = '/web/proto_exbridge_jp/ksecwatch'
    try:
        f.mkd(root)
    except ftplib.error_perm:
        pass
    for n in ('index.html', 'robots.txt', 'sitemap.xml', 'llms.txt'):
        f.storbinary(f'STOR {root}/{n}', open(out / n, 'rb'))
    for n in ('mascot.png', 'ksecwatch-ogp.png'):
        f.storbinary(f'STOR {root}/{n}', open(HERE / n, 'rb'))
    f.quit()
    print('published:', URL)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--store', default='')
    ap.add_argument('--deploy', action='store_true')
    a = ap.parse_args()
    o = build(a.store)
    if a.deploy:
        deploy(o)

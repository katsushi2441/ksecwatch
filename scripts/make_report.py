#!/usr/bin/env python3
"""見張りの記録（data/ksecwatch.sqlite）を、1枚の HTML の報告ページにする。
  .venv/bin/python scripts/make_report.py [--db data/ksecwatch.sqlite] [--out outputs/report.html] [--now "2026-10-28 09:00:00"]
社内の共有フォルダやメールに添えて見るためのもの。公開のサーバーには置かない（どのファイルがあるかが分かってしまうため）。"""
import argparse, html, pathlib, sqlite3, time

ROOT = pathlib.Path(__file__).resolve().parent.parent
KIND_JA = {'added': '増えた', 'modified': '変わった', 'removed': '消えた', 'perm': '権限が変わった', 'mtime_rollback': '日時が戻された'}
LEVEL_JA = {'alert': ('知らせた', 'bad'), 'ours': ('自社の更新', 'ok'), 'data': ('データの更新', 'ok'), 'quiet': ('ふつうの作り直し', 'ok'),
            'note': ('記録だけ', 'mid')}
ACTION_JA = {'scan': '毎時の見張り', 'full': '毎日の総点検', 'sweep': '全件の検査'}

CSS = """
:root{--ink:#0f2a3a;--sub:#4f6878;--line:#dbe7ee;--bg:#f5f9fb;--card:#fff;--teal:#0a8f88;--bad:#c0392b;--badbg:#fdecea;--mid:#9a6b00;--midbg:#fff6dc;--okbg:#e6f6f3}
*{box-sizing:border-box}html,body{margin:0;overflow-x:hidden;max-width:100%}
body{font-family:"Noto Sans JP",system-ui,sans-serif;color:var(--ink);background:var(--bg);line-height:1.7}
.wrap{max-width:1040px;margin:0 auto;padding:16px;overflow-wrap:anywhere}
.kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:16px 0}
.kpis>*{min-width:0}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px 16px;box-shadow:0 2px 8px rgba(15,42,58,.05)}
.kpi b{display:block;font-size:28px;line-height:1.2}.kpi span{font-size:13px;color:var(--sub)}
.kpi.bad{border-color:#f0b4ad;background:var(--badbg)}.kpi.bad b{color:var(--bad)}
section.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px 18px;margin:16px 0;box-shadow:0 2px 8px rgba(15,42,58,.05)}
section.card h2{font-size:18px;margin:0 0 10px}
.tbl{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--sub);font-weight:700;white-space:nowrap}
td.path{font-family:ui-monospace,Menlo,monospace;font-size:13px;word-break:break-all;min-width:200px}
.tag{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:700;white-space:nowrap}
.tag.bad{background:var(--badbg);color:var(--bad)}.tag.mid{background:var(--midbg);color:var(--mid)}.tag.ok{background:var(--okbg);color:var(--teal)}
.bar{display:flex;gap:2px;align-items:flex-end;height:48px;margin-top:6px}
.bar i{flex:1;background:#bfe3df;border-radius:2px 2px 0 0;min-height:2px}.bar i.bad{background:var(--bad)}
.muted{color:var(--sub);font-size:13px}
@media (max-width:640px){.kpis{grid-template-columns:repeat(2,minmax(0,1fr))}.kpi b{font-size:22px}}
"""


def h(s):
    return html.escape(str(s if s is not None else ''))


def render(c, now=None, title='Kurage Security Watch 見張りの記録'):
    """報告の本文（<div class="wrap"> の中身）を返す"""
    now = now or time.strftime('%Y-%m-%d %H:%M:%S')
    day_ago = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.mktime(time.strptime(now, '%Y-%m-%d %H:%M:%S')) - 86400))
    last = c.execute("SELECT at, action, files, sec FROM runs WHERE action IN ('scan','full') ORDER BY id DESC LIMIT 1").fetchone()
    n24 = c.execute('SELECT COUNT(*) FROM events e JOIN runs r ON r.id = e.run_id WHERE r.at > ?', (day_ago,)).fetchone()[0]
    a24 = c.execute("SELECT COUNT(*) FROM events e JOIN runs r ON r.id = e.run_id WHERE r.at > ? AND e.level = 'alert'", (day_ago,)).fetchone()[0]
    open_f = c.execute('SELECT site, path, rules, at FROM findings WHERE accepted IS NULL ORDER BY id DESC').fetchall()
    runs24 = c.execute('SELECT COUNT(*) FROM runs WHERE at > ?', (day_ago,)).fetchone()[0]
    out = []
    kpi = [(f"{last[2]:,}" if last else '-', '見張っているファイル', ''),
           (str(runs24), '直近24時間の見張り（回）', ''),
           (str(a24), '直近24時間に知らせた変化', 'bad' if a24 else ''),
           (str(len(open_f)), 'まだ確かめていない疑い', 'bad' if open_f else '')]
    out.append('<div class="kpis">' + ''.join(f'<div class="kpi {cls}"><b>{h(v)}</b><span>{h(l)}</span></div>' for v, l, cls in kpi) + '</div>')
    if last:
        out.append(f'<p class="muted">最後の見張り：{h(last[0])}（{h(ACTION_JA.get(last[1], last[1]))}・サーバーの中で {h(last[3])} 秒）。直近24時間の変化は {n24} 件で、そのうち自社の更新や記録だけのものを除いた {a24} 件を知らせました。</p>')

    out.append('<section class="card"><h2>不正なプログラムの疑い（まだ確かめていないもの）</h2>')
    if open_f:
        out.append('<div class="tbl"><table><tr><th>見つけた日時</th><th>場所</th><th>反応した規則</th></tr>')
        for site, path, rules, at in open_f[:50]:
            out.append(f'<tr><td>{h(at)}</td><td class="path">{h(site + path)}</td><td><span class="tag bad">{h(rules)}</span></td></tr>')
        out.append('</table></div>')
    else:
        out.append('<p>ありません。</p>')
    out.append('</section>')

    rows = c.execute('''SELECT r.at, e.site, e.path, e.kind, e.level, e.mode, e.old_mode FROM events e JOIN runs r ON r.id = e.run_id
                        ORDER BY e.id DESC LIMIT 20''').fetchall()
    out.append('<section class="card"><h2>最近の変化</h2><div class="tbl"><table><tr><th>日時</th><th>場所</th><th>何が</th><th>扱い</th></tr>')
    for at, site, path, kind, lv, mode, old in rows:
        lj, cls = LEVEL_JA.get(lv, (lv, 'mid'))
        k = KIND_JA.get(kind, kind) + (f'（{h(old)}→{h(mode)}）' if old else '')
        out.append(f'<tr><td>{h(at[5:16])}</td><td class="path">{h(site + path)}</td><td>{k}</td><td><span class="tag {cls}">{h(lj)}</span></td></tr>')
    out.append('</table></div><p class="muted">「自社の更新」は、手元の公開用のファイルと中身が同じもの。「データの更新」は、サーバー自身が書き換えるデータ入れの PHP で、先頭の止めの1行が崩れていないことを確かめたもの。</p></section>')

    days = c.execute('''SELECT substr(r.at,1,10) d, SUM(e.level='alert'), COUNT(e.id) FROM runs r LEFT JOIN events e ON e.run_id = r.id
                        GROUP BY d ORDER BY d DESC LIMIT 14''').fetchall()[::-1]
    if days:
        mx = max(x[2] for x in days) or 1
        out.append('<section class="card"><h2>日ごとの変化の数（直近14日）</h2><div class="bar">')
        for d, al, n in days:
            out.append(f'<i class="{"bad" if al else ""}" style="height:{max(4, int(48 * n / mx))}px" title="{h(d)} 変化{n}件・知らせた{al or 0}件"></i>')
        out.append(f'</div><p class="muted">{h(days[0][0])} 〜 {h(days[-1][0])}。赤は知らせた変化があった日。</p></section>')

    runs = c.execute('SELECT at, action, files, events, theirs, findings, sec FROM runs ORDER BY id DESC LIMIT 12').fetchall()
    out.append('<section class="card"><h2>見張りの実行</h2><div class="tbl"><table><tr><th>日時</th><th>種類</th><th>ファイル</th><th>変化</th><th>知らせた</th><th>疑い</th><th>秒</th></tr>')
    for at, act, files, ev, th, fd, sec in runs:
        out.append(f'<tr><td>{h(at[5:16])}</td><td>{h(ACTION_JA.get(act, act))}</td><td>{(files or 0):,}</td><td>{ev or 0}</td><td>{th or 0}</td><td>{fd or 0}</td><td>{h(sec)}</td></tr>')
    out.append('</table></div></section>')
    return '\n'.join(out)


def page(body, title='Kurage Security Watch 見張りの記録'):
    return f'''<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>{h(title)}</title><style>{CSS}</style></head>
<body><div class="wrap"><h1 style="font-size:22px;margin:8px 0">{h(title)}</h1>
{body}</div></body></html>'''


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--db', default=str(ROOT / 'data/ksecwatch.sqlite'))
    ap.add_argument('--out', default=str(ROOT / 'outputs/report.html'))
    ap.add_argument('--now')
    a = ap.parse_args()
    c = sqlite3.connect(a.db)
    out = pathlib.Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(page(render(c, a.now)), encoding='utf-8')
    print('wrote', out)

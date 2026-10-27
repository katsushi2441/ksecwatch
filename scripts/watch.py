#!/usr/bin/env python3
"""Kurage Security Watch（ksecwatch）：共有レンタルサーバーのサイトが、壊されていないか・何か置かれていないかを見張る。

  .venv/bin/python scripts/watch.py            毎時：変わったファイルを調べる（増えた・変わった PHP などは中身を取って YARA にかける）
  .venv/bin/python scripts/watch.py --full     毎日：中身の指紋を全部取り直して比べる（更新日時を戻す手口への保険）
  .venv/bin/python scripts/watch.py --sweep    いま置いてある PHP などを全部 YARA にかける（初回と、ルールを変えたとき）
  .venv/bin/python scripts/watch.py --report   直近の結果と、まだ確かめていない疑いを表示する
  .venv/bin/python scripts/watch.py --accept 理由   まだ確かめていない疑いを、全部「確認済み」にする（中身が変わればまた知らせる）
  --no-mail を付けると、メールを送らない

しくみ
- サーバーの中の見張り役（server/agent_main.php）が、全部のファイルの大きさ・日時・ctime・権限を見て、台帳との違いだけを返す（当社の4サイト17万件で約2秒）
- 増えた・変わった PHP などは、中身をもらって当社側で YARA（php-malware-finder のルール）にかける
- 同じ中身のファイルが手元（config.json の local_dirs）にあれば「当社のデプロイ」として分け、それだけならメールしない
- 決まり（policy.json）：サーバー自身が書くデータ入れの PHP は、先頭の止めの1行が崩れていないかを見る。HTML・SVG の変化は記録だけ
- 見つけたものは data/ksecwatch.sqlite に残し、config.json の alert_to に知らせる（同じものは2回知らせない）"""
import base64, fnmatch, gzip, hashlib, json, os, pathlib, re, smtplib, sqlite3, ssl, sys, time
from email.mime.text import MIMEText

import yara

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from agent_call import call  # noqa: E402
from ksw_config import CFG  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
DB = ROOT / 'data' / 'ksecwatch.sqlite'
RULES = ROOT / 'rules/php-malware-finder-master/data/php.yar'
ALERT_TO = CFG['alert_to']
LOCALS = [pathlib.Path(d) for d in CFG.get('local_dirs', [])] + [ROOT / 'data/deployed']
LOCAL_PRUNE = {'node_modules', '.git', '.venv', 'venv', '__pycache__', 'site-packages', 'storage'}
CODE_EXT = ('.php', '.php5', '.php7', '.php8', '.phtml', '.phar', '.inc', '.js', '.mjs', '.html', '.htm', '.svg', '.ini')
# 当社の書き方に反応するだけのもの（2026-10-27 実測）。日本語の文字（NonPrintableChars）と、@include（simpletrack の読み込み）
IGNORE = {('NonPrintableChars', '*'), ('DodgyPhp', '$silenced_include')}
POLICY = json.loads((ROOT / 'policy.json').read_text(encoding='utf-8'))
for _k, _v in (CFG.get('policy_local') or {}).items():   # この会社だけの決まりを足す
    if _k == 'yara_allow':
        POLICY['yara_allow']['items'] += _v
    elif _k in POLICY:
        POLICY[_k]['paths'] += _v
NOTE_EXT = ('.html', '.htm', '.svg')   # 中身の変化は記録だけ（当社のビルドが手元に残さず置くものが多い）
# データ入れの PHP の先頭の止め（<?php exit; ?> や Bludit の defined('BLUDIT') or die('...'); ?>）
GUARD = re.compile(rb"\A(\xef\xbb\xbf)?<\?php\s+(exit|die)\s*(\(\s*\))?\s*;\s*\?>|\A(\xef\xbb\xbf)?<\?php\s+defined\(\s*'BLUDIT'\s*\)\s+or\s+die\(\s*'[^']*'\s*\)\s*;\s*\?>", re.I)


def match(path, pats):
    return any(fnmatch.fnmatchcase(path, p) for p in pats)


def guarded(data):
    """先頭に止めの1行があり、そのあとに PHP の始まりが無いか"""
    m = GUARD.match(data)
    return bool(m) and b'<?' not in data[m.end():]


def allowed(path, hit):
    return any(fnmatch.fnmatchcase(path, a['path']) and a.get('rule') in (None, hit) for a in POLICY['yara_allow']['items'])


def db():
    DB.parent.mkdir(exist_ok=True)
    c = sqlite3.connect(DB)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, action TEXT, sec REAL, files INTEGER,
      events INTEGER, theirs INTEGER, findings INTEGER, note TEXT);
    CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER, site TEXT, path TEXT, kind TEXT,
      sha TEXT, size INTEGER, mtime TEXT, mode TEXT, old_mode TEXT, level TEXT);
    CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER, site TEXT, path TEXT, sha TEXT,
      rules TEXT, ours INTEGER, at TEXT, accepted TEXT, UNIQUE(site, path, sha));
    CREATE TABLE IF NOT EXISTS localidx(path TEXT PRIMARY KEY, size INTEGER, mtime REAL, sha TEXT);
    """)
    return c


def local_shas(c):
    """手元の PHP などの指紋の一覧。大きさと更新日時が前と同じなら取り直さない"""
    old = {r[0]: r[1:] for r in c.execute('SELECT path, size, mtime, sha FROM localidx')}
    seen = set()
    for dirpath, dirs, files in (w for d in LOCALS for w in os.walk(d)):
        dirs[:] = [d for d in dirs if d not in LOCAL_PRUNE and not d.startswith('.venv')]
        for n in files:
            ln = n.lower()
            if not (ln.endswith(CODE_EXT) or ln in ('.htaccess', '.user.ini')):
                continue
            p = os.path.join(dirpath, n)
            try:
                st = os.stat(p)
            except OSError:
                continue
            if st.st_size > 5 * 1024 * 1024 or not os.path.isfile(p):
                continue
            seen.add(p)
            o = old.get(p)
            if o and o[0] == st.st_size and o[1] == st.st_mtime:
                continue
            try:
                h = hashlib.sha256(open(p, 'rb').read()).hexdigest()
            except OSError:
                continue
            c.execute('INSERT OR REPLACE INTO localidx VALUES (?,?,?,?)', (p, st.st_size, st.st_mtime, h))
    gone = set(old) - seen
    c.executemany('DELETE FROM localidx WHERE path = ?', [(p,) for p in gone])
    c.commit()
    return {r[0] for r in c.execute('SELECT sha FROM localidx')}


_rules = None


def check(data):
    """YARA にかけて、当社の書き方に反応しただけのものを除いた「規則名:文字列名」を返す"""
    global _rules
    if _rules is None:
        _rules = yara.compile(filepath=str(RULES), includes=True)
    out = []
    for m in _rules.match(data=data, timeout=20):
        ids = [s.identifier for s in m.strings] or ['(条件)']
        keep = [i for i in ids if (m.rule, '*') not in IGNORE and (m.rule, i) not in IGNORE]
        if keep:
            out.append(m.rule + ':' + ','.join(sorted(set(keep))))
    return out


def fetch(items):
    """中身をもらう。1回 8MB までなので、残り（more）は続けて頼む"""
    while items:
        r = call('fetch', files=items)
        for x in r['files']:
            yield x
        items = r.get('more') or []


def inspect(c, run_id, items, ours_shas):
    """中身を取って調べ、新しく見つかったものを返す。データ入れの PHP は止めの1行を、ほかは YARA で見る"""
    new = []
    for x in fetch(items):
        if 'gz' not in x:
            if match(x['path'], POLICY['data_php']['paths']) and x.get('error') == 'too_large':
                hits = ['データ入れの PHP が大きすぎて中身を確かめられない（%s バイト）' % x.get('size')]
                x['sha'] = ''
            else:
                continue
        else:
            data = gzip.decompress(base64.b64decode(x['gz']))
            if match(x['path'], POLICY['data_php']['paths']):
                hits = [] if guarded(data) else ['データ入れの PHP の先頭の止めが崩れている／止めのあとに PHP がある']
            else:
                hits = [h for h in check(data) if not allowed(x['path'], h)]
        if not hits:
            continue
        ours = int(x['sha'] in ours_shas)
        cur = c.execute('INSERT OR IGNORE INTO findings(run_id, site, path, sha, rules, ours, at) VALUES (?,?,?,?,?,?,?)',
                        (run_id, x['site'], x['path'], x['sha'], ' '.join(hits), ours, time.strftime('%Y-%m-%d %H:%M:%S')))
        if cur.rowcount:
            new.append({'site': x['site'], 'path': x['path'], 'rules': hits, 'ours': ours})
    c.commit()
    return new


def level(e, ours_shas):
    """変化の重さ：ours（当社のデプロイと同じ中身）・data・quiet・note（記録だけ）・alert（知らせる）"""
    p = e['path']
    if e['kind'] in ('added', 'modified') and e.get('sha') in ours_shas:
        return 'ours'
    if match(p, POLICY['data_php']['paths']) and e['kind'] in ('added', 'modified'):
        return 'data'   # 中身は inspect で確かめる
    if match(p, POLICY['quiet']['paths']):
        return 'quiet'
    if e['kind'] == 'removed' or p.lower().endswith(NOTE_EXT) and e['kind'] in ('added', 'modified'):
        return 'note'
    return 'alert'


KIND_JA = {'added': '増えた', 'modified': '変わった', 'removed': '消えた', 'perm': '権限が変わった', 'mtime_rollback': '中身が変わったのに更新日時が古いまま'}


def mail(subject, body):
    E = os.environ
    msg = MIMEText(body, 'plain', 'utf-8')
    msg['Subject'] = subject
    msg['From'] = E.get('SMTP_FROM')
    msg['To'] = ALERT_TO
    with smtplib.SMTP_SSL(E.get('SMTP_HOST'), int(E.get('SMTP_PORT', '465')), context=ssl.create_default_context(), timeout=30) as s:
        s.login(E.get('SMTP_USER') or E.get('SMTP_FROM'), E['SMTP_PASSWORD'])
        s.send_message(msg)


def main():
    c = db()
    if '--report' in sys.argv:
        for r in c.execute('SELECT id, at, action, sec, files, events, theirs, findings, note FROM runs ORDER BY id DESC LIMIT 15'):
            print(r)
        n = c.execute('SELECT COUNT(*) FROM findings WHERE accepted IS NULL').fetchone()[0]
        print(f'まだ確かめていない疑い {n}件')
        for r in c.execute('SELECT site, path, rules, at FROM findings WHERE accepted IS NULL ORDER BY id DESC LIMIT 50'):
            print(' ', r)
        return
    if '--accept' in sys.argv:
        i = sys.argv.index('--accept')
        why = sys.argv[i + 1] if len(sys.argv) > i + 1 else ''
        if not why:
            sys.exit('理由を書いてください（例：--accept "EspoCRM の正規ライブラリ"）')
        n = c.execute('UPDATE findings SET accepted = ? WHERE accepted IS NULL', (time.strftime('%Y-%m-%d %H:%M ') + why,)).rowcount
        c.commit()
        print(f'{n}件を確認済みにした')
        return
    t0 = time.time()
    now = time.strftime('%Y-%m-%d %H:%M:%S')
    action = 'sweep' if '--sweep' in sys.argv else 'full' if '--full' in sys.argv else 'scan'
    run_id = c.execute('INSERT INTO runs(at, action) VALUES (?, ?)', (now, action)).lastrowid
    c.commit()
    ours_shas = local_shas(c)

    if action == 'sweep':
        cursor, items, nfiles = '', [], 0
        while True:
            r = call('list', cursor=cursor)
            items += [[s, p] for s, p, size, sha, *_ in r['rows'] if size and size <= 5 * 1024 * 1024 and sha not in ours_shas]
            nfiles += len(r['rows'])
            if not r['cursor']:
                break
            cursor = r['cursor']
        found = []
        for k in range(0, len(items), 400):
            found += inspect(c, run_id, items[k:k + 400], ours_shas)
            print(f'  {min(k + 400, len(items))} / {len(items)}（見つかった {len(found)}）', flush=True)
        c.execute('UPDATE runs SET sec=?, files=?, events=0, theirs=?, findings=?, note=? WHERE id=?',
                  (round(time.time() - t0, 1), nfiles, len(items), len(found), '手元と同じ中身のものは除いて調べた', run_id))
        c.commit()
        print(f'台帳の PHP など {nfiles}件のうち、手元に同じ中身が無い {len(items)}件を調べた。見つかった {len(found)}件')
        for x in found:
            print(' ', x)
        report(found, [], action)
        return

    r = call(action)
    evs = r['events']
    nfiles = sum(v['files'] for v in r['sites'].values())
    theirs = []
    for e in evs:
        e['level'] = level(e, ours_shas)
        c.execute('INSERT INTO events(run_id, site, path, kind, sha, size, mtime, mode, old_mode, level) VALUES (?,?,?,?,?,?,?,?,?,?)',
                  (run_id, e['site'], e['path'], e['kind'], e.get('sha'), e.get('size'), e.get('mtime'), e.get('mode'), e.get('old_mode'), e['level']))
        if e['level'] == 'alert':
            theirs.append(e)
    c.commit()
    found = inspect(c, run_id, [[e['site'], e['path']] for e in evs if e['kind'] in ('added', 'modified')], ours_shas)
    base = [k for k, v in r['sites'].items() if v.get('baseline')]
    note = ('台帳を作成: ' + ','.join(base)) if base else ''
    if r['events_total'] > len(evs):
        note += f" 変化 {r['events_total']}件のうち {len(evs)}件だけ受け取った"
    c.execute('UPDATE runs SET sec=?, files=?, events=?, theirs=?, findings=?, note=? WHERE id=?',
              (round(time.time() - t0, 1), nfiles, r['events_total'], len(theirs), len(found), note.strip(), run_id))
    c.commit()
    print(f"{action}: {nfiles}件・変化 {r['events_total']}件（知らせる {len(theirs)}件）・見つかった {len(found)}件・サーバー {r['sec']}秒・全体 {time.time() - t0:.1f}秒 {note}")
    for e in evs[:40]:
        print(' ', e['level'], KIND_JA.get(e['kind'], e['kind']), e['site'] + e['path'])
    report(found, theirs, action, evs)


def report(found, theirs, action, evs=()):
    if '--no-mail' in sys.argv or not (found or theirs):
        return
    lines = []
    if found:
        lines.append(f'■ 不正なプログラムの疑い {len(found)}件（YARA: php-malware-finder）')
        for x in found[:50]:
            lines.append(f"  https://{x['site']}{x['path']}  {' '.join(x['rules'])}{'（手元にも同じ中身あり）' if x['ours'] else ''}")
        lines.append('')
    if theirs:
        lines.append(f'■ 当社のデプロイではない変化 {len(theirs)}件（PHP・JavaScript・.htaccess など。手元に同じ中身のファイルが無い）')
        for e in theirs[:80]:
            lines.append(f"  {KIND_JA.get(e['kind'], e['kind'])}  {e['site']}{e['path']}  {e.get('mtime', '')} 権限{e.get('mode', '')}"
                         + (f"（前 {e['old_mode']}）" if e.get('old_mode') else ''))
        lines.append('')
    rest = {}
    for e in evs:
        if e['level'] != 'alert':
            rest[e['level']] = rest.get(e['level'], 0) + 1
    if rest:
        ja = {'ours': '当社のデプロイと同じ中身', 'data': 'データ入れの PHP（止めの1行を確認済み）', 'quiet': '作り直されるのがふつうのもの', 'note': 'HTML などの変化・消えたもの'}
        lines.append('（ほかに記録だけしたもの：' + '・'.join(f'{ja[k]} {n}件' for k, n in rest.items()) + '）')
    lines.append('')
    lines.append(f'確認: cd {ROOT} && .venv/bin/python scripts/watch.py --report')
    head = '不正なプログラムの疑い' if found else '見慣れない変化'
    mail(f'【Kurage Security Watch】{head}（{action}・{time.strftime("%m/%d %H:%M")}）', '\n'.join(lines))
    print('mailed:', ALERT_TO)


if __name__ == '__main__':
    main()

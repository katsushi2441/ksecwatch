#!/usr/bin/env python3
"""デモ用の見張りの記録（架空の会社のサイト）を作る。デモページ（proto.exbridge.jp/ksecwatch/）の中身。
  /usr/bin/python3 demo/make_sample_db.py demo/sample.sqlite
ファイル名・規則名は、実際の見張りで出る形に合わせてある（規則名は php-malware-finder で見本の裏口ファイルを検査した結果）。"""
import pathlib, random, sqlite3, sys, time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / 'scripts'))
out = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else 'demo/sample.sqlite')
out.unlink(missing_ok=True)
c = sqlite3.connect(out)
c.executescript("""
CREATE TABLE runs(id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, action TEXT, sec REAL, files INTEGER, events INTEGER, theirs INTEGER, findings INTEGER, note TEXT);
CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER, site TEXT, path TEXT, kind TEXT, sha TEXT, size INTEGER, mtime TEXT, mode TEXT, old_mode TEXT, level TEXT);
CREATE TABLE findings(id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER, site TEXT, path TEXT, sha TEXT, rules TEXT, ours INTEGER, at TEXT, accepted TEXT, UNIQUE(site, path, sha));
""")
rnd = random.Random(20261028)
END = time.mktime(time.strptime('2026-10-28 09:00:00', '%Y-%m-%d %H:%M:%S'))
W, S = 'www.example.jp', 'shop.example.jp'
files = 48213
# 14日分の見張り（毎時）と、毎日4時の総点検
special = {
    '2026-10-20 15:00': [(W, '/wp-content/themes/example/functions.php', 'modified', 'ours', None, None),
                         (W, '/wp-content/themes/example/style.css', 'modified', 'note', None, None)],
    '2026-10-23 11:00': [(S, '/app/Http/Controllers/OrderController.php', 'modified', 'ours', None, None)],
    '2026-10-26 03:00': [(W, '/wp-content/uploads/2026/10/class-wp-cache.php', 'added', 'alert', None, None),
                         (W, '/.htaccess', 'modified', 'alert', None, None),
                         (W, '/wp-includes/load.php', 'modified', 'alert', None, None)],
    '2026-10-26 04:00': [(W, '/wp-includes/load.php', 'mtime_rollback', 'alert', None, None)],
    '2026-10-27 22:00': [(S, '/public/index.php', 'perm', 'alert', '666', '644')],
}
t = END - 14 * 86400
while t <= END:
    at = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t))
    full = at[11:13] == '04'
    evs = list(special.get(at[:16], []))
    if at[11:13] in ('10', '14', '17') and rnd.random() < .6:
        evs.append((S, '/blog/bl-content/databases/pages.php', 'modified', 'data', None, None))
    if rnd.random() < .08:
        evs.append((W, f'/news/2026{at[5:7]}{at[8:10]}.html', 'added', 'note', None, None))
    files += sum(1 for e in evs if e[2] == 'added')
    theirs = sum(1 for e in evs if e[3] == 'alert')
    fnd = 1 if at.startswith('2026-10-26 03') else 0
    rid = c.execute('INSERT INTO runs(at, action, sec, files, events, theirs, findings, note) VALUES (?,?,?,?,?,?,?,?)',
                    (at, 'full' if full else 'scan', round(rnd.uniform(4.0, 6.5) if full else rnd.uniform(0.6, 1.1), 2), files, len(evs), theirs, fnd, '')).lastrowid
    for site, path, kind, lv, mode, old in evs:
        c.execute('INSERT INTO events(run_id, site, path, kind, size, mtime, mode, old_mode, level) VALUES (?,?,?,?,?,?,?,?,?)',
                  (rid, site, path, kind, rnd.randint(800, 40000), at, mode or '644', old, lv))
    if fnd:
        c.execute('INSERT INTO findings(run_id, site, path, sha, rules, ours, at) VALUES (?,?,?,?,?,?,?)',
                  (rid, W, '/wp-content/uploads/2026/10/class-wp-cache.php', 'demo1', 'ObfuscatedPhp:$eval DodgyPhp:$at_eval,$execution', 0, at))
        c.execute('INSERT INTO findings(run_id, site, path, sha, rules, ours, at) VALUES (?,?,?,?,?,?,?)',
                  (rid, W, '/wp-includes/load.php', 'demo2', 'ObfuscatedPhp:$eval', 0, at))
    t += 3600
c.commit()
print('wrote', out, c.execute('SELECT COUNT(*) FROM runs').fetchone()[0], 'runs')

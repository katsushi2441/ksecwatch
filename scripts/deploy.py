#!/usr/bin/env python3
"""サーバーへ見張り役を置く。FTPS の1接続にまとめる。
  python3 scripts/deploy.py
- 本体・設定・台帳は公開フォルダの外（config.json の server.ftp_home、権限 700）
- 公開フォルダ（server.ftp_public）には呼び出し口 agent.php だけ（署名が合わなければ 404）
- config.php（合言葉・見るサイト）は config.json と env_file から、その場で作って送る（手元にも git にも残さない）
- マルウェアの判定は当社側（scripts/watch.py の YARA）でするので、サーバーには判定の道具を置かない
  （はじめ phpMussel を置いたが、「system」のような普通の語にも反応して使えなかったので外した。残っていれば消す）"""
import ftplib, io, json, os, pathlib, ssl, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from ksw_config import CFG, ROOT  # noqa: E402

E = os.environ
HOME_FTP, HOME_FS, PUBLIC = CFG['server']['ftp_home'], CFG['server']['fs_home'], CFG['server']['ftp_public']
SITES = CFG['sites']


def php_str(s):
    return "'" + s.replace('\\', '\\\\').replace("'", "\\'") + "'"


sites_php = ',\n'.join(f"    {php_str(k)} => ['root' => {php_str(v['root'])}, 'skip' => [{', '.join(php_str(x) for x in v.get('skip', []))}]]"
                       for k, v in SITES.items())
config = f"""<?php
// 自動生成（ksecwatch/scripts/deploy.py）。合言葉の元は config.json の env_file
const KSW_SECRET = {php_str(E['KSECWATCH_SECRET'])};
const KSW_SITES = [
{sites_php},
];
"""

f = ftplib.FTP_TLS(E['FTP_HOST'], timeout=300, context=ssl.create_default_context())
f.login(E['FTP_USER'], E['FTP_PASS'])
f.prot_p()


def mkd(d):
    try:
        f.mkd(d)
    except ftplib.error_perm:
        pass


for d in (HOME_FTP, HOME_FTP + '/data', PUBLIC):
    mkd(d)
f.sendcmd(f'SITE CHMOD 700 {HOME_FTP}')
f.sendcmd(f'SITE CHMOD 700 {HOME_FTP}/data')
f.storbinary(f'STOR {HOME_FTP}/agent_main.php', open(ROOT / 'server/agent_main.php', 'rb'))
f.storbinary(f'STOR {HOME_FTP}/config.php', io.BytesIO(config.encode()))
stub = f"<?php\n// Kurage Security Watch（ksecwatch）の呼び出し口。本体と台帳は公開フォルダの外\nrequire {php_str(HOME_FS + '/agent_main.php')};\n"
f.storbinary(f'STOR {PUBLIC}/agent.php', io.BytesIO(stub.encode()))
# 置いた呼び出し口の控え（watch.py が「自分で置いたもの」と見分ける）
(ROOT / 'data/deployed').mkdir(parents=True, exist_ok=True)
(ROOT / 'data/deployed/agent.php').write_text(stub, encoding='utf-8')
print('deployed: agent_main.php config.php agent.php')


def rmtree(d):
    try:
        ents = list(f.mlsd(d, facts=['type']))
    except ftplib.error_perm:
        return 0
    n = 0
    for name, fa in ents:
        if name in ('.', '..'):
            continue
        if fa.get('type') == 'dir':
            n += rmtree(f'{d}/{name}')
        else:
            f.delete(f'{d}/{name}')
            n += 1
    f.rmd(d)
    return n


for d in (HOME_FTP + '/mussel', HOME_FTP + '/data/mussel_cache', HOME_FTP + '/data/quarantine'):
    n = rmtree(d)
    if n:
        print('removed:', d, n, 'files')
f.quit()

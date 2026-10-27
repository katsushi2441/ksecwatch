"""設定（config.json）と秘密の値（env_file）を読む。scripts/ のどれからも使う"""
import json, os, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def load():
    p = ROOT / 'config.json'
    if not p.exists():
        raise SystemExit('config.json がありません。config.example.json を写して書き換えてください')
    cfg = json.loads(p.read_text(encoding='utf-8'))
    envf = pathlib.Path(cfg.get('env_file') or '.env')
    if not envf.is_absolute():
        envf = ROOT / envf
    if envf.exists():
        for ln in open(envf, encoding='utf-8'):
            if '=' in ln and not ln.lstrip().startswith('#'):
                k, v = ln.split('=', 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    cfg['sites'] = {k: v for k, v in cfg['sites'].items() if not k.startswith('_')}
    return cfg


CFG = load()

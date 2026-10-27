#!/usr/bin/env python3
"""サーバーの見張り役（agent.php）を、署名つきで呼ぶ。
  /usr/bin/python3 scripts/agent_call.py scan|full|sweep [cursor]"""
import hashlib, hmac, json, os, sys, time, urllib.request

from ksw_config import CFG

URL = CFG['agent_url']


def call(action, **kw):
    body = json.dumps({'action': action, **kw}).encode()
    ts = str(int(time.time() * 1000))   # ミリ秒（同じか前の時刻は、サーバーが断る）
    time.sleep(0.002)
    sig = hmac.new(os.environ['KSECWATCH_SECRET'].encode(), ts.encode() + b'\n' + body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(URL, data=body, method='POST', headers={
        'Content-Type': 'application/json', 'X-KSW-Time': ts, 'X-KSW-Sig': sig, 'User-Agent': 'ksecwatch/1.0'})
    with urllib.request.urlopen(req, timeout=200) as r:
        return json.loads(r.read())


if __name__ == '__main__':
    a = sys.argv[1] if len(sys.argv) > 1 else 'scan'
    kw = {'cursor': sys.argv[2]} if a == 'sweep' and len(sys.argv) > 2 else {}
    print(json.dumps(call(a, **kw), ensure_ascii=False, indent=1))

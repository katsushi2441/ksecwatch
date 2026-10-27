# 設置手順

**AIエージェント（Claude Code / Codex など）に、このファイルを渡してください。**手順を読んで設置まで進めます。

置く場所は2つです。

- **見張られる側**：レンタルサーバー（PHP 8.0 以上・FTPS でファイルを置ける・管理者の権限は不要）
- **見張る側**：御社の Linux サーバー（Python 3.10 以上・外へ HTTPS とメールを出せる）。サイトの中身や記録は、ここにだけ残ります

## 1. 見張る側を用意する

```
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
mkdir -p rules && curl -sL https://github.com/jvoisin/php-malware-finder/archive/refs/heads/master.tar.gz | tar xz -C rules
```

**確認**：`ls rules/php-malware-finder-master/data/php.yar` があること。

## 2. 設定を書く

1. `config.example.json` を `config.json` に写して書き換える
   - `server.fs_home` と各サイトの `root` は、**サーバーの中から見たパス**です。FTP で見えるパスとは違います。分からなければ、`<?php echo __DIR__;` だけの PHP を1本置いて開き、表示されたパスから組み立て、確かめたらその PHP を消してください
   - `server.ftp_home` は**公開フォルダの外**にします（公開フォルダの中に置くと、台帳が外から読めるおそれがあります）
   - `local_dirs` には、サイトに上げる前のファイルが置いてある手元のフォルダを書きます。ここと中身が同じファイルは「自社の更新」として知らせません
2. `.env.example` を `.env` に写し、合言葉（`openssl rand -hex 32`）・FTP・メールの値を書く。`.env` と `config.json` は人に渡さない

## 3. 見張り役を置く

```
.venv/bin/python scripts/deploy.py
```

**確認**：
- `curl -s -o /dev/null -w '%{http_code}' -X POST <agent_url>` が **404** になること（署名の無い呼び出しは断る）
- `.venv/bin/python scripts/agent_call.py scan` が `"ok": true` を返し、初回は `baseline: true`（台帳を作っただけ）になること

## 4. いま置いてあるものを全部検査する（初回だけ）

```
.venv/bin/python scripts/watch.py --sweep --no-mail
```

見つかったものは1件ずつ中身を確かめてください。正規のライブラリが反応しただけなら、`config.json` の `policy_local.yara_allow` に場所と理由を書くか、`--accept "理由"` で確認済みにします。**中身を見ずに確認済みにしないでください。**

## 5. 毎時・毎日動かす

cron の例：

```
5 * * * *  cd /path/to/ksecwatch && .venv/bin/python scripts/watch.py >> outputs/watch.log 2>&1
35 4 * * * cd /path/to/ksecwatch && .venv/bin/python scripts/watch.py --full >> outputs/watch.log 2>&1
```

**確認**：試しに公開フォルダへ中身の無害な PHP（`<?php echo 1;`）を1本置き、次の見張りで `alert` として出ること。`--no-mail` を外した実行で、`alert_to` の受信箱に**メールが届いたこと**まで確かめてから、その PHP を消してください。

## 6. 記録を見る

```
.venv/bin/python scripts/watch.py --report        # 直近の実行と、まだ確かめていない疑い
.venv/bin/python scripts/make_report.py           # outputs/report.html（社内で見る報告ページ）
```

報告ページにはサイトのファイルの場所が出るので、公開のサーバーには置かないでください。

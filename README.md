# Kurage Security Watch（ksecwatch）

レンタルサーバー（管理者の権限が無い共有サーバー）に置いたサイトが、書き換えられていないか・何か置かれていないかを毎時見張り、見つけたらメールで知らせるシステム。

デモ：https://proto.exbridge.jp/ksecwatch/ （架空の会社のサイトの記録）

## しくみ

```
見張る側（御社の Linux サーバー・毎時）            レンタルサーバー
  scripts/watch.py ── 署名つき HTTPS ──▶ 公開フォルダの agent.php（呼び出し口だけ）
                                          └ 公開フォルダの外の agent_main.php（権限 700）
                                             全ファイルの 大きさ・更新日時・ctime・権限 を台帳と比べ、違いだけ返す
  ├ 手元（config.json の local_dirs）に同じ中身があれば「自社の更新」として知らせない
  ├ 増えた・変わった PHP などは中身をもらい、YARA（php-malware-finder）にかける
  ├ データ入れの PHP（Bludit の databases など）は、先頭の止めの1行が崩れていないかを見る
  └ 見つけたら config.json の alert_to にメール（同じ中身は2回知らせない）
```

- 当社の4サイト・約17万ファイルで、毎時の見張りはサーバーの中で2秒ほど。FTP で一覧を取ると10分以上かかり、接続を重ねるとサーバー会社に遮断されるので、FTP では見ない
- 中身の指紋（SHA-256）は、変わったものだけ取り直す。更新日時は touch で戻せるが ctime は戻せないので ctime も見る。1日1回、全部の指紋を取り直す（--full）
- マルウェアの判定はレンタルサーバーではしない（共有サーバーの CPU を使わない・誤検知の調整を見張る側で済ませる）
- 呼び出し口は、合言葉の HMAC 署名と時刻（ミリ秒・5分以内・前回より新しい）が合うときだけ動き、それ以外は 404

## 使い方

```
.venv/bin/python scripts/watch.py            # 毎時：変わったファイルを調べる
.venv/bin/python scripts/watch.py --full     # 毎日：中身の指紋を全部取り直して比べる
.venv/bin/python scripts/watch.py --sweep    # いま置いてある PHP などを全部 YARA にかける（初回・ルールを変えたとき）
.venv/bin/python scripts/watch.py --report   # 直近の結果と、まだ確かめていない疑い
.venv/bin/python scripts/watch.py --accept "理由"   # 確かめた疑いを確認済みにする（中身が変われば、また知らせる）
.venv/bin/python scripts/make_report.py      # outputs/report.html（社内で見る報告ページ）
.venv/bin/python scripts/deploy.py           # 見張り役を置く（config.php はその場で作り、手元に残さない）
```

設置は INSTALL.md（AIエージェントに渡せば手順どおりに進めます）。

## 決まり（policy.json と config.json の policy_local）

- `data_php` … サーバー自身が書き換えるデータ入れの PHP。変化は知らせず、止めの1行（`<?php exit; ?>`・Bludit の `defined('BLUDIT') or die(...)`）のあとに `<?` が無いことを確かめる
- `quiet` … サーバー側で作り直されるのがふつうのもの（Laravel の views など）
- `yara_allow` … YARA が正規のものに反応すると分かっているもの
- HTML・SVG の変化と、消えたファイルは記録だけ
- 日本語の文字に反応する NonPrintableChars と、`@include` に反応する規則は外している

## 使っている OSS

- php-malware-finder の規則（LGPL-3.0。INSTALL.md の手順で取ってくる。この配布物には含めない）
- YARA / yara-python（BSD-3-Clause / Apache-2.0）

このシステム自体は MIT License。提供：株式会社エクスブリッジ

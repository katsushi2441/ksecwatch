<?php
/* Kurage Security Watch（ksecwatch）の見張り役。共有レンタルサーバーの中で動く。
   公開フォルダには呼び出し口（agent.php）だけを置き、これと台帳は公開フォルダの外に置く。
   マルウェアかどうかの判定はここではしない（共有サーバーの CPU を使わない・誤検知の調整を当社側で済ませる）。
   変わったファイルの中身を当社のサーバーへ渡し、当社側で YARA（php-malware-finder）にかける。

   当社のサーバーから署名つきで呼ばれたときだけ動く（合言葉の HMAC・時刻（ミリ秒）のずれ5分まで・同じか前の時刻は使えない。違えば 404）。
   - scan  … 全部のファイルの大きさ・更新日時・ctime・権限をサーバーの中で見て、台帳と比べる。
             中身の指紋（SHA-256）は、変わったものだけ取り直す。更新日時は touch で戻せるが ctime は戻せないので、ctime も見る。
             初回は台帳を作るだけ。
   - full  … 中身の指紋を全部取り直して比べる（1日1回の保険。ctime まで戻すような手口に備える）
   - list  … 台帳の PHP などを端から順に返す（cursor で続きから。初めに1回、全部を当社側で調べるため）
   - fetch … 指定したファイルの中身を返す（gzip＋base64。1回 8MB まで） */

const KSW_HOME = __DIR__;           // 公開フォルダの外（scripts/deploy.py が置く）
const KSW_CODE = '~(\.(php\d?|phtml|phar|inc|js|mjs|html?|svg|py|pl|cgi|sh|ini)$)|(^\.htaccess$)|(^\.user\.ini$)~i';
const KSW_DOUBLE = '~\.php\d?\.~i';   // shell.php.jpg のような二重の拡張子
const KSW_MAX_HASH = 5242880;          // これより大きいファイルは中身を見ない（大きさ・日時だけ）
const KSW_MAX_EVENTS = 500;            // 1回で返す変化の上限（それ以上は件数だけ）
const KSW_FETCH_MAX = 8388608;         // fetch で1回に返す中身の合計の上限

require KSW_HOME . '/config.php';      // KSW_SECRET・KSW_SITES（scripts/deploy.py が作る）

function ksw_out($code, $data)
{
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

/* 署名を確かめる。合わなければ、ここに何も無いふりをする */
function ksw_auth($body)
{
    $ts = $_SERVER['HTTP_X_KSW_TIME'] ?? '';
    $sig = $_SERVER['HTTP_X_KSW_SIG'] ?? '';
    $ok = $_SERVER['REQUEST_METHOD'] === 'POST' && ctype_digit($ts) && abs(round(microtime(true) * 1000) - (int)$ts) <= 300000
        && hash_equals(hash_hmac('sha256', $ts . "\n" . $body, KSW_SECRET), $sig);
    if (!$ok) {
        http_response_code(404);
        exit;
    }
    $f = KSW_HOME . '/data/last_ts';
    $last = (int)@file_get_contents($f);
    if ((int)$ts <= $last) {   // 同じ署名の使い回しを断る
        http_response_code(404);
        exit;
    }
    file_put_contents($f, $ts, LOCK_EX);
}

function ksw_db()
{
    $db = new PDO('sqlite:' . KSW_HOME . '/data/manifest.sqlite');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->exec('PRAGMA journal_mode=WAL');
    $db->exec('CREATE TABLE IF NOT EXISTS files(site TEXT, path TEXT, size INTEGER, mtime INTEGER, ctime INTEGER, mode INTEGER, sha TEXT, code INTEGER,
        PRIMARY KEY(site, path))');
    return $db;
}

/* フォルダをたどって、ファイルの一覧（相対パス → 大きさ・日時・権限）を返す。シンボリックリンクの先へは入らない */
function ksw_walk($root, $skip)
{
    $out = [];
    $stack = [''];
    while ($stack) {
        $rel = array_pop($stack);
        $names = @scandir($root . $rel);
        if ($names === false) {
            continue;
        }
        foreach ($names as $n) {
            if ($n === '.' || $n === '..') {
                continue;
            }
            $p = $rel . '/' . $n;
            $st = @lstat($root . $p);
            if (!$st) {
                continue;
            }
            $type = $st['mode'] & 0170000;
            if ($type === 0040000) {
                if (!in_array($p, $skip, true)) {
                    $stack[] = $p;
                }
            } elseif ($type === 0100000) {
                $out[$p] = [$st['size'], $st['mtime'], $st['ctime'], $st['mode'] & 07777];
            }
        }
    }
    return $out;
}

function ksw_is_code($path)
{
    $n = basename($path);
    return preg_match(KSW_CODE, $n) || preg_match(KSW_DOUBLE, $n);
}

function ksw_scan($full)
{
    $db = ksw_db();
    $events = [];
    $nevents = 0;
    $sites = [];
    foreach (KSW_SITES as $site => $cfg) {
        $t = microtime(true);
        $root = $cfg['root'];
        $old = [];
        $q = $db->prepare('SELECT path, size, mtime, ctime, mode, sha, code FROM files WHERE site = ?');
        $q->execute([$site]);
        foreach ($q as $r) {
            $old[$r['path']] = $r;
        }
        $baseline = !$old;
        $found = ksw_walk($root, $cfg['skip'] ?? []);
        $hashed = 0;
        $db->beginTransaction();
        $up = $db->prepare('INSERT OR REPLACE INTO files(site, path, size, mtime, ctime, mode, sha, code) VALUES (?,?,?,?,?,?,?,?)');
        $add = function ($e) use (&$events, &$nevents) {
            $nevents++;
            if (count($events) < KSW_MAX_EVENTS) {
                $events[] = $e;
            }
        };
        foreach ($found as $path => [$size, $mtime, $ctime, $mode]) {
            $prev = $old[$path] ?? null;
            $code = ksw_is_code($path) ? 1 : 0;
            $meta = !$prev || $prev['size'] != $size || $prev['mtime'] != $mtime || $prev['ctime'] != $ctime || $prev['mode'] != $mode;
            if (!$meta && !$full) {
                continue;
            }
            $sha = $prev['sha'] ?? null;
            if ($code && $size <= KSW_MAX_HASH && ($meta || $full)) {
                $sha = @hash_file('sha256', $root . $path) ?: null;
                $hashed++;
            }
            if (!$baseline && $code) {
                $info = ['site' => $site, 'path' => $path, 'size' => $size, 'mtime' => date('Y-m-d H:i:s', $mtime), 'mode' => sprintf('%o', $mode)];
                if (!$prev) {
                    $add(['kind' => 'added', 'sha' => $sha] + $info);
                } elseif ($sha !== $prev['sha'] && ($sha !== null || $prev['sha'] !== null)) {
                    $add(['kind' => 'modified', 'sha' => $sha, 'old_size' => (int)$prev['size']] + $info);
                }
                if ($prev && $prev['mode'] != $mode) {
                    $add(['kind' => 'perm', 'old_mode' => sprintf('%o', $prev['mode'])] + $info);
                }
                // 更新日時が戻されている（中身が変わったのに、日時が前より古いか同じ）
                if ($prev && $sha !== $prev['sha'] && $mtime <= $prev['mtime']) {
                    $add(['kind' => 'mtime_rollback'] + $info);
                }
            }
            $up->execute([$site, $path, $size, $mtime, $ctime, $mode, $sha, $code]);
        }
        $del = $db->prepare('DELETE FROM files WHERE site = ? AND path = ?');
        foreach (array_diff_key($old, $found) as $path => $prev) {
            if ($prev['code']) {
                $add(['kind' => 'removed', 'site' => $site, 'path' => $path]);
            }
            $del->execute([$site, $path]);
        }
        $db->commit();
        $sites[$site] = ['files' => count($found), 'hashed' => $hashed, 'baseline' => $baseline, 'sec' => round(microtime(true) - $t, 2)];
    }
    return ['sites' => $sites, 'events' => $events, 'events_total' => $nevents];
}

function ksw_list($cursor)
{
    $q = ksw_db()->prepare('SELECT site, path, size, sha, mtime FROM files WHERE code = 1 AND (site || char(1) || path) > ? ORDER BY site || char(1) || path LIMIT 5000');
    $q->execute([$cursor]);
    $rows = $q->fetchAll(PDO::FETCH_NUM);
    return ['rows' => $rows, 'cursor' => $rows ? end($rows)[0] . "\1" . end($rows)[1] : null];
}

/* 中身を返す。台帳にある PHP など（code）だけ。読んだ中身の指紋も付ける */
function ksw_fetch($items)
{
    $q = ksw_db()->prepare('SELECT 1 FROM files WHERE site = ? AND path = ? AND code = 1');
    $out = [];
    $total = 0;
    $more = [];
    foreach ($items as $it) {
        [$site, $path] = $it + ['', ''];
        $q->execute([$site, $path]);
        if (!isset(KSW_SITES[$site]) || !$q->fetchColumn()) {
            $out[] = ['site' => $site, 'path' => $path, 'error' => 'not_in_manifest'];
            continue;
        }
        $file = KSW_SITES[$site]['root'] . $path;
        $size = @filesize($file);
        if ($size === false) {
            $out[] = ['site' => $site, 'path' => $path, 'error' => 'gone'];
            continue;
        }
        if ($size > KSW_MAX_HASH) {
            $out[] = ['site' => $site, 'path' => $path, 'error' => 'too_large', 'size' => $size];
            continue;
        }
        if ($total + $size > KSW_FETCH_MAX && $out) {
            $more[] = [$site, $path];
            continue;
        }
        $data = @file_get_contents($file);
        $total += strlen((string)$data);
        $out[] = ['site' => $site, 'path' => $path, 'sha' => hash('sha256', (string)$data), 'gz' => base64_encode(gzencode((string)$data, 6))];
    }
    return ['files' => $out, 'more' => $more];
}

$body = file_get_contents('php://input');
ksw_auth($body);
$req = json_decode($body, true) ?: [];
@set_time_limit(170);
$lock = fopen(KSW_HOME . '/data/lock', 'c');
if (!flock($lock, LOCK_EX | LOCK_NB)) {
    ksw_out(409, ['error' => '前の実行がまだ終わっていません']);
}
$t0 = microtime(true);
$act = $req['action'] ?? 'scan';
if ($act === 'list') {
    $res = ksw_list((string)($req['cursor'] ?? ''));
} elseif ($act === 'fetch') {
    $res = ksw_fetch((array)($req['files'] ?? []));
} elseif ($act === 'scan' || $act === 'full') {
    $res = ksw_scan($act === 'full');
} else {
    ksw_out(400, ['error' => 'action が違います']);
}
ksw_out(200, ['ok' => true, 'action' => $act, 'sec' => round(microtime(true) - $t0, 2), 'php' => PHP_VERSION,
    'limits' => ['max_execution_time' => ini_get('max_execution_time'), 'memory_limit' => ini_get('memory_limit'), 'peak_mb' => round(memory_get_peak_usage() / 1048576, 1)]] + $res);

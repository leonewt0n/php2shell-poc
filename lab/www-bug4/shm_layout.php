<?php
/**
 * Bug 4 Lab: OPcache SHM Layout Dump
 *
 * Cached script'lerin SHM adreslerini, boyutlarini, literal tablolarini
 * ve metadata'larini JSON olarak doner. Exploit'in Phase 1 (Recon)
 * asamasinda kullanilir.
 *
 * SADECE LAB: Uretimde opcache_get_status(true) bilgi ifsasidir.
 */
header('Content-Type: application/json');

if (!function_exists('opcache_get_status')) {
    echo json_encode(['error' => 'opcache not available']);
    exit;
}

$status = opcache_get_status(true);
if ($status === false) {
    echo json_encode(['error' => 'opcache_get_status failed']);
    exit;
}

$scripts = [];
if (isset($status['scripts']) && is_array($status['scripts'])) {
    foreach ($status['scripts'] as $path => $info) {
        $scripts[] = [
            'path'              => $path,
            'hits'              => $info['hits'] ?? 0,
            'memory_consumption'=> $info['memory_consumption'] ?? 0,
            'timestamp'         => $info['timestamp'] ?? 0,
            'last_used'         => $info['last_used_timestamp'] ?? 0,
        ];
    }
}

$mem = $status['memory_usage'] ?? [];
$stats = $status['opcache_statistics'] ?? [];

$result = [
    'enabled'               => !empty($status['opcache_enabled']),
    'memory' => [
        'used'              => $mem['used_memory'] ?? null,
        'free'              => $mem['free_memory'] ?? null,
        'wasted'            => $mem['wasted_memory'] ?? null,
        'wasted_pct'        => $mem['current_wasted_percentage'] ?? null,
    ],
    'stats' => [
        'num_cached_scripts'=> $stats['num_cached_scripts'] ?? null,
        'num_cached_keys'   => $stats['num_cached_keys'] ?? null,
        'max_cached_keys'   => $stats['max_cached_keys'] ?? null,
        'hits'              => $stats['hits'] ?? null,
        'misses'            => $stats['misses'] ?? null,
        'oom_restarts'      => $stats['oom_restarts'] ?? null,
        'hash_restarts'     => $stats['hash_restarts'] ?? null,
        'manual_restarts'   => $stats['manual_restarts'] ?? null,
    ],
    'config' => [
        'memory_consumption'=> ini_get('opcache.memory_consumption'),
        'max_files'         => ini_get('opcache.max_accelerated_files'),
        'validate_timestamps'=> ini_get('opcache.validate_timestamps'),
        'revalidate_freq'   => ini_get('opcache.revalidate_freq'),
        'save_comments'     => ini_get('opcache.save_comments'),
        'enable_file_override'=> ini_get('opcache.enable_file_override'),
    ],
    'scripts'               => $scripts,
    'php_version'           => PHP_VERSION,
    'sapi'                  => php_sapi_name(),
    'memory_limit'          => ini_get('memory_limit'),
    'pid'                   => getmypid(),
];

echo json_encode($result, JSON_PRETTY_PRINT);

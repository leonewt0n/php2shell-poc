<?php
// Bug 4 olcum ucu: OPcache durumunun kucuk bir ozetini JSON doner.
// bug4_opcache_confusion.py baseline ile karsilastirip tutarsizlik arar.
// SADECE LAB: bu dosyayi uretime koymayin (bilgi ifsasi).
header('Content-Type: application/json');
if (!function_exists('opcache_get_status')) {
    echo json_encode(array('enabled' => false));
    exit;
}
$st = opcache_get_status(false);
if ($st === false) {
    echo json_encode(array('enabled' => false));
    exit;
}
$stats = isset($st['opcache_statistics']) ? $st['opcache_statistics'] : array();
$mem   = isset($st['memory_usage']) ? $st['memory_usage'] : array();
echo json_encode(array(
    'enabled'            => !empty($st['opcache_enabled']),
    'num_cached_scripts' => isset($stats['num_cached_scripts']) ? $stats['num_cached_scripts'] : null,
    'num_cached_keys'    => isset($stats['num_cached_keys']) ? $stats['num_cached_keys'] : null,
    'max_cached_keys'    => isset($stats['max_cached_keys']) ? $stats['max_cached_keys'] : null,
    'used_memory'        => isset($mem['used_memory']) ? $mem['used_memory'] : null,
    'free_memory'        => isset($mem['free_memory']) ? $mem['free_memory'] : null,
));

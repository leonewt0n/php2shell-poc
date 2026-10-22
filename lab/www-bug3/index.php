<?php
// Bug 3 CONSUMER: icerik onemsizdir. UAF, bu dosya calismadan ONCE,
// .htaccess'teki deprecated php_value islenirken (request startup
// oncesi hata callback'inde) tetiklenir. Saglikli worker'da 200 donmeli.
header('Content-Type: text/plain');
echo "ok\n";

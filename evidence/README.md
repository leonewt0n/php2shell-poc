# Kanıt Dosyaları — Bütünlük ve Kapsam Notu

Bu dizindeki dosyalar, 22 Ekim 2026 tarihli lab çalıştırmalarının
**metin transkriptleridir**. Bütünlük doğrulaması:

```bash
cd evidence && shasum -a 256 -c SHA256SUMS
```

## Bilinen sınırlamalar (dürüstlük notu)

- Transkriptler ham artefakt değildir: `*.bin` bellek dökümleri,
  pcap kayıtları, Valgrind/ASAN raporları ve PHP build hash'leri
  bu repoya **dahil edilmemiştir** (`.gitignore` `*.bin`/`*.log`
  dosyalarını dışlar).
- Aynı adreslerin birden çok transkriptte tekrarı, çalıştırmaların
  aynı lab oturumundan alınmış olmasından kaynaklanabilir; bağımsız
  tekrar için lab'ı ayağa kaldırıp çalıştırmayı kendiniz yapın
  (`docs/WIZ_REPRODUCTION.md`).
- Yeni bir çalıştırmanın çıktısını eklerken: PHP sürümünü
  (`php -v`), imaj digest'ini ve tarihi transkriptin başına yazın
  ve `SHA256SUMS` dosyasını yeniden üretin.

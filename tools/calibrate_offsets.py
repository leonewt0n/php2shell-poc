#!/usr/bin/env python3
"""
nm ciktisini parse edip exploit offset'lerini cikarir (zif_system, zval_ptr_dtor).

    nm -D /usr/lib/apache2/modules/libphp.so > nm.txt
    python3 calibrate_offsets.py --nm nm.txt
    python3 calibrate_offsets.py --binary /path/to/libphp.so

HTDATA heap'e baglidir, nm'den cikarilamaz (varsayilan: 0x690D8).
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys

# nm satiri ornekleri:
#   0000000000465370 T zif_system
#   000000000065eb60 T zval_ptr_dtor
#   0000000000465370 T _zif_system   (bazi platformlar)
_NM_LINE = re.compile(
    r"^\s*([0-9a-fA-F]+)\s+[A-Za-z]\s+_?([A-Za-z_][\w.]*)\s*$")

WANTED = ("zif_system", "zval_ptr_dtor")


def parse_nm_output(text: str) -> dict[str, int]:
    """nm ciktisindan ilgilenilen sembollerin adres/offset'lerini cikar."""
    found: dict[str, int] = {}
    for line in text.splitlines():
        m = _NM_LINE.match(line)
        if not m:
            continue
        addr, name = int(m.group(1), 16), m.group(2)
        if name in WANTED and name not in found:
            found[name] = addr
    return found


def nm_for_binary(path: str) -> str:
    """Bir ikili/so icin nm calistirip ciktisini dondur."""
    for args in (["nm", "-D", path], ["nm", path]):
        try:
            out = subprocess.run(args, capture_output=True, text=True,
                                 timeout=60)
        except FileNotFoundError:
            raise SystemExit("hata: 'nm' bulunamadi (binutils kurulu olmali)")
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout
    raise SystemExit(f"hata: nm {path!r} icin sembol uretemedi")


def build_offsets(symbols: dict[str, int]) -> dict[str, int]:
    missing = [s for s in WANTED if s not in symbols]
    if missing:
        raise SystemExit(
            "hata: su semboller bulunamadi: " + ", ".join(missing) +
            "\n(stripped ikili olabilir; debug sembollu build gerekir)")
    return {
        "zif_system": symbols["zif_system"],
        "zval_ptr_dtor": symbols["zval_ptr_dtor"],
    }


def format_python(offsets: dict[str, int]) -> str:
    return (
        f"LINUX_ZIF_OFFSET  = 0x{offsets['zif_system']:X}"
        "        # zif_system\n"
        f"LINUX_DTOR_OFFSET = 0x{offsets['zval_ptr_dtor']:X}"
        "       # zval_ptr_dtor"
    )


def format_cli(offsets: dict[str, int]) -> str:
    return (f"--zif-offset 0x{offsets['zif_system']:x} "
            f"--dtor-offset 0x{offsets['zval_ptr_dtor']:x}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="PHP2Shell offset kalibrasyonu (nm -> exploit offsetleri)")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--nm", help="Kaydedilmis nm cikti dosyasi")
    src.add_argument("--binary", help="libphp.so / php ikilisi (nm calistirilir)")
    ap.add_argument("--json", action="store_true", help="JSON cikti")
    args = ap.parse_args()

    if args.nm:
        with open(args.nm, encoding="utf-8", errors="replace") as f:
            text = f.read()
    else:
        text = nm_for_binary(args.binary)

    offsets = build_offsets(parse_nm_output(text))

    if args.json:
        print(json.dumps(
            {"zif_system": hex(offsets["zif_system"]),
             "zval_ptr_dtor": hex(offsets["zval_ptr_dtor"]),
             "htdata_offset": None,
             "htdata_note": "heap kalibrasyonu gerekir (varsayilan 0x690D8)"},
            indent=2))
    else:
        print("[*] Kalibre edilen offset'ler:")
        print()
        print(format_python(offsets))
        print()
        print("[*] Komut satiri olarak:")
        print(f"    {format_cli(offsets)}")
        print()
        print("[!] HTDATA_OFFSET nm ile turetilemez; heap grooming")
        print("    kalibrasyonu gerekir (varsayilan: 0x690D8).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

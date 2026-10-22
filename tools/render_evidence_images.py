#!/usr/bin/env python3
"""
PHP2Shell - Kanit Transkriptlerini Terminal Ekran Goruntusune Cevir
==================================================================

evidence/*.txt dosyalarini koyu temali, terminal penceresi gorunumlu
PNG'lere donusturur (docs/images/evidence-*.png). Boylece README'deki
"ekran goruntuleri" her zaman repodaki gercek kanit metniyle birebir
ayni kalir; calistirma tekrar edilirse ayni komutla yenilenir:

    python3 tools/render_evidence_images.py

Gereksinim: Pillow (pip install pillow). Aracin kendisi icin degil,
yalnizca bu gorsellestirme icin gerekir.
"""
from __future__ import annotations

import os
import sys
import textwrap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(ROOT, "evidence")
OUT_DIR = os.path.join(ROOT, "docs", "images")

FONT_CANDIDATES = [
    "/System/Library/Fonts/Menlo.ttc",
    "/System/Library/Fonts/SFNSMono.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "C:/Windows/Fonts/consola.ttf",
]

BG = (13, 17, 23)          # GitHub dark
TITLE_BG = (22, 27, 34)
FG = (201, 209, 217)
GREEN = (63, 185, 80)
RED = (248, 81, 73)
CYAN = (88, 166, 255)
GRAY = (139, 148, 158)
YELLOW = (210, 153, 34)

FONT_SIZE = 20
LINE_H = 28
PAD = 32
WRAP = 112


def load_font(size):
    from PIL import ImageFont
    for path in FONT_CANDIDATES:
        if os.path.exists(path):
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                continue
    return ImageFont.load_default()


def color_for(line: str):
    s = line.strip()
    if "PROOF:" in s or "uid=" in s or "CONFIRMED" in s or "BASARILI" in s:
        return GREEN
    if s.startswith("[+]") or s.startswith("[!!]"):
        return GREEN
    if s.startswith("[-]"):
        return RED
    if s.startswith("[*]") or s.startswith("[?]"):
        return CYAN
    if set(s) <= set("=-") and len(s) > 10:
        return GRAY
    if s.isupper() and len(s) > 8:
        return YELLOW
    return FG


def render(txt_path: str, png_path: str) -> tuple[int, int]:
    from PIL import Image, ImageDraw
    with open(txt_path, encoding="utf-8", errors="replace") as f:
        raw = f.read().splitlines()

    lines: list[str] = []
    for line in raw:
        lines.extend(textwrap.wrap(line, WRAP) or [""])

    font = load_font(FONT_SIZE)
    font_title = load_font(FONT_SIZE - 4)
    tmp = Image.new("RGB", (10, 10))
    draw = ImageDraw.Draw(tmp)
    text_w = max((draw.textlength(l, font=font) for l in lines), default=0)
    width = int(text_w) + PAD * 2
    title_h = 46
    height = title_h + PAD + LINE_H * len(lines) + PAD

    img = Image.new("RGB", (width, height), BG)
    d = ImageDraw.Draw(img)
    # Baslik cubugu + pencere dugmeleri
    d.rectangle([0, 0, width, title_h], fill=TITLE_BG)
    for i, c in enumerate(((248, 81, 73), (210, 153, 34), (63, 185, 80))):
        x = 18 + i * 26
        d.ellipse([x, 15, x + 14, 29], fill=c)
    title = f"evidence/{os.path.basename(txt_path)}"
    d.text((100, 13), title, font=font_title, fill=GRAY)

    y = title_h + PAD
    for line in lines:
        d.text((PAD, y), line, font=font, fill=color_for(line))
        y += LINE_H

    img.save(png_path)
    return img.size


def main() -> int:
    try:
        import PIL  # noqa: F401
    except ImportError:
        print("hata: Pillow gerekli -> pip install pillow", file=sys.stderr)
        return 1
    os.makedirs(OUT_DIR, exist_ok=True)
    made = 0
    for name in sorted(os.listdir(SRC_DIR)):
        if not name.endswith(".txt"):
            continue
        src = os.path.join(SRC_DIR, name)
        out = os.path.join(OUT_DIR, f"evidence-{name[:-4]}.png")
        w, h = render(src, out)
        print(f"[+] {os.path.relpath(out, ROOT)} ({w}x{h})")
        made += 1
    print(f"[*] {made} gorsel uretildi -> docs/images/")
    return 0


if __name__ == "__main__":
    sys.exit(main())

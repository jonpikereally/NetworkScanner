#!/usr/bin/env python3
"""Draws Network Scanner's icon (radar sweep over a constellation of devices) and writes
NetworkScanner.icns. Needs Pillow: pip3 install pillow. Run from the repo root."""
import io, math, struct
from PIL import Image, ImageDraw, ImageFilter

S = 1024

def draw():
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    # body on the macOS icon grid: 824 square, radius ~185, soft shadow
    shadow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(shadow).rounded_rectangle((100, 112, 924, 936), 185, fill=(0, 0, 0, 110))
    img.alpha_composite(shadow.filter(ImageFilter.GaussianBlur(22)))
    body = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    bd = ImageDraw.Draw(body)
    for y in range(100, 925):  # vertical gradient, deep navy to teal-blue
        t = (y - 100) / 824
        c = (int(10 + 8 * t), int(32 + 60 * t), int(64 + 70 * t), 255)
        bd.line((100, y, 924, y), fill=c)
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle((100, 100, 924, 924), 185, fill=255)
    img.paste(body, (0, 0), mask)

    cx, cy = 512, 512
    layer = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    # sweep wedge, fading
    for i in range(60):
        a0 = -110 + i
        alpha = int(150 * (i / 60) ** 2)
        d.pieslice((cx - 330, cy - 330, cx + 330, cy + 330), a0, a0 + 1.5, fill=(80, 230, 200, alpha))
    # rings and crosshair
    for r in (110, 220, 330):
        d.ellipse((cx - r, cy - r, cx + r, cy + r), outline=(140, 240, 220, 150), width=8)
    d.line((cx - 330, cy, cx + 330, cy), fill=(140, 240, 220, 80), width=5)
    d.line((cx, cy - 330, cx, cy + 330), fill=(140, 240, 220, 80), width=5)
    # devices, linked to the centre
    devices = [(-45, 220), (-150, 290), (20, 300), (160, 160), (110, 280), (-100, 120)]
    pts = [(cx + r * math.cos(math.radians(a)), cy + r * math.sin(math.radians(a))) for a, r in devices]
    for x, y in pts:
        d.line((cx, cy, x, y), fill=(255, 255, 255, 70), width=6)
    glow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    for x, y in pts:
        gd.ellipse((x - 44, y - 44, x + 44, y + 44), fill=(90, 255, 210, 140))
    layer.alpha_composite(glow.filter(ImageFilter.GaussianBlur(18)))
    d = ImageDraw.Draw(layer)
    for x, y in pts:
        d.ellipse((x - 26, y - 26, x + 26, y + 26), fill=(235, 255, 250, 255))
    d.ellipse((cx - 34, cy - 34, cx + 34, cy + 34), fill=(255, 210, 90, 255))
    clipped = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    clipped.paste(layer, (0, 0), Image.composite(layer.getchannel("A"), Image.new("L", (S, S), 0), mask))
    img.alpha_composite(clipped)
    return img

def icns(img, path):
    chunks = b""
    for kind, size in [(b"icp4", 16), (b"icp5", 32), (b"icp6", 64), (b"ic07", 128),
                       (b"ic08", 256), (b"ic09", 512), (b"ic10", 1024)]:
        buf = io.BytesIO()
        img.resize((size, size), Image.LANCZOS).save(buf, "PNG")
        data = buf.getvalue()
        chunks += kind + struct.pack(">I", len(data) + 8) + data
    with open(path, "wb") as f:
        f.write(b"icns" + struct.pack(">I", len(chunks) + 8) + chunks)

if __name__ == "__main__":
    im = draw()
    im.save("icon_1024.png")
    icns(im, "NetworkScanner.icns")
    print("Wrote NetworkScanner.icns and icon_1024.png")

#!/usr/bin/env python3
"""Generate the MacRecon README banner (assets/banner.png) with Pillow.

Rendered at 2x and downsampled, which is what keeps the type edges crisp
rather than relying on Pillow's fairly blunt text antialiasing.
"""

import math
import os

from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "assets", "banner.png")

W, H = 1280, 440
SCALE = 2
W2, H2 = W * SCALE, H * SCALE

BG0 = (8, 12, 18)
BG1 = (14, 24, 37)
TEAL = (40, 224, 200)
BLUE = (61, 139, 253)
WHITE = (233, 240, 246)
MUTED = (139, 152, 169)
CARD = (22, 27, 34)
BORDER = (44, 54, 68)
AMBER = (255, 138, 61)

SUP = "/System/Library/Fonts/Supplemental/"
SYS = "/System/Library/Fonts/"


def font(path, size, index=0):
    return ImageFont.truetype(path, size * SCALE, index=index)


def F_BLACK(s):
    return font(SUP + "Arial Black.ttf", s)


def F_BOLD(s):
    return font(SUP + "Arial Bold.ttf", s)


def F_REG(s):
    return font(SUP + "Arial.ttf", s)


def F_MONO(s):
    return font(SYS + "Menlo.ttc", s)


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def tracked(d, xy, text, fnt, fill, tracking=0):
    """Draw text with letter-spacing; returns the end x."""
    x, y = xy
    for ch in text:
        d.text((x, y), ch, font=fnt, fill=fill)
        x += d.textlength(ch, font=fnt) + tracking * SCALE
    return x


def text_w(d, text, fnt, tracking=0):
    return sum(d.textlength(c, font=fnt) + tracking * SCALE for c in text)


def _shield(d, cx, cy, r, color):
    """A small shield outline, drawn rather than typed (see centre glyph)."""
    pts = [
        (cx, cy - r),
        (cx + r * 0.82, cy - r * 0.6),
        (cx + r * 0.82, cy + r * 0.18),
        (cx, cy + r),
        (cx - r * 0.82, cy + r * 0.18),
        (cx - r * 0.82, cy - r * 0.6),
    ]
    d.polygon(pts, outline=color, fill=None, width=max(1, int(r * 0.22)))


def build():
    img = Image.new("RGB", (W2, H2), BG0)
    d = ImageDraw.Draw(img, "RGBA")

    # Diagonal-ish gradient.
    for y in range(H2):
        d.line([(0, y), (W2, y)], fill=lerp(BG0, BG1, (y / H2) ** 0.85))

    # Dot grid.
    step = 26 * SCALE
    for gy in range(0, H2, step):
        for gx in range(0, W2, step):
            d.ellipse([gx, gy, gx + 2, gy + 2], fill=(255, 255, 255, 9))

    # --- right: concentric "scan" rings around an Apple-ish mark -----------
    cx, cy = int(W2 * 0.795), int(H2 * 0.50)

    glow = Image.new("RGBA", (W2, H2), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    gd.ellipse([cx - 150 * SCALE, cy - 150 * SCALE,
                cx + 150 * SCALE, cy + 150 * SCALE],
               fill=(40, 224, 200, 30))
    glow = glow.filter(ImageFilter.GaussianBlur(60 * SCALE // 2))
    img = Image.alpha_composite(img.convert("RGBA"), glow).convert("RGB")
    d = ImageDraw.Draw(img, "RGBA")

    for i, r in enumerate(range(58, 250, 32)):
        a = max(78 - i * 10, 16)
        d.ellipse([cx - r * SCALE, cy - r * SCALE,
                   cx + r * SCALE, cy + r * SCALE],
                  outline=(40, 224, 200, a), width=SCALE)

    d.line([(cx - 250 * SCALE, cy), (cx + 250 * SCALE, cy)],
           fill=(40, 224, 200, 24), width=SCALE)
    d.line([(cx, cy - 250 * SCALE), (cx, cy + 250 * SCALE)],
           fill=(40, 224, 200, 24), width=SCALE)

    # Sweep wedge.
    sweep = Image.new("RGBA", (W2, H2), (0, 0, 0, 0))
    sd = ImageDraw.Draw(sweep)
    R = 244 * SCALE
    sd.pieslice([cx - R, cy - R, cx + R, cy + R], -62, -20,
                fill=(40, 224, 200, 55))
    img = Image.alpha_composite(img.convert("RGBA"), sweep).convert("RGB")
    d = ImageDraw.Draw(img, "RGBA")

    # Detected "hosts".
    for ang, rr, col in [(-38, 148, TEAL), (-74, 208, BLUE), (-14, 104, TEAL),
                         (-104, 178, MUTED), (-140, 128, AMBER),
                         (-168, 222, MUTED), (32, 196, BLUE)]:
        bx = cx + int(math.cos(math.radians(ang)) * rr * SCALE)
        by = cy + int(math.sin(math.radians(ang)) * rr * SCALE)
        d.ellipse([bx - 4 * SCALE, by - 4 * SCALE,
                   bx + 4 * SCALE, by + 4 * SCALE], fill=col)
        d.ellipse([bx - 9 * SCALE, by - 9 * SCALE,
                   bx + 9 * SCALE, by + 9 * SCALE],
                  outline=col + (90,), width=SCALE)

    # Centre glyph: a magnifier over the scanned host. Drawn as vectors --
    # Apple Symbols has no U+F8FF outline and Pillow won't rasterise colour
    # emoji, so both the  and 🔍 codepoints render as tofu here.
    d.ellipse([cx - 32 * SCALE, cy - 32 * SCALE,
               cx + 32 * SCALE, cy + 32 * SCALE],
              fill=(10, 16, 22), outline=TEAL, width=2 * SCALE)
    d.ellipse([cx - 13 * SCALE, cy - 16 * SCALE,
               cx + 9 * SCALE, cy + 6 * SCALE],
              outline=TEAL, width=3 * SCALE)
    d.line([(cx + 7 * SCALE, cy + 4 * SCALE),
            (cx + 17 * SCALE, cy + 15 * SCALE)],
           fill=TEAL, width=4 * SCALE)

    # --- left accent bars ---------------------------------------------------
    d.rectangle([0, 0, 7 * SCALE, H2], fill=TEAL)
    d.rectangle([7 * SCALE, 0, 11 * SCALE, H2], fill=BLUE)

    LX = 68 * SCALE

    # Eyebrow pill.
    eyebrow = "macOS RECON TOOLKIT"
    ef = F_BOLD(13)
    ew = text_w(d, eyebrow, ef, 2)
    d.rounded_rectangle([LX, 52 * SCALE, LX + ew + 34 * SCALE, 84 * SCALE],
                        radius=16 * SCALE, fill=(40, 224, 200, 26),
                        outline=(40, 224, 200, 125), width=SCALE)
    tracked(d, (LX + 17 * SCALE, 60 * SCALE), eyebrow, ef, TEAL, 2)

    # Title.
    ty = 94 * SCALE
    x = tracked(d, (LX - 2 * SCALE, ty), "Mac", F_BLACK(80), TEAL)
    tracked(d, (x + 4 * SCALE, ty), "Recon", F_BLACK(80), WHITE)

    # Tagline.
    tracked(d, (LX, 208 * SCALE), "macOS  INFORMATION  GATHERER",
            F_BOLD(21), WHITE, 3)

    # Description.
    d.text((LX, 246 * SCALE),
           "System, hardware, users, network, persistence and a graded",
           font=F_REG(17), fill=MUTED)
    d.text((LX, 271 * SCALE),
           "security audit — read-only, on the Mac in front of you.",
           font=F_REG(17), fill=MUTED)

    # Feature chips.
    chips = ["System", "Hardware", "Users", "Network", "Software",
             "Persistence", "Audit"]
    chx, chy = LX, 312 * SCALE
    cf = F_BOLD(12)
    for c in chips:
        w = d.textlength(c, font=cf) + 24 * SCALE
        d.rounded_rectangle([chx, chy, chx + w, chy + 29 * SCALE],
                            radius=14 * SCALE, fill=CARD, outline=BORDER,
                            width=SCALE)
        d.text((chx + 12 * SCALE, chy + 7 * SCALE), c, font=cf,
               fill=(198, 209, 221))
        chx += w + 8 * SCALE

    # Redaction badge -- the feature worth advertising on the banner.
    badge = "REDACTION BY DEFAULT"
    bf = F_BOLD(12)
    bw = text_w(d, badge, bf, 1)
    by = 358 * SCALE
    d.rounded_rectangle([LX, by, LX + bw + 48 * SCALE, by + 28 * SCALE],
                        radius=14 * SCALE, fill=(40, 224, 200, 22),
                        outline=(40, 224, 200, 110), width=SCALE)
    _shield(d, LX + 15 * SCALE, by + 14 * SCALE, 8 * SCALE, TEAL)
    tracked(d, (LX + 30 * SCALE, by + 7 * SCALE), badge, bf, TEAL, 1)

    # Command hint.
    cmd = "$ python3 macrecon.py"
    d.text((LX, 398 * SCALE), cmd, font=F_MONO(14), fill=TEAL)
    bx = LX + int(d.textlength(cmd, font=F_MONO(14))) + 14 * SCALE
    d.text((bx, 399 * SCALE), "·  read-only  ·  by at0m-b0mb",
           font=F_REG(13), fill=MUTED)

    out = img.resize((W, H), Image.LANCZOS)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    out.save(OUT)
    print("saved", OUT, out.size)


if __name__ == "__main__":
    build()

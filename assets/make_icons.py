"""Generates the NtSentry icon assets: a radar with an "NT" badge at the bottom left.

Outputs (next to this script):
  ntsentry.ico         16-256 px, embedded in the executable by build.rs
  icon-64.rgba         64x64 RGBA, window icon
  icon-32.rgba         32x32 RGBA, notification-area icon
  icon-32-alert.rgba   32x32 RGBA, notification-area icon while an alert is active

Requires Pillow and the Segoe UI fonts that ship with Windows:
    python make_icons.py
"""
import os

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
S = 1024
TEAL = (25, 135, 150, 255)
TEAL_DARK = (12, 70, 82, 255)
SCOPE = (14, 52, 60, 255)
TEAL_LIGHT = (90, 220, 225, 255)
AMBER = (245, 175, 40, 255)
WHITE = (245, 248, 250, 255)
RED = (205, 55, 45, 255)
RED_DARK = (110, 25, 20, 255)


def font(size):
    for name in ("seguibl.ttf", "segoeuib.ttf", "arialbd.ttf"):
        path = os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "Fonts", name)
        if os.path.exists(path):
            return ImageFont.truetype(path, size)
    raise SystemExit("A bold Windows font (Segoe UI Black/Bold or Arial Bold) is required")


def p(x, y):
    return (x * S, y * S)


def draw(alert=False):
    im = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    # Radar scope.
    d.ellipse([p(0.04, 0.04), p(0.96, 0.96)], fill=TEAL_DARK)
    d.ellipse([p(0.08, 0.08), p(0.92, 0.92)], fill=SCOPE)
    for r, w in ((0.42, 14), (0.28, 12), (0.14, 10)):
        d.ellipse([p(0.5 - r, 0.5 - r), p(0.5 + r, 0.5 + r)], outline=TEAL, width=w)
    d.line([p(0.5, 0.08), p(0.5, 0.92)], fill=TEAL, width=8)
    d.line([p(0.08, 0.5), p(0.92, 0.5)], fill=TEAL, width=8)
    sweep = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    sd = ImageDraw.Draw(sweep)
    for i in range(30):
        sd.pieslice([p(0.08, 0.08), p(0.92, 0.92)], -60 + i * 2, -58 + i * 2, fill=(90, 220, 220, 10 + i * 6))
    im.alpha_composite(sweep)
    d.line([p(0.5, 0.5), p(0.92, 0.5)], fill=TEAL_LIGHT, width=14)
    r = 0.045
    d.ellipse([p(0.70 - r, 0.34 - r), p(0.70 + r, 0.34 + r)], fill=RED if alert else AMBER)
    # "NT" badge, bottom left.
    outer, inner = (RED_DARK, RED) if alert else (TEAL_DARK, TEAL)
    d.rounded_rectangle([p(0.02, 0.66), p(0.50, 0.96)], radius=S * 0.08, fill=outer)
    d.rounded_rectangle([p(0.05, 0.69), p(0.47, 0.93)], radius=S * 0.06, fill=inner)
    f = font(int(S * 0.20))
    box = d.textbbox((0, 0), "NT", font=f)
    w, h = box[2] - box[0], box[3] - box[1]
    d.text((0.26 * S - w / 2 - box[0], 0.81 * S - h / 2 - box[1]), "NT", font=f, fill=WHITE)
    return im


def write_rgba(image, size, name):
    data = image.resize((size, size), Image.LANCZOS).tobytes()
    assert len(data) == size * size * 4
    with open(os.path.join(HERE, name), "wb") as f:
        f.write(data)


def main():
    normal, alert = draw(), draw(alert=True)
    big = normal.resize((256, 256), Image.LANCZOS)
    big.save(
        os.path.join(HERE, "ntsentry.ico"),
        sizes=[(16, 16), (20, 20), (24, 24), (32, 32), (40, 40), (48, 48), (64, 64), (128, 128), (256, 256)],
    )
    write_rgba(normal, 64, "icon-64.rgba")
    write_rgba(normal, 32, "icon-32.rgba")
    write_rgba(alert, 32, "icon-32-alert.rgba")
    print("icons written to", HERE)


if __name__ == "__main__":
    main()

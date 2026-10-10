#!/usr/bin/env python3
"""Build every app icon from the brand avatar.

The app icon is the avatar of the brand kit (public/marketing/brand/privacynotes-avatar.svg):
Brand Blue fills the whole frame, the corner fold sits in the top-right corner, and the
padlock and check sit in the middle. The padlock and check come from
packages/web/icon/app-icon-glyph.svg; the blue and the fold are drawn here, so the layered
formats (Android, Icon Composer) can carry them as separate layers. Each platform gets the
shape its system expects:

  iOS        square, no corners (the system masks it); light and dark both blue, tinted
  Android    adaptive: the blue and the fold as the background layer, the glyph as the
             foreground, scaled so the launcher's 72dp viewport shows the whole avatar
  Windows    rounded tile that fills the canvas (the .ico has no system mask)
  Linux      the same tile as Windows
  macOS 11+  pre-rounded squircle on Apple's 824px grid with a soft shadow
  macOS 26   glyph.png and fold.png for AppIcon.icon; the blue is its fill, in dark too

Run from packages/desktop through `pnpm icon`. It does not build Assets.car, which
still needs Icon Composer and actool (ops/docs/macos-icon.md).
Needs Pillow and the Tauri CLI, which rasterizes the SVG.
"""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw, ImageFilter

HERE = Path(__file__).resolve().parent.parent
ICONS = HERE / "src-tauri" / "icons"
GLYPH_SVG = HERE.parent / "web" / "icon" / "app-icon-glyph.svg"

# Spec: ops/docs/design-decisions.md (social avatar) - the avatar's colors and fold
BLUE = (0x1E, 0x40, 0xAF)
FOLD = (0x4F, 0x6B, 0xD5)
FOLD_START = 0.5            # the fold line runs from (FOLD_START, 0) to (1, 1 - FOLD_START) of the frame
# Spec: ops/docs/macos-icon.md (what ships where)
ANDROID_VIEW = 72 / 108     # share of the adaptive canvas that a launcher shows
TILE_INSET = 16             # Windows / Linux tile margin at 1024px
TILE_RADIUS = 0.22          # of the tile side
MAC_BODY = (100, 824)       # Apple's macOS grid: offset and side of the squircle at 1024px
MAC_RADIUS = 185
SS = 4                      # supersampling for the drawn shapes


def rasterize(svg: Path, tmp: Path) -> Image.Image:
    out = tmp / "raster"
    subprocess.run(["npx", "tauri", "icon", str(svg), "--png", "2048", "-o", str(out)],
                   cwd=HERE, check=True, stdout=subprocess.DEVNULL)
    return Image.open(out / "2048x2048.png").convert("RGBA")


def fold_layer(frame: int, canvas: int = 1024) -> Image.Image:
    """The fold of a centered frame of side `frame`, carried out to the canvas edges.

    The frame offset cancels out of the line, so it is x - y = frame * FOLD_START in
    canvas pixels whatever the frame size.
    """
    c, k = canvas * SS, frame * FOLD_START * SS
    big = Image.new("RGBA", (c, c), (0, 0, 0, 0))
    ImageDraw.Draw(big).polygon([(k, 0), (c, 0), (c, c - k)], fill=FOLD + (255,))
    return big.resize((canvas, canvas), Image.LANCZOS)


def glyph_at(src: Image.Image, frame: int, canvas: int = 1024) -> Image.Image:
    g = src.resize((frame, frame), Image.LANCZOS)
    out = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
    o = (canvas - frame) // 2
    out.alpha_composite(g, (o, o))
    return out


def avatar(src: Image.Image, side: int = 1024) -> Image.Image:
    im = Image.new("RGBA", (side, side), BLUE + (255,))
    im.alpha_composite(fold_layer(side, side))
    im.alpha_composite(glyph_at(src, side, side))
    return im


def rounded_mask(box: tuple, radius: int, size: int = 1024) -> Image.Image:
    big = Image.new("L", (size * SS, size * SS), 0)
    ImageDraw.Draw(big).rounded_rectangle([v * SS for v in box], radius=radius * SS, fill=255)
    return big.resize((size, size), Image.LANCZOS)


def tile(src: Image.Image, box: tuple, radius: int) -> Image.Image:
    """The avatar fitted into `box` and rounded, on a transparent 1024 canvas."""
    out = Image.new("RGBA", (1024, 1024), (0, 0, 0, 0))
    out.alpha_composite(avatar(src, box[2] - box[0]), (box[0], box[1]))
    out.putalpha(rounded_mask(box, radius))
    return out


def main() -> None:
    if not GLYPH_SVG.exists():
        sys.exit(f"missing {GLYPH_SVG}")
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        src = rasterize(GLYPH_SVG, tmp)

        # iOS: light and dark are the same opaque avatar, so the dark style keeps the brand
        # blue instead of the system's black ground. Tinted stays transparent: the system
        # recolors every icon in that style.
        app = ICONS / "ios-appearances"
        avatar(src).convert("RGB").save(app / "AppIcon-light-1024.png")
        avatar(src).convert("RGB").save(app / "AppIcon-dark-1024.png")
        tinted = fold_layer(1024)
        tinted.alpha_composite(glyph_at(src, 1024))
        gray = tinted.convert("L").convert("RGBA")
        gray.putalpha(tinted.getchannel("A"))
        gray.save(app / "AppIcon-tinted-1024.png")

        # macOS 26: two Icon Composer layers; the document's fill is the blue.
        assets = ICONS / "AppIcon.icon" / "Assets"
        glyph_at(src, 1024).save(assets / "glyph.png")
        fold_layer(1024).save(assets / "fold.png")

        # macOS 11 to 15: the .icns shows as drawn, so the squircle and its shadow are baked in.
        o, s = MAC_BODY
        box = (o, o, o + s, o + s)
        shadow_a = rounded_mask(box, MAC_RADIUS).filter(ImageFilter.GaussianBlur(24))
        shadow_a = ImageChops.offset(shadow_a, 0, 10).point(lambda v: v * 30 // 100)
        mac = Image.new("RGBA", (1024, 1024), (0, 0, 0, 0))
        mac.putalpha(shadow_a)
        mac.alpha_composite(tile(src, box, MAC_RADIUS))
        mac.save(ICONS / "macos-master-1024.png")

        # Windows, Linux and the Android sets: the Tauri CLI sizes them from these inputs.
        side = 1024 - 2 * TILE_INSET
        tile(src, (TILE_INSET, TILE_INSET, 1024 - TILE_INSET, 1024 - TILE_INSET),
             round(side * TILE_RADIUS)).save(tmp / "tile.png")
        view = round(1024 * ANDROID_VIEW)
        bg = Image.new("RGBA", (1024, 1024), BLUE + (255,))
        bg.alpha_composite(fold_layer(view))
        bg.save(tmp / "android-bg.png")
        glyph_at(src, view).save(tmp / "android-fg.png")
        (tmp / "icon.json").write_text(json.dumps({
            "default": "tile.png",
            "bg_color": "#%02x%02x%02x" % BLUE,
            "android_bg": "android-bg.png",
            "android_fg": "android-fg.png",
            "android_fg_scale": 100,
        }))
        # Into a scratch folder: with gen/ present the CLI writes the mobile sets there
        # instead of into icons/, and its flat iOS set is replaced by the appearance set.
        out = tmp / "out"
        subprocess.run(["npx", "tauri", "icon", str(tmp / "icon.json"), "-o", str(out)],
                       cwd=HERE, check=True, stdout=subprocess.DEVNULL)
        for f in out.iterdir():
            if f.is_file():
                shutil.copy2(f, ICONS / f.name)
        shutil.copytree(out / "android", ICONS / "android", dirs_exist_ok=True)

        # The legacy launcher icons (Android 7, below the adaptive format): the CLI lays the
        # foreground over the background at full size, which blows the glyph up past the edge.
        for d in (ICONS / "android").glob("mipmap-*dpi"):
            n = Image.open(d / "ic_launcher.png").size[0]
            inset = round(1024 / 24)
            tile(src, (inset, inset, 1024 - inset, 1024 - inset), 120) \
                .resize((n, n), Image.LANCZOS).save(d / "ic_launcher.png")
            circle = Image.new("L", (1024 * SS, 1024 * SS), 0)
            ImageDraw.Draw(circle).ellipse((0, 0, 1024 * SS - 1, 1024 * SS - 1), fill=255)
            rnd = avatar(src)
            rnd.putalpha(circle.resize((1024, 1024), Image.LANCZOS))
            rnd.resize((n, n), Image.LANCZOS).save(d / "ic_launcher_round.png")
    print("App icons rebuilt from", GLYPH_SVG.name)


if __name__ == "__main__":
    main()

"""Draws the Linkerino icon: a folder with a shortcut badge on a blue rounded square."""

import os
from PIL import Image, ImageDraw

SIZE = 1024
TOP = (86, 148, 246)
BOTTOM = (23, 74, 214)
WHITE = (255, 255, 255, 255)
PAPER = (240, 246, 255, 255)
PAPER_EDGE = (214, 228, 250, 255)
ACCENT = (27, 79, 216, 255)


def vertical_gradient(size, top, bottom):
    image = Image.new("RGBA", (1, size))
    for y in range(size):
        ratio = y / max(size - 1, 1)
        image.putpixel((0, y), (
            round(top[0] + (bottom[0] - top[0]) * ratio),
            round(top[1] + (bottom[1] - top[1]) * ratio),
            round(top[2] + (bottom[2] - top[2]) * ratio),
            255,
        ))
    return image.resize((size, size), Image.BILINEAR)


def rounded_mask(size, radius):
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=255)
    return mask


def main():
    canvas = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    background = vertical_gradient(SIZE, TOP, BOTTOM)
    canvas.paste(background, (0, 0), rounded_mask(SIZE, 208))

    draw = ImageDraw.Draw(canvas)

    # Folder: back panel with a tab, then the front panel on top.
    draw.rounded_rectangle([132, 250, 700, 706], radius=54, fill=PAPER)
    draw.rounded_rectangle([132, 196, 470, 300], radius=44, fill=PAPER)
    draw.rounded_rectangle([104, 320, 744, 736], radius=64, fill=PAPER_EDGE)
    draw.rounded_rectangle([120, 306, 728, 720], radius=60, fill=WHITE)

    # Shortcut badge: white rounded square with a blue arrow, classic "link" hint.
    draw.rounded_rectangle([576, 566, 948, 938], radius=104, fill=WHITE)
    draw.rounded_rectangle([596, 586, 928, 918], radius=86, fill=ACCENT)
    draw.polygon([(640, 722), (800, 722), (800, 676), (904, 752), (800, 828), (800, 782), (640, 782)],
                 fill=WHITE)

    canvas.save(os.path.join("rust", "assets", "linkerino-1024.png"))

    sizes = [256, 128, 64, 48, 40, 32, 24, 20, 16]
    frames = []
    for size in sizes:
        frames.append(canvas.resize((size, size), Image.LANCZOS).convert("RGBA"))
    ico_path = os.path.join("rust", "assets", "linkerino.ico")
    frames[0].save(ico_path, format="ICO", sizes=[(s, s) for s in sizes], append_images=frames[1:])
    frames[0].save(os.path.join("rust", "assets", "linkerino-256.png"))
    frames[0].save(os.path.join("docs", "images", "linkerino-icon.png"))

    print("ico bytes:", os.path.getsize(ico_path))
    print("sizes:", sizes)


if __name__ == "__main__":
    main()

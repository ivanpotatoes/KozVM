"""Build the classic Win32 KozVM icon from a shared pixel/vector definition."""
from pathlib import Path
from PIL import Image, ImageDraw

root = Path(__file__).resolve().parents[1] / 'assets'
rects = [
    (0, 1, 16, 14, '#000000'), (0, 1, 15, 13, '#c0c0c0'),
    (0, 1, 15, 1, '#ffffff'), (0, 1, 1, 13, '#ffffff'),
    (14, 2, 1, 12, '#808080'), (1, 13, 13, 1, '#808080'),
    (2, 3, 11, 2, '#000080'), (2, 6, 11, 6, '#ffffff'),
    (3, 7, 2, 2, '#008000'), (3, 10, 2, 1, '#808080'),
]
# V: five-pixel monogram, legible at the native 16px menu size.
for x, y in [(7, 7), (11, 7), (7, 8), (11, 8),
             (8, 9), (10, 9), (8, 10), (10, 10), (9, 11)]:
    rects.append((x, y, 1, 1, '#000080'))
icon = Image.new('RGBA', (16, 16))
draw = ImageDraw.Draw(icon)
for x, y, w, h, color in rects:
    draw.rectangle((x, y, x+w-1, y+h-1), fill=color)
icon.save(root / 'kozvm-menu.png')
sizes = [16, 20, 24, 32, 48, 64, 128, 256]
frames = [icon.resize((s, s), Image.Resampling.NEAREST) for s in sizes]
frames[-1].save(root / 'kozvm.ico', sizes=[(s, s) for s in sizes], append_images=frames[:-1])
frames[-1].save(root / 'kozvm.png')
svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" shape-rendering="crispEdges">'
svg += ''.join(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="{c}"/>' for x,y,w,h,c in rects)
(root / 'kozvm.svg').write_text(svg + '</svg>\n')

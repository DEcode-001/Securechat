# Render plain-text logs to PNG images for report screenshots
from PIL import Image, ImageDraw, ImageFont
from pathlib import Path
import textwrap

font = ImageFont.load_default()

art = Path('artifacts')
(art / 'logs').mkdir(parents=True, exist_ok=True)

for name in ['server.log', 'client1.log', 'client2.log']:
    p = art / 'logs' / name
    if not p.exists():
        (art / f'ss_{name}.png').write_bytes(b'')
        continue
    text = p.read_text(encoding='utf-8', errors='ignore')
    lines = text.splitlines()
    wrapped = []
    for ln in lines:
        wrapped.extend(textwrap.wrap(ln, width=80) or [''])
    width = 1000
    line_h = 16
    height = max(200, 20 + line_h * (len(wrapped)+2))
    img = Image.new('RGB', (width, height), color=(20,20,20))
    d = ImageDraw.Draw(img)
    y = 10
    d.text((10,y), f"{name}", fill=(0,200,0), font=font)
    y += 24
    for ln in wrapped:
        d.text((10,y), ln, fill=(230,230,230), font=font)
        y += line_h
    img.save(art / f'ss_{name}.png')

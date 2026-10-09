from cyclothone.lens.photo import phash
from PIL import Image
import io

def _png(v=120):
    image=Image.new("L",(64,64),0)
    # Compare structure rather than uniform brightness, which pHash ignores.
    from PIL import ImageDraw
    draw=ImageDraw.Draw(image)
    extent = 16 if v < 180 else 40
    draw.rectangle((8, 8, extent, extent), fill=255)
    out=io.BytesIO(); image.save(out,format="PNG"); return out.getvalue()

def test_phash_is_stable():
    assert phash(_png()) == phash(_png())

def test_phash_changes_for_different_image():
    assert phash(_png(120)) != phash(_png(240))

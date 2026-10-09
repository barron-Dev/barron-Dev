from cyclothone.lens.photo import phash
from PIL import Image, ImageDraw
import io

def _png(v=120):
    image=Image.new("L",(64,64),v); out=io.BytesIO(); image.save(out,format="PNG"); return out.getvalue()

def test_phash_is_stable():
    assert phash(_png()) == phash(_png())

def _pattern_png():
    image = Image.new("L", (64, 64), 120)
    draw = ImageDraw.Draw(image)
    draw.rectangle((32, 0, 63, 63), fill=240)
    out = io.BytesIO()
    image.save(out, format="PNG")
    return out.getvalue()


def test_phash_changes_for_different_image():
    # Perceptual hashes intentionally ignore uniform brightness changes.
    # Use a structural difference rather than two solid shades.
    assert phash(_png(120)) != phash(_pattern_png())

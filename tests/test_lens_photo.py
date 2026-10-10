from cyclothone.lens.photo import phash
from PIL import Image
import io

def _png(v=120):
    image=Image.new("L",(64,64),v); out=io.BytesIO(); image.save(out,format="PNG"); return out.getvalue()

def test_phash_is_stable():
    assert phash(_png()) == phash(_png())

def test_phash_changes_for_different_image_structure():
    image = Image.new("L", (64, 64), 0)
    for x in range(64):
        for y in range(64):
            image.putpixel((x, y), 255 if (x // 8 + y // 8) % 2 else 0)
    out = io.BytesIO()
    image.save(out, format="PNG")
    # Perceptual hashing intentionally ignores a uniform brightness change;
    # a structural pattern is the meaningful difference for this assertion.
    assert phash(_png(120)) != phash(out.getvalue())

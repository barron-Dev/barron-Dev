from cyclothone.lens.photo import phash
from PIL import Image
import io

def _png(v=120):
    image=Image.new("L",(64,64),v); out=io.BytesIO(); image.save(out,format="PNG"); return out.getvalue()

def test_phash_is_stable():
    assert phash(_png()) == phash(_png())

def test_phash_changes_for_different_image():
    assert phash(_png(120)) != phash(_png(240))

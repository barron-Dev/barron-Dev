from io import BytesIO

from PIL import Image, ImageDraw

from cyclothone.brand.logo import LogoMatcher


def image_bytes(variant: int = 0) -> bytes:
    image = Image.new("RGB", (96, 96), "white")
    draw = ImageDraw.Draw(image)
    draw.rectangle((12, 12, 84, 84), outline="black", width=5)
    draw.line((12, 12, 84, 84), fill="black", width=4)
    if variant:
        draw.ellipse((28, 28, 68, 68), outline="black", width=3)
    stream = BytesIO()
    image.save(stream, format="PNG")
    return stream.getvalue()


def test_phash_is_stable_and_64_bits():
    matcher = LogoMatcher()
    left = matcher.phash(image_bytes())
    right = matcher.phash(image_bytes())
    assert len(left) == 16
    assert left == right
    assert matcher.phash_distance(left, right) == 0


def test_phash_is_a_distance_signal_not_a_boolean_verdict():
    matcher = LogoMatcher()
    left = matcher.phash(image_bytes())
    right = matcher.phash(image_bytes(1))
    assert 0 <= matcher.phash_distance(left, right) <= 64
    assert matcher.similarity(left, right) == 1 - matcher.phash_distance(left, right) / 64

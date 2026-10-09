from __future__ import annotations
import io
from hashlib import sha256

from PIL import Image, ImageOps

class PhotoFingerprintError(ValueError): pass

def phash(data: bytes) -> str:
    if not data or len(data) > 5 * 1024 * 1024:
        raise PhotoFingerprintError("image must be between 1 byte and 5 MiB")
    try:
        with Image.open(io.BytesIO(data)) as image:
            image.verify()
        with Image.open(io.BytesIO(data)) as image:
            image = ImageOps.exif_transpose(image).convert("L").resize((32,32), Image.Resampling.LANCZOS)
            pixels = list(image.getdata())
    except Exception as exc:
        raise PhotoFingerprintError("invalid or unsupported image") from exc
    # 32x32 low-frequency DCT, 8x8 coefficients, excluding DC.
    import math
    coeffs=[]
    for u in range(8):
        for v in range(8):
            s=0.0
            for x in range(32):
                for y in range(32):
                    s += pixels[x*32+y] * math.cos(math.pi*(2*x+1)*u/64) * math.cos(math.pi*(2*y+1)*v/64)
            au=1/math.sqrt(32) if u==0 else math.sqrt(2/32)
            av=1/math.sqrt(32) if v==0 else math.sqrt(2/32)
            coeffs.append(au*av*s)
    ac=coeffs[1:]
    med=sorted(ac)[len(ac)//2]
    bits=sum(1<<i for i,c in enumerate(ac) if c>med)
    return f"{bits:016x}"

def content_digest(data: bytes) -> str:
    return sha256(data).hexdigest()

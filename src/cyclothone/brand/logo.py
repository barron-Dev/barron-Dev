from __future__ import annotations

import io
import math
from statistics import median


class LogoMatcher:
    """Deterministic image fingerprints; similarity is a signal, not identity proof."""

    def _pixels(self, image_bytes: bytes, size: int, *, width: int | None = None) -> list[int]:
        try:
            from PIL import Image

            image = Image.open(io.BytesIO(image_bytes)).convert("L")
            image = image.resize((width or size, size))
            return list(image.getdata())
        except Exception:
            return []

    def _hash(self, image_bytes: bytes, size: int = 16, diff: bool = False) -> str:
        px = self._pixels(image_bytes, size, width=(size + 1 if diff else size))
        if not px:
            return ""
        if diff:
            bits = "".join(
                "1" if px[row * (size + 1) + col] > px[row * (size + 1) + col + 1] else "0"
                for row in range(size) for col in range(size)
            )
        else:
            average = sum(px) / len(px)
            bits = "".join("1" if value > average else "0" for value in px)
        return f"{int(bits, 2):0{size * size // 4}x}"

    def ahash(self, image_bytes: bytes, size: int = 16) -> str:
        return self._hash(image_bytes, size)

    def dhash(self, image_bytes: bytes, size: int = 16) -> str:
        return self._hash(image_bytes, size, True)

    def phash(self, image_bytes: bytes, hash_size: int = 8, highfreq_factor: int = 4) -> str:
        """Compute a classic low-frequency DCT perceptual hash (64 bits by default)."""
        size = hash_size * highfreq_factor
        pixels = self._pixels(image_bytes, size)
        if not pixels:
            return ""
        matrix = [
            [float(pixels[row * size + col]) for col in range(size)]
            for row in range(size)
        ]
        cos_x = [
            [math.cos((2 * x + 1) * u * math.pi / (2 * size)) for x in range(size)]
            for u in range(hash_size)
        ]
        dct = []
        for v in range(hash_size):
            row = []
            for u in range(hash_size):
                total = 0.0
                for y in range(size):
                    for x in range(size):
                        total += matrix[y][x] * cos_x[u][x] * cos_x[v][y]
                cu = math.sqrt(1 / size) if u == 0 else math.sqrt(2 / size)
                cv = math.sqrt(1 / size) if v == 0 else math.sqrt(2 / size)
                row.append(cu * cv * total)
            dct.append(row)
        values = [dct[y][x] for y in range(hash_size) for x in range(hash_size)]
        threshold = median(values[1:])
        bits = "".join("1" if value > threshold else "0" for value in values)
        return f"{int(bits, 2):0{hash_size * hash_size // 4}x}"

    def hamming(self, left: str, right: str) -> int:
        if not left or not right or len(left) != len(right):
            return 999
        try:
            return (int(left, 16) ^ int(right, 16)).bit_count()
        except ValueError:
            return 999

    def phash_distance(self, left: str, right: str) -> int:
        return self.hamming(left, right)

    def similarity(self, left: str, right: str) -> float:
        distance = self.hamming(left, right)
        return 0.0 if distance >= 999 else max(0.0, 1 - distance / (len(left) * 4))

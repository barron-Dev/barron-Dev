from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass


_COUNTRY_CODES = {
    "229": "BJ", "1": "US", "44": "GB", "33": "FR", "49": "DE",
    "39": "IT", "34": "ES", "971": "AE", "91": "IN", "86": "CN",
    "81": "JP", "27": "ZA", "234": "NG", "233": "GH", "254": "KE",
    "255": "TZ", "256": "UG", "212": "MA", "213": "DZ", "216": "TN",
}


@dataclass(frozen=True, slots=True)
class NormalizedNumber:
    e164: str
    e164_hash: str
    country: str
    country_code: str
    national: str
    line_type: str
    carrier: str | None
    carrier_mcc_mnc: str | None


class NumberNormalizer:
    @staticmethod
    def hash_value(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def redact(e164: str) -> str:
        return e164[:4] + "*" * max(0, len(e164) - 7) + e164[-3:]

    @classmethod
    def normalize(cls, raw: str) -> NormalizedNumber:
        if not isinstance(raw, str):
            raise ValueError("number must be text")
        value = raw.strip()
        if not value:
            raise ValueError("number is empty")
        digits = re.sub(r"[^0-9+]", "", value)
        if digits.startswith("00"):
            digits = "+" + digits[2:]
        if not digits.startswith("+") or not digits[1:].isdigit():
            raise ValueError("number must use international +E.164 form")
        e164 = digits
        if not 8 <= len(e164[1:]) <= 15:
            raise ValueError("invalid E.164 length")
        code = next((c for c in sorted(_COUNTRY_CODES, key=len, reverse=True) if e164[1:].startswith(c)), None)
        if code is None:
            country = "ZZ"
            country_code = e164[1:4]
        else:
            country = _COUNTRY_CODES[code]
            country_code = code
        national = e164[1 + len(country_code):]
        if not national:
            raise ValueError("missing national number")
        return NormalizedNumber(
            e164=e164,
            e164_hash=cls.hash_value(e164),
            country=country,
            country_code=country_code,
            national=national,
            line_type="unknown",
            carrier=None,
            carrier_mcc_mnc=None,
        )

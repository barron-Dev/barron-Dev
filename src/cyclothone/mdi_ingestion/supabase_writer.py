"""Server-side writer for existing MDI tables; never use in a browser."""
from __future__ import annotations
import os, math
from datetime import datetime
from typing import Any
from urllib.parse import urlparse
import httpx

class MDIWriteError(RuntimeError): pass

def _config() -> tuple[str, str]:
    url, key = os.environ.get("SUPABASE_URL", "").rstrip("/"), os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
    if urlparse(url).scheme != "https" or not urlparse(url).netloc or not key:
        raise MDIWriteError("Trusted worker requires HTTPS SUPABASE_URL and service-role key")
    if os.environ.get("CYCLOTHONE_MDI_INGESTION_ENABLED", "").lower() != "true":
        raise MDIWriteError("MDI ingestion is disabled")
    return url, key

def write_rf_observations(peaks: list[dict[str, Any]], *, observer_id: str | None = None,
                          latitude: float | None = None, longitude: float | None = None) -> int:
    url, key = _config()
    if (latitude is None) != (longitude is None): raise ValueError("coordinates must be supplied together")
    if latitude is not None and (not -90 <= latitude <= 90 or not -180 <= longitude <= 180):
        raise ValueError("invalid coordinates")
    rows = []
    for p in peaks:
        required = ("center_frequency_hz","peak_frequency_hz","relative_power_db","noise_floor_db",
                    "sample_rate_hz","sample_count","observed_at","rf_hash")
        if any(k not in p for k in required): raise ValueError("peak missing provenance")
        datetime.fromisoformat(str(p["observed_at"]).replace("Z","+00:00"))
        power = float(p["relative_power_db"])
        if not math.isfinite(power): raise ValueError("non-finite power")
        raw = {"source":"local_sdr_passive_spectrum","algorithm":p.get("method","welch_median_energy_v1"),
               "rf_hash":str(p["rf_hash"]),"center_frequency_hz":int(p["center_frequency_hz"]),
               "peak_frequency_hz":int(p["peak_frequency_hz"]),"sample_rate_hz":int(p["sample_rate_hz"]),
               "sample_count":int(p["sample_count"]),"relative_power_db":power,
               "measurement_unit":p.get("measurement_unit","dBFS/Hz"),"noise_floor_db":float(p["noise_floor_db"]),
               "coverage_note":"passive spectrum energy only; no protocol or identity decoded"}
        row = {"radio":"sdr_spectrum","observed_at":str(p["observed_at"]),"raw":raw}
        if observer_id: row["observer_id"] = observer_id
        if latitude is not None: row.update({"lat":latitude,"lon":longitude})
        rows.append(row)
    if not rows: return 0
    with httpx.Client(timeout=httpx.Timeout(10,connect=3),follow_redirects=False) as client:
        r = client.post(f"{url}/rest/v1/mdi_rf_observations",
          headers={"apikey":key,"Authorization":f"Bearer {key}","Content-Type":"application/json","Prefer":"return=minimal"},json=rows)
    if r.status_code not in (200,201,204): raise MDIWriteError(f"RF insert failed ({r.status_code}); response omitted")
    return len(rows)

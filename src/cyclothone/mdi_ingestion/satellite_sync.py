"""Public CelesTrak OMM -> Skyfield/SGP4 positions; no target tasking or comms inference."""
from __future__ import annotations
import hashlib, json, os
from datetime import datetime, timezone
from typing import Any
import httpx

CELESTRAK_WEATHER_OMM = "https://celestrak.org/NORAD/elements/gp.php?GROUP=weather&FORMAT=json"
class SatelliteSyncError(RuntimeError): pass

def fetch_public_orbital_positions(*, latitude: float, longitude: float,
        observed_at: datetime | None = None, source_url: str = CELESTRAK_WEATHER_OMM) -> tuple[list[dict[str, Any]],dict[str,Any]]:
    if not -90 <= latitude <= 90 or not -180 <= longitude <= 180: raise ValueError("invalid coordinates")
    if source_url != CELESTRAK_WEATHER_OMM: raise ValueError("source is not on the approved public catalog allowlist")
    try:
        from skyfield.api import EarthSatellite, load, wgs84
    except ImportError as exc: raise SatelliteSyncError("Install requirements-mdi-ingestion.txt") from exc
    with httpx.Client(timeout=httpx.Timeout(15,connect=4),follow_redirects=False,
                       headers={"User-Agent":"Cyclothone-MDI-public-catalog/1.0"}) as client:
        response = client.get(source_url); response.raise_for_status()
        if len(response.content) > 8*1024*1024: raise SatelliteSyncError("catalog response exceeded 8 MiB")
        body = response.content
    try: items = json.loads(body)
    except (ValueError,UnicodeDecodeError) as exc: raise SatelliteSyncError("invalid catalog JSON") from exc
    if not isinstance(items,list) or not items: raise SatelliteSyncError("empty catalog; no observations written")
    if len(items)>5000: raise SatelliteSyncError("catalog exceeded bounded item count")
    stamp = (observed_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    ts = load.timescale(); t = ts.from_datetime(stamp); observer = wgs84.latlon(latitude,longitude)
    digest = hashlib.sha256(body).hexdigest(); rows = []
    for item in items:
        if not isinstance(item,dict) or not item.get("NORAD_CAT_ID"): continue
        try:
            sat = EarthSatellite.from_omm(ts,item); topocentric = (sat-observer).at(t)
            alt,az,distance = topocentric.altaz(); subpoint = sat.at(t).subpoint()
            norad = int(item["NORAD_CAT_ID"])
        except (ValueError,TypeError,KeyError): continue
        rows.append({"norad_id":norad,"observation_type":"public_orbital_position",
          "footprint_center_lat":float(subpoint.latitude.degrees),"footprint_center_lon":float(subpoint.longitude.degrees),
          "acquired_at":stamp.isoformat(),"asset_url":source_url,"asset_sha256":digest,
          "metadata":{"source":"CelesTrak public GP OMM weather catalog","catalog_name":str(item.get("OBJECT_NAME",""))[:120],
          "catalog_epoch":str(item.get("EPOCH","")),"observer_altitude_deg":round(float(alt.degrees),4),
          "observer_azimuth_deg":round(float(az.degrees),4),"slant_range_km":round(float(distance.km),3),
          "propagator":"Skyfield/SGP4","source_response_sha256":digest,
          "coverage_note":"public orbital elements; not evidence of communications or target observation"}})
    if not rows: raise SatelliteSyncError("no valid orbital elements; no observations written")
    return rows,{"source_url":source_url,"source_sha256":digest,"elements_received":len(items),
                 "positions_calculated":len(rows),"fetched_at":stamp.isoformat()}

def persist_public_orbital_positions(rows: list[dict[str,Any]]) -> int:
    url=os.environ.get("SUPABASE_URL","").rstrip("/"); key=os.environ.get("SUPABASE_SERVICE_ROLE_KEY","")
    if os.environ.get("CYCLOTHONE_MDI_INGESTION_ENABLED","").lower()!="true": raise SatelliteSyncError("MDI ingestion is disabled")
    if not url.startswith("https://") or not key: raise SatelliteSyncError("trusted worker configuration missing")
    if not rows: return 0
    with httpx.Client(timeout=httpx.Timeout(10,connect=3),follow_redirects=False) as client:
        r=client.post(f"{url}/rest/v1/mdi_satellite_observations",
          headers={"apikey":key,"Authorization":f"Bearer {key}","Content-Type":"application/json","Prefer":"return=minimal"},json=rows)
    if r.status_code not in (200,201,204): raise SatelliteSyncError(f"satellite insert failed ({r.status_code}); response omitted")
    return len(rows)

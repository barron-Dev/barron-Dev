"""One-shot trusted-worker entrypoint; invoke explicitly from an authorized edge/worker host."""
from __future__ import annotations
import argparse, os
from datetime import datetime, timezone
from .rf_spectrum import capture_once
from .satellite_sync import fetch_public_orbital_positions, persist_public_orbital_positions
from .supabase_writer import write_rf_observations

def main() -> int:
    parser=argparse.ArgumentParser(description="Run one real MDI source-ingestion pass")
    parser.add_argument("source", choices=("rf","satellite"))
    args=parser.parse_args()
    if os.environ.get("CYCLOTHONE_MDI_INGESTION_ENABLED","").lower()!="true":
        parser.error("MDI ingestion is disabled; set CYCLOTHONE_MDI_INGESTION_ENABLED=true after review")
    if args.source=="rf":
        center=int(os.environ["CYCLOTHONE_MDI_RF_CENTER_FREQUENCY_HZ"])
        rate=int(os.environ.get("CYCLOTHONE_MDI_RF_SAMPLE_RATE_HZ","2000000"))
        gain=float(os.environ.get("CYCLOTHONE_MDI_RF_GAIN_DB","20"))
        count=int(os.environ.get("CYCLOTHONE_MDI_RF_SAMPLE_COUNT","262144"))
        observer=os.environ.get("CYCLOTHONE_MDI_OBSERVER_ID")
        lat=os.environ.get("CYCLOTHONE_MDI_OBSERVER_LAT")
        lon=os.environ.get("CYCLOTHONE_MDI_OBSERVER_LON")
        peaks=capture_once(center_frequency_hz=center,sample_rate_hz=rate,gain_db=gain,sample_count=count)
        inserted=write_rf_observations(peaks,observer_id=observer,
            latitude=float(lat) if lat is not None else None,
            longitude=float(lon) if lon is not None else None)
        print(f"RF capture completed: peaks={len(peaks)} persisted={inserted}; passive energy only")
        return 0
    lat=float(os.environ["CYCLOTHONE_MDI_OBSERVER_LAT"])
    lon=float(os.environ["CYCLOTHONE_MDI_OBSERVER_LON"])
    rows,receipt=fetch_public_orbital_positions(latitude=lat,longitude=lon,observed_at=datetime.now(timezone.utc))
    inserted=persist_public_orbital_positions(rows)
    print(f"Satellite sync completed: catalog_items={receipt['elements_received']} positions={len(rows)} persisted={inserted} source_sha256={receipt['source_sha256']}")
    return 0

if __name__=="__main__":
    raise SystemExit(main())

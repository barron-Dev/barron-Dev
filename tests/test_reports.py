from datetime import datetime, timezone
import json

from sentinel.reports.csv_export import render_csv
from sentinel.reports.models import ReportIR
from sentinel.reports.pdf import render_pdf
from sentinel.reports.stix import render_stix21


def sample() -> ReportIR:
    return ReportIR(case_number="C-202609-00001", title="Ransomware case", category="ransomware", severity="critical", status="investigating", created_at=datetime.now(timezone.utc), tenant_name="Acme", agency="uaecert", summary="Detected malicious activity.", iocs=[{"ioc_type":"sha256","value":"a"*64,"severity":"high","confidence":0.95,"source":"internal"},{"ioc_type":"domain","value":"evil.example","severity":"high","confidence":0.9,"source":"internal"}], wallets=["bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"])


def test_csv_contains_case_and_ioc():
    out = render_csv(sample()).decode("utf-8-sig")
    assert "C-202609-00001" in out
    assert "evil.example" in out


def test_pdf_bytes():
    out = render_pdf(sample())
    assert out.startswith(b"%PDF-")
    assert len(out) > 1000


def test_stix21_bundle():
    bundle = json.loads(render_stix21(sample()))
    assert bundle["type"] == "bundle"
    assert {obj["type"] for obj in bundle["objects"]} >= {"identity", "indicator", "malware", "report"}
    assert all(obj.get("spec_version") == "2.1" for obj in bundle["objects"])

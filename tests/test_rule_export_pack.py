import zipfile
from datetime import datetime, timezone
from io import BytesIO
from types import SimpleNamespace

from services.rule_export_pack import build_rules_export_zip


def test_zip_manifest_and_rule_file():
    r = SimpleNamespace(
        id=7,
        rule_name="Test Rule",
        rule_text="title: t\n",
        rule_format="sigma",
        platform="Windows",
        mitre_technique_id="T1059",
        mitre_technique_ids=["T1059"],
        version=2,
        operational_status="production",
        use_case_id=1,
        updated_at=datetime.now(timezone.utc),
    )
    raw = build_rules_export_zip([r], {1: "UC1"})
    zf = zipfile.ZipFile(BytesIO(raw))
    names = zf.namelist()
    assert "manifest.yaml" in names
    assert any(n.startswith("sigma/") and n.endswith(".yml") for n in names)
    manifest = zf.read("manifest.yaml").decode("utf-8")
    assert "T1059" in manifest and "UC1" in manifest

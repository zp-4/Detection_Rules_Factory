from services.exec_report_pdf import build_executive_pdf


def test_pdf_builds():
    b = build_executive_pdf({"rule_count": 1, "platforms": {"Windows": 1}}, title="T")
    assert b.startswith(b"%PDF")

"""Governance: rule archival retention and executive PDF export."""
from datetime import datetime, timedelta, timezone

import pandas as pd
import streamlit as st
from sqlalchemy import and_

from db.models import RuleImplementation
from db.repo import RuleChangeLogRepository, RuleRepository
from db.session import SessionLocal
from services.auth import get_current_user, has_permission, require_sign_in
from services.exec_metrics import collect_executive_metrics
from services.exec_report_pdf import build_executive_pdf
from services.governance_config import load_governance_config, save_governance_config
from utils.session_persistence import restore_session_state

restore_session_state()

st.set_page_config(page_title="Governance", page_icon="📦", layout="wide")

require_sign_in("Governance")
username = get_current_user() or ""

if not has_permission("read"):
    st.error("Read permission required.")
    st.stop()

st.title("📦 Governance")
st.caption("Archive retired rules per retention policy and download executive PDF summaries.")

db = SessionLocal()
try:
    cfg = load_governance_config()
    tab_pdf, tab_arch, tab_set = st.tabs(
        ["Executive PDF", "Rule archival", "Retention settings"]
    )

    with tab_pdf:
        st.subheader("Executive summary (PDF)")
        m = collect_executive_metrics(db, include_archived=False)
        c1, c2, c3 = st.columns(3)
        c1.metric("Rules (active view)", m.get("rule_count", 0))
        c2.metric("Use cases", m.get("use_case_count", 0))
        c3.metric("Archived (total)", m.get("archived_total", 0))
        pdf_bytes = build_executive_pdf(m)
        st.download_button(
            label="Download executive_summary.pdf",
            data=pdf_bytes,
            file_name=f"executive_summary_{datetime.now(timezone.utc).strftime('%Y%m%d')}.pdf",
            mime="application/pdf",
        )

    with tab_arch:
        st.subheader("Archive / unarchive rules")
        if not has_permission("update"):
            st.warning("**update** permission required to change archival state.")
        days = int(cfg.get("retention_days_after_retired") or 90)
        cutoff = datetime.utcnow() - timedelta(days=days)
        retired_open = (
            db.query(RuleImplementation)
            .filter(
                and_(
                    RuleImplementation.operational_status == "retired",
                    RuleImplementation.archived_at.is_(None),
                )
            )
            .all()
        )
        eligible = [r for r in retired_open if r.updated_at and r.updated_at <= cutoff]
        st.caption(
            f"Retention window: **{days}** days after last update while status is **retired**. "
            f"Eligible for suggested archival now: **{len(eligible)}**."
        )
        if eligible and has_permission("update"):
            opts = {f"{r.id} — {r.rule_name} (updated {r.updated_at})": r.id for r in eligible}
            pick = st.multiselect("Suggest archive (retired + past retention)", options=list(opts.keys()))
            if st.button("Archive selected", type="primary"):
                for k in pick:
                    rid = opts[k]
                    rule = RuleRepository.get_by_id(db, rid)
                    if not rule:
                        continue
                    prev = RuleChangeLogRepository._rule_to_dict(rule)
                    RuleRepository.update(
                        db,
                        rid,
                        archived_at=datetime.utcnow(),
                        archived_by=username,
                    )
                    r2 = RuleRepository.get_by_id(db, rid)
                    if r2:
                        RuleChangeLogRepository.log_update(
                            db,
                            r2,
                            prev,
                            username,
                            reason="Archived (governance retention)",
                        )
                st.success("Archived.")
                st.rerun()

        archived_rows = (
            db.query(RuleImplementation)
            .filter(RuleImplementation.archived_at.isnot(None))
            .order_by(RuleImplementation.archived_at.desc())
            .limit(200)
            .all()
        )
        if archived_rows:
            st.markdown("**Archived rules**")
            df = pd.DataFrame(
                [
                    {
                        "id": r.id,
                        "name": r.rule_name,
                        "archived_at": r.archived_at,
                        "archived_by": r.archived_by,
                    }
                    for r in archived_rows
                ]
            )
            st.dataframe(df, width="stretch", hide_index=True)
            if has_permission("update"):
                uopts = {f"{r.id} — {r.rule_name}": r.id for r in archived_rows}
                up = st.multiselect("Unarchive", options=list(uopts.keys()))
                if st.button("Unarchive selected"):
                    for k in up:
                        rid = uopts[k]
                        prev = RuleChangeLogRepository._rule_to_dict(
                            RuleRepository.get_by_id(db, rid)
                        )
                        RuleRepository.update(db, rid, archived_at=None, archived_by=None)
                        r2 = RuleRepository.get_by_id(db, rid)
                        if r2:
                            RuleChangeLogRepository.log_update(
                                db,
                                r2,
                                prev,
                                username,
                                reason="Unarchived from Governance",
                            )
                    st.success("Done.")
                    st.rerun()
        else:
            st.info("No archived rules.")

    with tab_set:
        st.subheader("Retention threshold")
        if not has_permission("admin"):
            st.warning("**admin** permission required to edit retention settings.")
        else:
            with st.form("gov_cfg"):
                ret = st.number_input(
                    "Days after last update (retired rules) before suggested archive",
                    min_value=1,
                    max_value=3650,
                    value=int(cfg.get("retention_days_after_retired") or 90),
                )
                if st.form_submit_button("Save"):
                    save_governance_config({"retention_days_after_retired": int(ret)})
                    st.success("Saved to `config/governance.yaml`.")
                    st.rerun()

finally:
    db.close()

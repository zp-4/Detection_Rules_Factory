"""Guided onboarding checklist."""

from __future__ import annotations

import streamlit as st

from db.models import AiAuditResult, OfflineAuditResult, RuleImplementation
from db.session import SessionLocal
from services.auth import get_current_user, require_sign_in
from services.onboarding import compute_progress, mark_step
from utils.app_navigation import render_app_sidebar
from utils.session_persistence import restore_session_state

restore_session_state()

st.set_page_config(page_title="Onboarding", page_icon="🧩", layout="wide")

require_sign_in("Onboarding")
username = get_current_user()
render_app_sidebar(username)

st.title("🧩 Guided onboarding")
st.caption("Get started with first import, first audit, and dashboard readiness.")

db = SessionLocal()
try:
    has_import = db.query(RuleImplementation).count() > 0
    has_audit = (
        db.query(OfflineAuditResult).count() > 0
        or db.query(AiAuditResult).count() > 0
    )
finally:
    db.close()

progress = compute_progress(username=username, has_import=has_import, has_audit=has_audit)

st.progress(progress.completed / progress.total)
st.caption(f"{progress.completed}/{progress.total} steps completed")

with st.container(border=True):
    st.markdown("### 1) First import")
    if progress.first_import:
        st.success("Completed")
    else:
        st.info("Import your first rules set (e.g. Git Sigma import).")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("Open Git Sigma import", use_container_width=True):
            st.switch_page("pages/18_Git_Sigma_Import.py")
    with c2:
        if st.button("Mark done", key="ob_mark_import", use_container_width=True):
            mark_step(username, "first_import", True)
            st.rerun()

with st.container(border=True):
    st.markdown("### 2) First audit")
    if progress.first_audit:
        st.success("Completed")
    else:
        st.info("Run one audit to validate MITRE mapping and quality.")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("Open MITRE audit", use_container_width=True):
            st.switch_page("pages/2_Audit.py")
    with c2:
        if st.button("Mark done", key="ob_mark_audit", use_container_width=True):
            mark_step(username, "first_audit", True)
            st.rerun()

with st.container(border=True):
    st.markdown("### 3) Dashboard ready")
    if progress.dashboard_seen:
        st.success("Completed")
    else:
        st.info("Review your dashboard indicators and priorities.")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("Open dashboard", use_container_width=True):
            st.switch_page("app.py")
    with c2:
        if st.button("Mark done", key="ob_mark_dashboard", use_container_width=True):
            mark_step(username, "dashboard_seen", True)
            st.rerun()

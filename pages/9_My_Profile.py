"""User profile — identity, role, and lightweight session preferences."""
import streamlit as st
from db.session import SessionLocal
from utils.session_persistence import restore_session_state
from services.auth import (
    get_current_user,
    get_user_role,
    get_user_team,
    load_rbac_config,
    require_sign_in,
    user_has_password,
)
from services.user_workspace import workspace_summary

restore_session_state()

st.set_page_config(
    page_title="My profile",
    page_icon="👤",
    layout="wide",
)

require_sign_in("your profile")
username = get_current_user()

st.title("👤 My profile")
st.caption("Overview of your account in this workspace (demo RBAC).")

col1, col2 = st.columns(2)
with col1:
    st.subheader("Identity")
    st.markdown(f"- **Username:** `{username}`")
    st.markdown(f"- **Role:** `{get_user_role() or 'N/A'}`")
    st.markdown(f"- **Team:** `{get_user_team() or 'N/A'}`")
    st.markdown(
        "- **Password:** "
        + ("`required` (RBAC hash)" if user_has_password(username) else "`optional` (username-only)")
    )

with col2:
    st.subheader("Workspace")
    cfg = load_rbac_config()
    total_users = len(cfg.get("users", {}))
    st.metric("Configured accounts", total_users)
    st.caption("Users are defined in `config/rbac.yaml` or Streamlit secrets.")

db = SessionLocal()
try:
    wo, wr, wrules, watt = workspace_summary(db, username)
finally:
    db.close()

st.divider()
st.subheader("Your scope (from use case owners / reviewers)")
c1, c2, c3, c4 = st.columns(4)
c1.metric("Owned use cases", wo)
c2.metric("Reviewer use cases", wr)
c3.metric("Rules in scope", wrules)
c4.metric("Attention (tags)", watt)

st.divider()
st.subheader("Shortcuts")
s1, s2, s3 = st.columns(3)
with s1:
    if st.button("My workspace", width="stretch", type="primary"):
        st.switch_page("pages/10_My_Workspace.py")
with s2:
    if st.button("Rules catalogue", width="stretch"):
        st.switch_page("pages/1_Use_Cases.py")
with s3:
    if st.button("MITRE audit", width="stretch"):
        st.switch_page("pages/2_Audit.py")

st.divider()
st.subheader("Session preferences")
st.caption("Stored in this browser session only (not synced to the server).")

if "profile_compact_tables" not in st.session_state:
    st.session_state["profile_compact_tables"] = False

st.session_state["profile_compact_tables"] = st.checkbox(
    "Prefer compact tables where supported",
    value=st.session_state["profile_compact_tables"],
    help="Other pages can read this flag later to tune layout density.",
)

if st.button("Go to home", type="primary"):
    st.switch_page("app.py")

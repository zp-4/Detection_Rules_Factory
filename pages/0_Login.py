"""Dedicated sign-in portal (wide layout + compact padding)."""
import sys
import os

if sys.platform == "win32":
    os.environ["PYTHONIOENCODING"] = "utf-8"
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

import streamlit as st
from utils.session_persistence import restore_session_state
from utils.streamlit_ui import apply_global_styles, apply_login_page_styles
from services.auth import (
    get_current_user,
    login,
    logout,
    load_rbac_config,
    user_has_password,
)

restore_session_state()

st.set_page_config(
    page_title="Sign in — Detection Rules Factory",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed",
)

apply_global_styles()
apply_login_page_styles()

username = get_current_user()

if username:
    _, mid_signed, _ = st.columns([0.12, 1, 0.12])
    with mid_signed:
        st.success(f"Signed in as **{username}**")
        st.caption(
            f"Role: **{st.session_state.get('user_role', 'N/A')}** · "
            f"Team: **{st.session_state.get('user_team', 'N/A')}**"
        )
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Go to home", type="primary", use_container_width=True):
                st.switch_page("app.py")
        with c2:
            if st.button("Sign out", use_container_width=True):
                logout()
                st.rerun()
    st.stop()

_, mid, _ = st.columns([0.12, 1, 0.12])
with mid:
    with st.container(border=True):
        st.markdown("## Detection Rules Factory")
        st.caption("Sign in to manage detection rules and MITRE ATT&CK coverage.")

        with st.form("sign_in_portal"):
            login_username = st.text_input("Username", placeholder="e.g. admin")
            login_password = st.text_input(
                "Password",
                type="password",
                placeholder="If required for your account",
            )
            submitted = st.form_submit_button("Sign in", type="primary", use_container_width=True)
            if submitted:
                u = login_username.strip() if login_username else ""
                if not u:
                    st.error("Please enter a username.")
                elif user_has_password(u) and not (login_password and login_password.strip()):
                    st.error("Password required for this account.")
                elif login(u, login_password or ""):
                    st.switch_page("app.py")
                else:
                    st.error("Invalid username or password.")

    cfg = load_rbac_config()
    known = sorted(cfg.get("users", {}).keys())
    if known:
        with st.expander("Demo accounts"):
            st.markdown("You can sign in as: " + ", ".join(f"`{u}`" for u in known))

    st.caption(
        "Accounts without `password_hash` in RBAC: username only. "
        "Use `python scripts/hash_password.py` to set passwords. "
        "Prefer SSO for production."
    )

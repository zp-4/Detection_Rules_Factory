"""Main landing page / router for Detection Rules Factory."""
# -*- coding: utf-8 -*-
import sys
import os
# Set UTF-8 encoding for Windows compatibility
if sys.platform == 'win32':
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    # Ensure UTF-8 encoding is used
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    if hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8')

import streamlit as st
from services.auth import get_current_user
from services.feature_flags import maintenance_message
from utils.session_persistence import restore_session_state
from utils.app_navigation import (
    count_unread_notifications,
    render_app_sidebar,
    render_home_quick_links,
)

# Restore session state on page load
restore_session_state()

st.set_page_config(
    page_title="Detection Rules Factory",
    page_icon="🏭",
    layout="wide",
    initial_sidebar_state="expanded"
)

username = get_current_user()
if not username:
    st.switch_page("pages/0_Login.py")

_n_unread = count_unread_notifications(username)
render_app_sidebar(username, _n_unread)

# Main content
_banner = maintenance_message()
if _banner:
    st.warning(_banner)

st.markdown(
    """
<div class="drf-hero">
  <p class="drf-hero-kicker">SOC detection platform</p>
  <h1 class="drf-hero-title">Detection Rules Factory</h1>
  <p class="drf-hero-lead">
    Unified rule catalogue, MITRE ATT&amp;CK coverage, CTI workflows, and governance —
    use the sidebar or the shortcuts below.
  </p>
</div>
    """,
    unsafe_allow_html=True,
)

render_home_quick_links(_n_unread)

st.divider()
st.markdown("### System status")

col1, col2, col3 = st.columns(3)

with col1:
    with st.container(border=True):
        st.caption("DATABASE")
        try:
            from db.session import engine
            from sqlalchemy import inspect
            inspector = inspect(engine)
            tables = inspector.get_table_names()
            st.success(f"{len(tables)} tables")
        except Exception:
            st.error("Not initialized")

with col2:
    with st.container(border=True):
        st.caption("MITRE ENGINE")
        try:
            from services.mitre_coverage import get_mitre_engine
            get_mitre_engine()
            st.success("Ready")
        except Exception:
            st.warning("Not loaded")

with col3:
    with st.container(border=True):
        st.caption("SESSION")
        if username:
            st.success(username)
        else:
            st.info("Not signed in")

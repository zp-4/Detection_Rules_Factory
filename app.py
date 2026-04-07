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
from services.auth import get_current_user, login, logout
from utils.session_persistence import restore_session_state, persist_session_state

# Restore session state on page load
restore_session_state()

st.set_page_config(
    page_title="Detection Rules Factory",
    page_icon="🏭",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Sidebar login
st.sidebar.title("🏭 Detection Rules Factory")

username = get_current_user()

if not username:
    st.sidebar.subheader("Login")
    login_username = st.sidebar.text_input("Username")
    if st.sidebar.button("Login"):
        if login(login_username):
            st.sidebar.success(f"Logged in as {login_username}")
            st.rerun()
        else:
            st.sidebar.error("Invalid username")
else:
    st.sidebar.success(f"Logged in as: **{username}**")
    st.sidebar.caption(f"Role: {st.session_state.get('user_role', 'N/A')}")
    st.sidebar.caption(f"Team: {st.session_state.get('user_team', 'N/A')}")
    
    if st.sidebar.button("Logout"):
        logout()
        st.rerun()

# Main content
st.title("🏭 Detection Rules Factory")
st.markdown("""
**A comprehensive platform for managing SOC detection rules and MITRE ATT&CK coverage analysis.**

### Features:
- 📋 **Rules Catalogue**: Manage and filter detection rules with tags
- 🛡️ **MITRE Audit**: Gap analysis against MITRE ATT&CK framework
- 🎯 **MITRE Mapping Analysis**: AI-powered mapping verification and improvement
- 📊 **Coverage Dashboard**: Visualize MITRE coverage across your detection rules
- 🎯 **Group Coverage**: Analyze coverage of APT groups' techniques
- 🔍 **CTI Detection Opportunity**: Extract detection rules from threat intelligence
- ⚙️ **Administration**: Manage quotas and access control

### Navigation:
Use the sidebar to navigate between pages, or select from the pages below.
""")

# Quick links
col1, col2, col3, col4, col5, col6, col7 = st.columns(7)

with col1:
    if st.button("📋 Rules", width='stretch'):
        st.switch_page("pages/1_Use_Cases.py")

with col2:
    if st.button("🛡️ Audit", width='stretch'):
        st.switch_page("pages/2_Audit.py")

with col3:
    if st.button("🎯 Mapping", width='stretch'):
        st.switch_page("pages/3_Mapping.py")

with col4:
    if st.button("📊 Dashboard", width='stretch'):
        st.switch_page("pages/4_Dashboard_MITRE.py")

with col5:
    if st.button("🎯 Groups", width='stretch'):
        st.switch_page("pages/5_Group_Coverage.py")

with col6:
    if st.button("🔍 CTI", width='stretch'):
        st.switch_page("pages/6_CTI_Detection.py")

with col7:
    if st.button("⚙️ Admin", width='stretch'):
        st.switch_page("pages/8_Admin.py")

st.divider()

# Status
st.subheader("System Status")
col1, col2, col3 = st.columns(3)

with col1:
    try:
        from db.session import engine
        from sqlalchemy import inspect
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        st.success(f"✅ Database: {len(tables)} tables")
    except:
        st.error("❌ Database: Not initialized")

with col2:
    try:
        from services.mitre_coverage import get_mitre_engine
        get_mitre_engine()
        st.success("✅ MITRE Engine: Ready")
    except:
        st.warning("⚠️ MITRE Engine: Not loaded")

with col3:
    if username:
        st.success(f"✅ User: {username}")
    else:
        st.info("ℹ️ User: Not logged in")

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
from services.auth import get_current_user, logout
from services.feature_flags import maintenance_message
from utils.session_persistence import restore_session_state, persist_session_state

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

# Sidebar (authenticated)
st.sidebar.title("🏭 Detection Rules Factory")
_msg = maintenance_message()
if _msg:
    st.sidebar.warning(_msg)
st.sidebar.success(f"Logged in as: **{username}**")
st.sidebar.caption(f"Role: {st.session_state.get('user_role', 'N/A')}")
st.sidebar.caption(f"Team: {st.session_state.get('user_team', 'N/A')}")
if st.sidebar.button("Sign out"):
    logout()
    st.rerun()
if st.sidebar.button("My workspace"):
    st.switch_page("pages/10_My_Workspace.py")
if st.sidebar.button("My profile"):
    st.switch_page("pages/9_My_Profile.py")

# Main content
_banner = maintenance_message()
if _banner:
    st.warning(_banner)
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
col1, col2, col3, col4, col5, col6, col7, col8 = st.columns(8)

with col1:
    if st.button("📌 Workspace", width='stretch'):
        st.switch_page("pages/10_My_Workspace.py")

with col2:
    if st.button("📋 Rules", width='stretch'):
        st.switch_page("pages/1_Use_Cases.py")

with col3:
    if st.button("🛡️ Audit", width='stretch'):
        st.switch_page("pages/2_Audit.py")

with col4:
    if st.button("🎯 Mapping", width='stretch'):
        st.switch_page("pages/3_Mapping.py")

with col5:
    if st.button("📊 Dashboard", width='stretch'):
        st.switch_page("pages/4_Dashboard_MITRE.py")

with col6:
    if st.button("🎯 Groups", width='stretch'):
        st.switch_page("pages/5_Group_Coverage.py")

with col7:
    if st.button("🔍 CTI", width='stretch'):
        st.switch_page("pages/6_CTI_Detection.py")

with col8:
    if st.button("⚙️ Admin", width='stretch'):
        st.switch_page("pages/8_Admin.py")

r1, r2, r3, r4 = st.columns([1, 1, 1, 3])
with r1:
    if st.button("🔄 Use case workflow", width="stretch"):
        st.switch_page("pages/11_Use_Case_Workflow.py")
with r2:
    if st.button("📑 Rule version diff", width="stretch"):
        st.switch_page("pages/12_Rule_Version_Diff.py")
with r3:
    if st.button("🎯 MITRE coverage hub", width="stretch"):
        st.switch_page("pages/13_MITRE_Coverage_Hub.py")

r5a, r5b, r5c, r5d = st.columns(4)
with r5a:
    if st.button("🧪 Detection engineering", width="stretch"):
        st.switch_page("pages/14_Detection_Engineering.py")

r6a, r6b = st.columns(2)
with r6a:
    if st.button("📚 CTI library", width="stretch"):
        st.switch_page("pages/15_CTI_Library.py")

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

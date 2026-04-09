"""Main landing page — tableau de bord utilisateur (la navigation reste dans la sidebar)."""
# -*- coding: utf-8 -*-
import sys
import os
if sys.platform == 'win32':
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    if hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8')

import html

import pandas as pd
import streamlit as st

from services.auth import ROLES, get_current_user, has_permission
from services.feature_flags import maintenance_message
from services.onboarding import compute_progress, mark_step
from utils.mitre_links import technique_links_markdown
from utils.session_persistence import restore_session_state
from utils.dashboard_home import load_home_dashboard_stats
from utils.app_navigation import (
    count_unread_notifications,
    render_app_sidebar,
)

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

_banner = maintenance_message()
if _banner:
    st.warning(_banner)

_has_import = stats.n_rules > 0
_has_audit = stats.n_audits_total > 0
_onb = compute_progress(username=username, has_import=_has_import, has_audit=_has_audit)
if _onb.completed < _onb.total:
    st.info(
        f"Onboarding in progress: {_onb.completed}/{_onb.total}. "
        "Complete steps in usr > Onboarding."
    )
elif "onboarding_banner_dismissed" not in st.session_state:
    st.success("Onboarding complete. Your workspace is ready.")
    if st.button("Hide this message", key="hide_onboarding_done"):
        st.session_state["onboarding_banner_dismissed"] = True
        mark_step(username, "dashboard_seen", True)
        st.rerun()

role = st.session_state.get("user_role", "—")
team = st.session_state.get("user_team", "—")
_safe = html.escape
_u, _r, _t = _safe(str(username)), _safe(str(role)), _safe(str(team))

st.markdown(
    f"""
<div class="drf-topbar">
  <div class="drf-topbar-left">
    <span class="drf-topbar-kicker">User dashboard</span>
    <h1 class="drf-topbar-title">Detection Rules Factory</h1>
  </div>
  <p class="drf-topbar-right">
    {_u} · {_r} · {_t}
  </p>
</div>
    """,
    unsafe_allow_html=True,
)

stats = load_home_dashboard_stats(username)
role_permissions = [str(p) for p in ROLES.get(str(role), [])]
safe_badges = "".join(
    f'<span class="drf-badge">{html.escape(p)}</span>' for p in role_permissions
) or '<span class="drf-badge">read</span>'
st.markdown(
    f'<div class="drf-badge-row"><span class="drf-badge-title">Permissions:</span>{safe_badges}</div>',
    unsafe_allow_html=True,
)

if stats.error and not stats.db_ok:
    st.error(f"Base de données indisponible : {stats.error}")

st.markdown("### Snapshot")
st.markdown(
    f"""
<div class="drf-kpi-grid">
  <div class="drf-kpi-card"><span>Cas d’usage</span><strong>{stats.n_use_cases}</strong></div>
  <div class="drf-kpi-card"><span>Règles</span><strong>{stats.n_rules}</strong></div>
  <div class="drf-kpi-card"><span>En revue</span><strong>{stats.n_use_cases_in_review}</strong></div>
  <div class="drf-kpi-card"><span>Entrées CTI</span><strong>{stats.n_cti_entries}</strong></div>
  <div class="drf-kpi-card"><span>Notifications</span><strong>{stats.n_unread_notifications}</strong></div>
  <div class="drf-kpi-card"><span>Reevaluation {stats.quarterly_label}</span><strong>{stats.n_quarterly_reeval_queue}</strong></div>
</div>
    """,
    unsafe_allow_html=True,
)

col_left, col_right = st.columns([1.45, 1], gap="large")

with col_left:
    st.markdown("### Activity")
    with st.container(border=True):
        st.markdown('<div class="drf-priority-list">', unsafe_allow_html=True)
        if stats.n_my_reviews > 5 and has_permission("update"):
            st.markdown(
                f'<div class="drf-priority-item drf-priority-crit">Review queue: <strong>{stats.n_my_reviews}</strong> assigned</div>',
                unsafe_allow_html=True,
            )
        elif stats.n_my_reviews > 0 and has_permission("update"):
            st.markdown(
                f'<div class="drf-priority-item drf-priority-warn">Review queue: <strong>{stats.n_my_reviews}</strong> assigned</div>',
                unsafe_allow_html=True,
            )
        elif has_permission("update"):
            st.markdown(
                '<div class="drf-priority-item drf-priority-ok">Review queue: clear</div>',
                unsafe_allow_html=True,
            )

        if stats.n_unread_notifications > 10:
            st.markdown(
                f'<div class="drf-priority-item drf-priority-crit">Unread notifications: <strong>{stats.n_unread_notifications}</strong></div>',
                unsafe_allow_html=True,
            )
        elif stats.n_unread_notifications > 0:
            st.markdown(
                f'<div class="drf-priority-item drf-priority-info">Unread notifications: <strong>{stats.n_unread_notifications}</strong></div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<div class="drf-priority-item drf-priority-ok">Unread notifications: 0</div>',
                unsafe_allow_html=True,
            )

        if has_permission("trigger_ai"):
            st.markdown(
                '<div class="drf-priority-item drf-priority-info">AI drafting enabled</div>',
                unsafe_allow_html=True,
            )
        if stats.n_quarterly_reeval_queue > 25:
            st.markdown(
                f'<div class="drf-priority-item drf-priority-crit">Quarterly reevaluation queue: <strong>{stats.n_quarterly_reeval_queue}</strong></div>',
                unsafe_allow_html=True,
            )
        elif stats.n_quarterly_reeval_queue > 0:
            st.markdown(
                f'<div class="drf-priority-item drf-priority-warn">Quarterly reevaluation queue: <strong>{stats.n_quarterly_reeval_queue}</strong></div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<div class="drf-priority-item drf-priority-ok">Quarterly reevaluation queue: 0</div>',
                unsafe_allow_html=True,
            )
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("### Use case distribution")
    if stats.use_cases_by_status:
        df = pd.DataFrame(
            [
                {"Statut": k, "Nombre": v}
                for k, v in sorted(stats.use_cases_by_status.items())
            ]
        )
        st.bar_chart(df.set_index("Statut"), height=280)
    else:
        st.info("No use-case data.")

with col_right:
    st.markdown("### Platform")
    with st.container(border=True):
        st.caption("DATABASE")
        if stats.db_ok:
            st.success("Connected")
        else:
            st.error("Unavailable")
    with st.container(border=True):
        st.caption("MITRE ENGINE")
        if stats.mitre_engine_ok:
            st.success("Loaded")
        else:
            st.warning("Not loaded")
    st.markdown("### Explainability")
    with st.container(border=True):
        if stats.explainability_items:
            for it in stats.explainability_items:
                rule_name = html.escape(str(it.get("rule_name", "Rule")))
                sentence = html.escape(str(it.get("summary_sentence", "")))
                tids = it.get("technique_ids", [])
                st.markdown(
                    f"**{rule_name}** (`#{int(it.get('rule_id', 0))}`)  \n{sentence}"
                )
                st.caption(f"MITRE: {technique_links_markdown(tids)}")
        else:
            st.caption("No explainability snippets available yet.")

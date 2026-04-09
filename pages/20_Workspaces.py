"""Workspace reporting by team (BU/region abstraction)."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from db.models import RuleImplementation, UseCase
from db.session import SessionLocal
from services.auth import get_current_user, get_user_team, load_rbac_config, require_sign_in
from services.workspaces import build_workspace_rows
from utils.app_navigation import render_app_sidebar
from utils.session_persistence import restore_session_state

restore_session_state()

st.set_page_config(page_title="Workspaces", page_icon="🧭", layout="wide")

require_sign_in("Workspaces")
username = get_current_user()
render_app_sidebar(username)

st.title("🧭 Workspaces")
st.caption("Team-based view (BU/region) with consolidated reporting.")

db = SessionLocal()
try:
    users = load_rbac_config().get("users", {})
    use_cases = db.query(UseCase).all()
    rules = db.query(RuleImplementation).all()
    rows = build_workspace_rows(users, use_cases, rules)

    if not rows:
        st.info("No workspace data available.")
        st.stop()

    my_team = str(get_user_team(username) or "").strip()
    show_only_my_team = st.toggle(
        "Show only my workspace",
        value=bool(my_team),
        help="Filter to your team workspace only.",
    )

    filtered = rows
    if show_only_my_team and my_team:
        filtered = [r for r in rows if r.workspace == my_team]

    if not filtered:
        st.warning("No rows match the current filter.")
        st.stop()

    total_ws = len(filtered)
    total_users = sum(r.users for r in filtered)
    total_rules = sum(r.rules_in_scope for r in filtered)
    total_to_improve = sum(r.rules_to_improve for r in filtered)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Workspaces", total_ws)
    c2.metric("Users", total_users)
    c3.metric("Rules in scope", total_rules)
    c4.metric("Rules to improve", total_to_improve)

    df = pd.DataFrame(
        [
            {
                "Workspace": r.workspace,
                "Users": r.users,
                "Use cases (owned)": r.use_cases_owned,
                "Use cases (reviewed)": r.use_cases_reviewed,
                "Rules in scope": r.rules_in_scope,
                "Rules to improve": r.rules_to_improve,
            }
            for r in filtered
        ]
    )
    st.dataframe(df, hide_index=True, width="stretch")

    chart_df = df.set_index("Workspace")[["Rules in scope", "Rules to improve"]]
    st.bar_chart(chart_df, height=280)
finally:
    db.close()

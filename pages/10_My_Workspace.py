"""Personal workspace — use cases, scoped rules, and attention items."""
import streamlit as st
import pandas as pd
from db.session import SessionLocal
from db.models import RuleChangeLog
from services.auth import get_current_user, require_sign_in, has_permission
from services.user_workspace import (
    use_cases_owned_by,
    use_cases_where_reviewer,
    review_queue_rows_for_reviewer,
    rule_ids_under_use_cases,
    rules_needing_attention,
    workspace_summary,
)
from utils.session_persistence import restore_session_state

restore_session_state()

st.set_page_config(
    page_title="My workspace",
    page_icon="📌",
    layout="wide",
)

require_sign_in("My workspace")
username = get_current_user()

st.title("📌 My workspace")
st.caption("Use cases where you are owner or reviewer, and rules that may need your attention.")

db = SessionLocal()
try:
    owned = use_cases_owned_by(db, username)
    reviewer = use_cases_where_reviewer(db, username)
    n_own, n_rev, n_rules, n_att = workspace_summary(db, username)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Use cases (owner)", n_own)
    c2.metric("Use cases (reviewer)", n_rev)
    c3.metric("Rules in scope", n_rules)
    c4.metric("Needs attention (tags)", n_att)

    st.divider()

    col_a, col_b = st.columns(2)
    with col_a:
        st.subheader("Owned use cases")
        if owned:
            st.dataframe(
                pd.DataFrame([{"id": uc.id, "name": uc.name, "status": uc.status} for uc in owned]),
                width="stretch",
                hide_index=True,
            )
        else:
            st.info("You are not listed as owner on any use case yet.")

    with col_b:
        st.subheader("Reviewer on")
        if reviewer:
            st.dataframe(
                pd.DataFrame([{"id": uc.id, "name": uc.name, "status": uc.status} for uc in reviewer]),
                width="stretch",
                hide_index=True,
            )
        else:
            st.info("You are not listed as reviewer on any use case.")

    queue_rows = review_queue_rows_for_reviewer(db, username)
    if queue_rows:
        st.subheader("Review queue (priority / SLA)")
        st.caption(
            "Use cases in **review** where you are a reviewer. "
            "Sorted by overdue, then priority (1 = highest), then due date."
        )
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "id": r["use_case"].id,
                        "name": r["use_case"].name,
                        "priority": r["priority"],
                        "due_at": r["due_at"],
                        "overdue": r["overdue"],
                        "assignee": r["assignee"] or "—",
                    }
                    for r in queue_rows
                ]
            ),
            width="stretch",
            hide_index=True,
        )
        if st.button("Open use case workflow"):
            st.switch_page("pages/11_Use_Case_Workflow.py")

    uc_ids = list({uc.id for uc in owned} | {uc.id for uc in reviewer})
    scoped_rules = rule_ids_under_use_cases(db, uc_ids)
    attention = rules_needing_attention(scoped_rules)

    st.subheader("Rules in your scope needing attention")
    if attention:
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "id": r.id,
                        "rule_name": r.rule_name,
                        "platform": r.platform,
                        "tags": ", ".join(r.tags) if isinstance(r.tags, list) else r.tags,
                    }
                    for r in attention[:50]
                ]
            ),
            width="stretch",
            hide_index=True,
        )
        if len(attention) > 50:
            st.caption(f"Showing 50 of {len(attention)} rules.")
    else:
        st.success("No tagged attention items in your scoped rules.")

    st.divider()
    st.subheader("Your recent rule changes")
    recent = (
        db.query(RuleChangeLog)
        .filter(RuleChangeLog.changed_by == username)
        .order_by(RuleChangeLog.changed_at.desc())
        .limit(15)
        .all()
    )
    if recent:
        rows = []
        for ch in recent:
            name = "—"
            if ch.new_state and isinstance(ch.new_state, dict):
                name = ch.new_state.get("rule_name", name)
            elif ch.previous_state and isinstance(ch.previous_state, dict):
                name = ch.previous_state.get("rule_name", name)
            rows.append(
                {
                    "when": ch.changed_at,
                    "action": ch.action,
                    "rule": name,
                }
            )
        st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
    else:
        st.info("No changelog entries for your user yet.")

    st.divider()
    cgo1, cgo2, cgo3 = st.columns(3)
    with cgo1:
        if st.button("Open rules catalogue", width="stretch"):
            st.switch_page("pages/1_Use_Cases.py")
    with cgo2:
        if st.button("Open MITRE mapping", width="stretch"):
            st.switch_page("pages/3_Mapping.py")
    with cgo3:
        if has_permission("admin"):
            if st.button("Admin platform", width="stretch"):
                st.switch_page("pages/8_Admin.py")

finally:
    db.close()

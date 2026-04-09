"""Global search hub (rules, use cases, techniques, comments)."""

from __future__ import annotations

import streamlit as st

from db.session import SessionLocal
from services.auth import get_current_user, require_sign_in
from services.global_search import search_global
from services.saved_views import delete_saved_view, list_saved_views, upsert_saved_view
from utils.app_navigation import render_app_sidebar
from utils.mitre_links import technique_links_markdown
from utils.session_persistence import restore_session_state

restore_session_state()

st.set_page_config(page_title="Global Search", page_icon="🔎", layout="wide")

require_sign_in("Global Search")
username = get_current_user()
render_app_sidebar(username)

st.title("🔎 Global Search")
st.caption("Search across rules, MITRE technique IDs, use cases and comments.")
st.caption("Tip: use Cmd+K / Ctrl+K habit to open this page quickly from sidebar.")

if "global_search_query" not in st.session_state:
    st.session_state["global_search_query"] = ""
if "global_search_limit" not in st.session_state:
    st.session_state["global_search_limit"] = 20

q = st.text_input(
    "Search query",
    key="global_search_query",
    placeholder="e.g. T1059, powershell, suspicious child process, review note...",
)
_default_limit = int(st.session_state.get("global_search_limit", 20))
if _default_limit < 5 or _default_limit > 50:
    _default_limit = 20
limit = st.slider(
    "Max results per section",
    min_value=5,
    max_value=50,
    value=_default_limit,
    step=5,
    key="global_search_limit",
)

st.markdown("### Saved views")
saved = list_saved_views(username)
left, mid, right = st.columns([1.2, 1.2, 1.6])
with left:
    selected_name = st.selectbox(
        "Load saved view",
        options=["(none)"] + [v.name for v in saved],
        index=0,
    )
with mid:
    save_name = st.text_input("Save as", placeholder="e.g. T1059 review backlog")
with right:
    c_save, c_delete = st.columns(2)
    with c_save:
        if st.button("Save / Update", use_container_width=True):
            if upsert_saved_view(username, name=save_name, query=q, limit_per_type=limit):
                st.success("Saved view updated.")
                st.rerun()
            else:
                st.warning("Provide a name and at least 2 chars query.")
    with c_delete:
        if st.button("Delete selected", use_container_width=True):
            if selected_name != "(none)" and delete_saved_view(username, selected_name):
                st.success("Saved view deleted.")
                st.rerun()
            else:
                st.warning("Select an existing saved view.")

if selected_name != "(none)":
    chosen = next((v for v in saved if v.name == selected_name), None)
    if chosen and (q != chosen.query or int(limit) != int(chosen.limit_per_type)):
        st.session_state["global_search_query"] = chosen.query
        st.session_state["global_search_limit"] = int(chosen.limit_per_type)
        st.rerun()

if len((q or "").strip()) < 2:
    st.info("Type at least 2 characters.")
    st.stop()

db = SessionLocal()
try:
    results = search_global(db, q, limit_per_type=limit)
finally:
    db.close()

c1, c2, c3, c4 = st.columns(4)
c1.metric("Rules", len(results.rules))
c2.metric("Use cases", len(results.use_cases))
c3.metric("Techniques", len(results.techniques))
c4.metric("Comments", len(results.comments))

col_l, col_r = st.columns(2, gap="large")

with col_l:
    st.subheader("Rules")
    if results.rules:
        for r in results.rules:
            st.markdown(
                f"**{r['rule_name']}** (`#{r['id']}`) · {r['platform']}  \n"
                f"MITRE: {technique_links_markdown(r.get('techniques') or [])}"
            )
    else:
        st.caption("No rule matches.")

    st.subheader("Use cases")
    if results.use_cases:
        for uc in results.use_cases:
            st.markdown(
                f"**{uc['name']}** (`#{uc['id']}`) · status `{uc['status']}`  \n"
                f"MITRE claimed: {technique_links_markdown(uc.get('mitre_claimed') or [])}"
            )
    else:
        st.caption("No use-case matches.")

with col_r:
    st.subheader("Technique hits")
    if results.techniques:
        for t in results.techniques:
            st.markdown(
                f"`{t['technique_id']}` in **{t['rule_name']}** (`#{t['rule_id']}`)"
            )
    else:
        st.caption("No MITRE technique matches.")

    st.subheader("Comments")
    if results.comments:
        for c in results.comments:
            st.markdown(
                f"**{c['author']}** on `{c['entity_type']}#{c['entity_id']}`: {c['preview']}"
            )
    else:
        st.caption("No comment matches.")

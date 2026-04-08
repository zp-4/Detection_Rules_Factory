"""Compare saved rule snapshots (changelog) — rule text and MITRE mapping."""
import streamlit as st
from db.session import SessionLocal
from db.models import RuleImplementation
from db.repo import RuleChangeLogRepository, RuleRepository
from services.auth import has_permission, require_sign_in
from services.rule_snapshot import mitre_snapshot_text
from utils.diff_html import generate_colored_diff, generate_side_by_side_diff
from utils.session_persistence import restore_session_state

restore_session_state()

st.set_page_config(
    page_title="Rule version diff",
    page_icon="📑",
    layout="wide",
)

require_sign_in("Rule version diff")

if not has_permission("read"):
    st.error("Read permission required.")
    st.stop()

st.title("📑 Rule version diff")
st.caption(
    "Pick a rule, then compare two snapshots from the audit log (`new_state` after each change). "
    "Business `version` increments on meaningful updates (see `RuleChangeLogRepository.log_update`)."
)

db = SessionLocal()
try:
    rules = db.query(RuleImplementation).order_by(RuleImplementation.rule_name).all()
    if not rules:
        st.info("No rules in the database.")
        st.stop()

    labels = {f"{r.id} — {r.rule_name} (v{r.version or 1})": r.id for r in rules}
    choice = st.selectbox("Rule", options=list(labels.keys()))
    rule_id = labels[choice]
    rule = RuleRepository.get_by_id(db, rule_id)
    if not rule:
        st.error("Rule not found.")
        st.stop()

    c1, c2, c3 = st.columns(3)
    c1.metric("Current version", rule.version or 1)
    c2.metric("Platform", rule.platform)
    c3.metric("Format", rule.rule_format or "—")

    history = RuleChangeLogRepository.get_rule_history(db, rule_id, limit=100)
    snapshots = [h for h in history if h.new_state and isinstance(h.new_state, dict)]
    snapshots_asc = sorted(snapshots, key=lambda h: h.changed_at)

    if len(snapshots_asc) < 2:
        st.warning("Need at least two changelog entries with stored state to compare.")
        st.stop()

    def opt_label(h):
        v = h.new_state.get("version", "?")
        return f"#{h.id} v{v} @ {h.changed_at} ({h.action})"

    opts = {opt_label(h): h.id for h in snapshots_asc}

    col_a, col_b = st.columns(2)
    with col_a:
        earlier_key = st.selectbox(
            "Earlier snapshot",
            options=list(opts.keys()),
            index=max(0, len(opts) - 2),
        )
    with col_b:
        later_key = st.selectbox(
            "Later snapshot",
            options=list(opts.keys()),
            index=max(0, len(opts) - 1),
        )

    id_a = opts[earlier_key]
    id_b = opts[later_key]
    entry_a = RuleChangeLogRepository.get_change_by_id(db, id_a)
    entry_b = RuleChangeLogRepository.get_change_by_id(db, id_b)
    if not entry_a or not entry_b:
        st.error("Could not load selected log rows.")
        st.stop()

    if entry_a.changed_at > entry_b.changed_at:
        entry_a, entry_b = entry_b, entry_a

    old_state = entry_a.new_state
    new_state = entry_b.new_state

    st.subheader("Rule query / logic (`rule_text`)")
    mode = st.radio(
        "View mode",
        ["Colored diff", "Side by side", "Raw"],
        horizontal=True,
    )
    old_text = (old_state.get("rule_text") or "") if isinstance(old_state, dict) else ""
    new_text = (new_state.get("rule_text") or "") if isinstance(new_state, dict) else ""

    if mode == "Colored diff":
        html = generate_colored_diff(old_text, new_text)
        if html:
            st.markdown(html, unsafe_allow_html=True)
        else:
            st.info("No differences in rule text.")
    elif mode == "Side by side":
        st.markdown(generate_side_by_side_diff(old_text, new_text), unsafe_allow_html=True)
    else:
        x1, x2 = st.columns(2)
        with x1:
            st.code(old_text or "—", language="yaml")
        with x2:
            st.code(new_text or "—", language="yaml")

    st.subheader("MITRE mapping")
    m_old = mitre_snapshot_text(old_state if isinstance(old_state, dict) else None)
    m_new = mitre_snapshot_text(new_state if isinstance(new_state, dict) else None)
    mh = generate_colored_diff(m_old, m_new)
    if mh:
        st.markdown(mh, unsafe_allow_html=True)
    else:
        st.success("MITRE mapping fields are identical between snapshots.")

    with st.expander("Full JSON snapshots"):
        j1, j2 = st.columns(2)
        with j1:
            st.json(old_state)
        with j2:
            st.json(new_state)

    if st.button("Open audit trail"):
        st.switch_page("pages/7_Audit_Trail.py")

finally:
    db.close()

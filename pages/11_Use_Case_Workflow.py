"""Use case lifecycle — transition draft → review → approved → deprecated."""
import streamlit as st
from datetime import datetime

from db.session import SessionLocal
from db.models import DecisionLog
from db.repo import UseCaseRepository, CommentRepository
from services.comment_notifications import add_comment_with_notifications
from services.auth import get_current_user, has_permission, require_sign_in
from services.review_schedule import review_due_at_from_start
from utils.session_persistence import restore_session_state

restore_session_state()

st.set_page_config(
    page_title="Use case workflow",
    page_icon="🔄",
    layout="wide",
)

require_sign_in("Use case workflow")

if not has_permission("update"):
    st.error("You need **update** permission to change use case status.")
    st.stop()

STATUSES = ["draft", "review", "approved", "deprecated"]

st.title("🔄 Use case workflow")
st.caption(
    "Change use case status and record a decision in `decision_logs`. "
    "Entering **review** sets `review_started_at` and optional SLA due date."
)

db = SessionLocal()
try:
    use_cases = UseCaseRepository.list_all(db, limit=500)
    if not use_cases:
        st.info("No use cases in the database.")
        st.stop()

    labels = [f"{uc.id} — {uc.name} ({uc.status or '?'})" for uc in use_cases]
    choice = st.selectbox("Select use case", options=labels, index=0)
    idx = labels.index(choice)
    uc = use_cases[idx]

    st.markdown(f"**Current status:** `{uc.status}`")
    st.markdown(f"**Description:** {uc.description or '—'}")

    rp = getattr(uc, "review_priority", None) or 3
    sla = getattr(uc, "review_sla_days", None)
    assignee = getattr(uc, "review_assignee", None) or ""
    started = getattr(uc, "review_started_at", None)
    due = getattr(uc, "review_due_at", None)
    st.caption(
        f"Review queue: priority **{rp}**, SLA days **{sla or '—'}**, "
        f"assignee **{assignee or '—'}**, started **{started or '—'}**, due **{due or '—'}**"
    )

    with st.form("review_meta"):
        st.subheader("Review queue settings")
        n_pri = st.number_input("Priority (1 = highest)", min_value=1, max_value=5, value=int(rp))
        n_sla = st.number_input(
            "SLA days (applied when status becomes review)",
            min_value=0,
            max_value=365,
            value=int(sla) if sla is not None else 0,
        )
        n_assignee = st.text_input("Review assignee (username)", value=assignee)
        if st.form_submit_button("Save review settings"):
            UseCaseRepository.update(
                db,
                uc.id,
                review_priority=int(n_pri),
                review_sla_days=int(n_sla) if n_sla else None,
                review_assignee=n_assignee.strip() or None,
            )
            st.success("Review settings saved.")
            st.rerun()

    if (uc.status or "") == "review" and started and sla:
        if st.button("Recalculate review due date from start + SLA"):
            new_due = review_due_at_from_start(started, sla)
            UseCaseRepository.update(db, uc.id, review_due_at=new_due)
            st.success("Due date updated.")
            st.rerun()

    with st.form("transition_form"):
        new_status = st.selectbox(
            "New status",
            STATUSES,
            index=STATUSES.index(uc.status) if uc.status in STATUSES else 0,
        )
        reason = st.text_area("Reason / notes", placeholder="Why this transition?", height=100)
        submitted = st.form_submit_button("Apply transition", type="primary")

        if submitted:
            if new_status == uc.status:
                st.warning("Status unchanged.")
            else:
                old = uc.status
                log = DecisionLog(
                    entity_type="use_case",
                    entity_id=uc.id,
                    from_status=old,
                    to_status=new_status,
                    decided_by=get_current_user() or "unknown",
                    reason=reason.strip() or None,
                )
                db.add(log)

                extra = {}
                if new_status == "review" and old != "review":
                    now = datetime.utcnow()
                    extra["review_started_at"] = now
                    extra["review_due_at"] = review_due_at_from_start(
                        now, getattr(uc, "review_sla_days", None)
                    )
                elif old == "review" and new_status != "review":
                    extra["review_started_at"] = None
                    extra["review_due_at"] = None

                UseCaseRepository.update(db, uc.id, status=new_status, **extra)
                st.success(f"Updated **{uc.name}** from `{old}` → `{new_status}`.")
                st.rerun()

    st.divider()
    st.subheader("Discussion")
    for cm in CommentRepository.get_for_entity(db, "use_case", uc.id):
        st.markdown(f"**{cm.author}** — {cm.created_at}:  \n{cm.body}")
    if has_permission("update"):
        with st.form("uc_comment_form"):
            uc_body = st.text_area("Comment (@username to notify)", height=100, key="uc_comment_body")
            if st.form_submit_button("Post comment"):
                if uc_body.strip():
                    add_comment_with_notifications(
                        db,
                        entity_type="use_case",
                        entity_id=uc.id,
                        use_case_id=uc.id,
                        author=get_current_user() or "unknown",
                        body=uc_body,
                    )
                    st.success("Posted.")
                    st.rerun()

    st.divider()
    st.subheader("Recent decisions (all use cases)")
    recent = (
        db.query(DecisionLog)
        .filter(DecisionLog.entity_type == "use_case")
        .order_by(DecisionLog.decided_at.desc())
        .limit(20)
        .all()
    )
    if recent:
        for row in recent:
            st.write(
                f"- **{row.decided_at}** — use case `{row.entity_id}` "
                f"`{row.from_status}` → `{row.to_status}` by **{row.decided_by}**"
                + (f" — _{row.reason}_" if row.reason else "")
            )
    else:
        st.caption("No decision log entries yet.")

finally:
    db.close()

"""Collaboration: notification inbox and quick comment composer."""
import streamlit as st

from db.repo import NotificationRepository
from db.session import SessionLocal
from services.auth import get_current_user, has_permission, require_sign_in
from services.comment_notifications import add_comment_with_notifications
from utils.session_persistence import restore_session_state

restore_session_state()

st.set_page_config(page_title="Collaboration", page_icon="💬", layout="wide")

require_sign_in("Collaboration")
username = get_current_user() or ""

if not has_permission("read"):
    st.error("Read permission required.")
    st.stop()

st.title("💬 Collaboration")
st.caption("In-app notifications (@mentions) and optional comment composer.")

db = SessionLocal()
try:
    tab_inbox, tab_compose = st.tabs(["Inbox", "Compose comment"])

    with tab_inbox:
        unread = NotificationRepository.count_unread(db, username)
        st.metric("Unread", unread)
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Mark all read", type="secondary") and unread:
                n = NotificationRepository.mark_all_read(db, username)
                st.success(f"Marked {n} notification(s) as read.")
                st.rerun()
        rows = NotificationRepository.list_for_user(db, username, limit=80)
        if not rows:
            st.info("No notifications yet. Use **@username** in a comment to notify someone.")
        else:
            for n in rows:
                badge = "🔴" if n.read_at is None else "✅"
                with st.expander(f"{badge} #{n.id} — {n.created_at}"):
                    st.markdown(n.message)
                    if n.read_at is None and st.button("Mark read", key=f"mr_{n.id}"):
                        NotificationRepository.mark_read(db, n.id, username)
                        st.rerun()

    with tab_compose:
        st.caption("Comments also appear on the **Rules catalogue** and **Use case workflow** pages.")
        if not has_permission("update"):
            st.warning("**update** permission required to post comments.")
        else:
            et = st.selectbox("Entity type", ["rule", "use_case"], key="co_et")
            eid = st.number_input("Entity ID", min_value=1, value=1, step=1, key="co_eid")
            uc = st.number_input("Use case ID (optional, for linking)", min_value=0, value=0, key="co_uc")
            body = st.text_area(
                "Comment (use @username for mentions)",
                height=160,
                key="co_body",
                placeholder="@reviewer1 please check this mapping",
            )
            if st.button("Post comment", type="primary", key="co_post"):
                if not body.strip():
                    st.error("Body is required.")
                else:
                    add_comment_with_notifications(
                        db,
                        entity_type=et,
                        entity_id=int(eid),
                        use_case_id=int(uc) if uc else None,
                        author=username,
                        body=body,
                    )
                    st.success("Comment posted; mentioned users were notified.")
                    st.rerun()

finally:
    db.close()

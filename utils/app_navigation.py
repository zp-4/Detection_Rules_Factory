"""Grouped navigation for the Streamlit app (sidebar + home quick links)."""

from __future__ import annotations

import streamlit as st

from utils.streamlit_ui import apply_global_styles

# (label, page path, stable key suffix for st.button)
_NAV_GROUPS: list[tuple[str, list[tuple[str, str, str]]]] = [
    (
        "Daily work",
        [
            ("My workspace", "pages/10_My_Workspace.py", "ws"),
            ("Rules catalogue", "pages/1_Use_Cases.py", "rules"),
            ("Collaboration", "pages/16_Collaboration.py", "collab"),
        ],
    ),
    (
        "MITRE & coverage",
        [
            ("MITRE audit", "pages/2_Audit.py", "audit"),
            ("Mapping analysis", "pages/3_Mapping.py", "mapping"),
            ("Coverage dashboard", "pages/4_Dashboard_MITRE.py", "dash"),
            ("Group coverage", "pages/5_Group_Coverage.py", "group"),
            ("MITRE coverage hub", "pages/13_MITRE_Coverage_Hub.py", "hub"),
        ],
    ),
    (
        "CTI",
        [
            ("CTI detection", "pages/6_CTI_Detection.py", "cti_det"),
            ("CTI library", "pages/15_CTI_Library.py", "cti_lib"),
        ],
    ),
    (
        "Lifecycle & quality",
        [
            ("Use case workflow", "pages/11_Use_Case_Workflow.py", "workflow"),
            ("Rule version diff", "pages/12_Rule_Version_Diff.py", "diff"),
            ("Audit trail", "pages/7_Audit_Trail.py", "trail"),
            ("Detection engineering", "pages/14_Detection_Engineering.py", "de"),
            ("Governance", "pages/17_Governance.py", "gov"),
        ],
    ),
    (
        "Engineering & AI",
        [
            ("Rule draft assistant", "pages/19_Rule_Draft_Assistant.py", "draft"),
            ("AI configuration", "pages/0_AI_Config.py", "ai"),
        ],
    ),
    (
        "Operations & admin",
        [
            ("Git Sigma import", "pages/18_Git_Sigma_Import.py", "git"),
            ("Administration", "pages/8_Admin.py", "admin"),
        ],
    ),
]


def count_unread_notifications(username: str | None) -> int:
    if not username:
        return 0
    try:
        from db.session import SessionLocal
        from db.repo import NotificationRepository

        db = SessionLocal()
        try:
            return int(NotificationRepository.count_unread(db, username))
        finally:
            db.close()
    except Exception:
        return 0


def _collab_label(unread: int) -> str:
    if unread and unread > 0:
        return f"Collaboration ({unread})"
    return "Collaboration"


def render_sidebar_navigation(username: str, unread_notifications: int = 0) -> None:
    """Grouped page links (used under the app chrome)."""
    st.sidebar.markdown("### Navigate")
    if st.sidebar.button("Home", key="sb_nav_home", use_container_width=True):
        st.switch_page("app.py")
    st.sidebar.divider()
    for title, items in _NAV_GROUPS:
        st.sidebar.caption(title.upper())
        for label, path, suffix in items:
            display = label
            if suffix == "collab":
                display = _collab_label(unread_notifications)
            key = f"sb_nav_{suffix}"
            if st.sidebar.button(display, key=key, use_container_width=True):
                st.switch_page(path)
    st.sidebar.divider()
    st.sidebar.caption("Account")
    if st.sidebar.button("My profile", key="sb_nav_profile", use_container_width=True):
        st.switch_page("pages/9_My_Profile.py")


def render_app_sidebar(username: str, unread_notifications: int | None = None) -> None:
    """
    Full sidebar: maintenance, identity, sign out, then grouped navigation.
    Call once per page after the user is authenticated.
    """
    apply_global_styles()
    from services.auth import logout
    from services.feature_flags import maintenance_message

    if unread_notifications is None:
        unread_notifications = count_unread_notifications(username)

    st.sidebar.title("🏭 Detection Rules Factory")
    _msg = maintenance_message()
    if _msg:
        st.sidebar.warning(_msg)
    st.sidebar.success(f"Logged in as: **{username}**")
    st.sidebar.caption(
        f"Role **{st.session_state.get('user_role', 'N/A')}** · "
        f"Team **{st.session_state.get('user_team', 'N/A')}**"
    )
    if st.sidebar.button("Sign out", key="sb_signout_global", use_container_width=True):
        logout()
        st.rerun()
    st.sidebar.divider()
    render_sidebar_navigation(username, unread_notifications)


def render_home_quick_links(unread_notifications: int = 0) -> None:
    """Home page: expanders instead of a wall of buttons."""
    with st.container(border=True):
        st.markdown("### Quick access")
        st.caption("Grouped shortcuts — same destinations as the sidebar.")
        for idx, (title, items) in enumerate(_NAV_GROUPS):
            expanded = idx == 0
            with st.expander(title, expanded=expanded):
                n = len(items)
                ncols = min(4, max(1, n))
                cols = st.columns(ncols)
                for i, (label, path, suffix) in enumerate(items):
                    display = _collab_label(unread_notifications) if suffix == "collab" else label
                    key = f"home_{suffix}"
                    with cols[i % ncols]:
                        if st.button(display, key=key, use_container_width=True):
                            st.switch_page(path)

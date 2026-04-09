"""Grouped navigation: sidebar roles (usr / conf) + workspace sections."""

from __future__ import annotations

import html

import streamlit as st

from utils.streamlit_ui import apply_global_styles

# Material Symbols (Streamlit :material/...:)
_NAV_MATERIAL: dict[str, str] = {
    "ws": ":material/workspaces:",
    "rules": ":material/view_kanban:",
    "collab": ":material/forum:",
    "audit": ":material/verified_user:",
    "mapping": ":material/schema:",
    "dash": ":material/insert_chart:",
    "group": ":material/groups:",
    "hub": ":material/hub:",
    "cti_det": ":material/radar:",
    "cti_lib": ":material/library_books:",
    "workflow": ":material/account_tree:",
    "diff": ":material/compare_arrows:",
    "trail": ":material/history:",
    "de": ":material/science:",
    "gov": ":material/gavel:",
    "draft": ":material/edit_note:",
    "ai": ":material/tune:",
    "git": ":material/cloud_download:",
    "admin": ":material/admin_panel_settings:",
    "profile": ":material/person:",
    "workspaces": ":material/hub:",
    "search": ":material/search:",
    "onboard": ":material/school:",
}

# (group title, [(label, page path, suffix, required_permission), ...])
# required_permission: None = tout utilisateur connecté (read) ; sinon clé ROLES dans services.auth
# Order: métier d’abord, puis usr (compte), puis conf (plateforme / IA / admin)
_NAV_GROUPS: list[tuple[str, list[tuple[str, str, str, str | None]]]] = [
    (
        "Workspace",
        [
            ("My workspace", "pages/10_My_Workspace.py", "ws", None),
            ("Workspaces", "pages/20_Workspaces.py", "workspaces", None),
            ("Rules catalogue", "pages/1_Use_Cases.py", "rules", None),
            ("Collaboration", "pages/16_Collaboration.py", "collab", None),
        ],
    ),
    (
        "MITRE & coverage",
        [
            ("MITRE audit", "pages/2_Audit.py", "audit", None),
            ("Mapping analysis", "pages/3_Mapping.py", "mapping", None),
            ("Coverage dashboard", "pages/4_Dashboard_MITRE.py", "dash", None),
            ("Group coverage", "pages/5_Group_Coverage.py", "group", None),
            ("MITRE coverage hub", "pages/13_MITRE_Coverage_Hub.py", "hub", None),
        ],
    ),
    (
        "CTI",
        [
            ("CTI detection", "pages/6_CTI_Detection.py", "cti_det", None),
            ("CTI library", "pages/15_CTI_Library.py", "cti_lib", None),
        ],
    ),
    (
        "Lifecycle & quality",
        [
            ("Use case workflow", "pages/11_Use_Case_Workflow.py", "workflow", "update"),
            ("Rule version diff", "pages/12_Rule_Version_Diff.py", "diff", None),
            ("Audit trail", "pages/7_Audit_Trail.py", "trail", None),
            ("Detection engineering", "pages/14_Detection_Engineering.py", "de", None),
            ("Governance", "pages/17_Governance.py", "gov", None),
        ],
    ),
    (
        "Rule drafting",
        [
            ("Rule draft assistant", "pages/19_Rule_Draft_Assistant.py", "draft", "trigger_ai"),
        ],
    ),
    (
        "Imports",
        [
            ("Git Sigma import", "pages/18_Git_Sigma_Import.py", "git", "create"),
        ],
    ),
    (
        "Search",
        [
            ("Global search", "pages/21_Global_Search.py", "search", None),
        ],
    ),
    (
        "usr · Compte",
        [
            ("My profile", "pages/9_My_Profile.py", "profile", None),
            ("Onboarding", "pages/22_Onboarding.py", "onboard", None),
        ],
    ),
    (
        "conf · Configuration",
        [
            ("AI configuration", "pages/0_AI_Config.py", "ai", None),
            ("Administration", "pages/8_Admin.py", "admin", "admin"),
        ],
    ),
]


def nav_groups_for_current_user() -> list[tuple[str, list[tuple[str, str, str]]]]:
    """Liens visibles selon RBAC (sidebar et dashboard cohérents)."""
    from services.auth import has_permission

    out: list[tuple[str, list[tuple[str, str, str]]]] = []
    for title, items in _NAV_GROUPS:
        visible: list[tuple[str, str, str]] = []
        for label, path, suffix, req in items:
            if req is None:
                if not has_permission("read"):
                    continue
            elif not has_permission(req):
                continue
            visible.append((label, path, suffix))
        if visible:
            out.append((title, visible))
    return out


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


def _icon_for_suffix(suffix: str) -> str:
    return _NAV_MATERIAL.get(suffix, ":material/chevron_right:")


def _link_label(label: str, suffix: str, unread_notifications: int) -> str:
    if suffix == "collab":
        return _collab_label(unread_notifications)
    return label


def render_sidebar_navigation(username: str, unread_notifications: int = 0) -> None:
    """Expanders par zone + page_link (filtré RBAC, une seule colonne à gauche)."""
    for idx, (group_title, items) in enumerate(nav_groups_for_current_user()):
        with st.sidebar.expander(group_title, expanded=(idx == 0)):
            for label, path, suffix in items:
                st.page_link(
                    path,
                    label=_link_label(label, suffix, unread_notifications),
                    icon=_icon_for_suffix(suffix),
                    use_container_width=True,
                )


def render_app_sidebar(username: str, unread_notifications: int | None = None) -> None:
    """Sidebar: brand, compact identity, menus only, Sign out en bas."""
    apply_global_styles()
    from services.auth import logout
    from services.feature_flags import maintenance_message

    if unread_notifications is None:
        unread_notifications = count_unread_notifications(username)

    st.sidebar.page_link(
        "app.py",
        label="Detection Rules Factory",
        icon=":material/layers:",
        help="Home",
        use_container_width=True,
    )
    _msg = maintenance_message()
    if _msg:
        st.sidebar.warning(_msg)

    role = st.session_state.get("user_role", "N/A")
    team = st.session_state.get("user_team", "N/A")
    safe_u = html.escape(str(username))
    safe_r = html.escape(str(role))
    safe_t = html.escape(str(team))
    st.sidebar.markdown(
        f'<div class="drf-sidebar-ident">'
        f'<span class="drf-sidebar-ident-name">{safe_u}</span>'
        f'<span class="drf-sidebar-ident-meta">{safe_r} · {safe_t}</span>'
        f"</div>",
        unsafe_allow_html=True,
    )

    st.sidebar.divider()
    st.sidebar.caption("Tâches accessibles selon votre rôle")
    render_sidebar_navigation(username, unread_notifications)

    st.sidebar.divider()
    if st.sidebar.button(
        "Sign out",
        key="sb_signout_global",
        icon=":material/logout:",
        type="tertiary",
        use_container_width=True,
    ):
        logout()
        st.rerun()


def render_dashboard_expanders_only(unread_notifications: int = 0) -> None:
    """Blocs de navigation (expanders) — à éviter sur l’accueil (doublon sidebar). Rétrocompat."""
    with st.container(border=True):
        for idx, (title, items) in enumerate(nav_groups_for_current_user()):
            expanded = idx == 0
            with st.expander(title, expanded=expanded):
                for label, path, suffix in items:
                    st.page_link(
                        path,
                        label=_link_label(label, suffix, unread_notifications),
                        icon=_icon_for_suffix(suffix),
                        use_container_width=True,
                    )


def render_home_quick_links(unread_notifications: int = 0) -> None:
    """Rétrocompat : ancienne page d’accueil avec liens dupliqués. Préférer le dashboard stats."""
    st.markdown("### Dashboard")
    st.caption(
        "Navigation alignée sur la sidebar : métier (Workspace → Imports), "
        "puis **usr** (compte), puis **conf** (configuration plateforme / IA)."
    )
    render_dashboard_expanders_only(unread_notifications)

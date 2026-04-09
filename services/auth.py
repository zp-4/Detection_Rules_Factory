"""Simple RBAC authentication service."""
import yaml
import os
from typing import Optional, Dict, Any
import streamlit as st

from utils.password_hashing import verify_password


# Default roles and permissions
ROLES = {
    "reader": ["read"],
    "contributor": ["read", "create", "update"],
    "reviewer": ["read", "create", "update", "review", "trigger_ai"],
    "admin": ["read", "create", "update", "review", "trigger_ai", "admin", "force_rerun"]
}


def load_rbac_config() -> Dict:
    """Load RBAC configuration from YAML or secrets."""
    # Try secrets first (for Streamlit Cloud)
    try:
        if hasattr(st, 'secrets') and "rbac" in st.secrets:
            return st.secrets["rbac"]
    except Exception:
        # Secrets file doesn't exist, continue to file-based config
        pass
    
    # Try config file
    config_path = os.path.join("config", "rbac.yaml")
    if os.path.exists(config_path):
        with open(config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    
    # Default config
    return {
        "users": {
            "admin": {"role": "admin", "team": "security"},
            "reviewer1": {"role": "reviewer", "team": "security"},
            "contributor1": {"role": "contributor", "team": "soc"},
            "reader1": {"role": "reader", "team": "soc"}
        }
    }


def get_current_user() -> Optional[str]:
    """Get current user from session state."""
    return st.session_state.get("username")


def get_user_role(username: Optional[str] = None) -> Optional[str]:
    """Get user role."""
    if not username:
        username = get_current_user()
    
    if not username:
        return None
    
    config = load_rbac_config()
    user_config = config.get("users", {}).get(username)
    if user_config:
        return user_config.get("role")
    return None


def get_user_team(username: Optional[str] = None) -> Optional[str]:
    """Get user team."""
    if not username:
        username = get_current_user()
    
    if not username:
        return None
    
    config = load_rbac_config()
    user_config = config.get("users", {}).get(username)
    if user_config:
        return user_config.get("team")
    return None


def get_user_entry(username: str) -> Optional[Dict[str, Any]]:
    """Return the RBAC dict for a username, or None."""
    if not username:
        return None
    config = load_rbac_config()
    entry = config.get("users", {}).get(username)
    if entry is None:
        return None
    if not isinstance(entry, dict):
        return None
    return entry


def user_has_password(username: str) -> bool:
    """True if this account requires a password (password_hash set in RBAC)."""
    entry = get_user_entry(username)
    if not entry:
        return False
    ph = entry.get("password_hash")
    return bool(ph and str(ph).strip())


def has_permission(permission: str, username: Optional[str] = None) -> bool:
    """Check if user has permission."""
    role = get_user_role(username)
    if not role:
        return False
    
    permissions = ROLES.get(role, [])
    return permission in permissions


def require_permission(permission: str):
    """Decorator to require permission."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            if not has_permission(permission):
                st.error(f"Permission denied. Required: {permission}")
                st.stop()
            return func(*args, **kwargs)
        return wrapper
    return decorator


SIGN_IN_PAGE = "pages/0_Login.py"


def require_sign_in(page_description: str = "this page") -> None:
    """
    If the user is not logged in, show a gate with a link to the sign-in
    portal and stop rendering the rest of the page.
    """
    if get_current_user():
        return
    st.warning(f"Please sign in to access {page_description}.")
    if st.button("Open sign-in portal", type="primary"):
        st.switch_page(SIGN_IN_PAGE)
    st.caption("Sign in via the portal (see `config/rbac.yaml`; optional passwords).")
    st.stop()


def login(username: str, password: str = "") -> bool:
    """
    Authenticate against RBAC config. If the user has ``password_hash`` set
    (see ``scripts/hash_password.py``), the password must match; otherwise
    username-only login remains allowed (demo mode).
    """
    config = load_rbac_config()
    users = config.get("users", {})
    if username not in users:
        return False
    entry = get_user_entry(username)
    if entry:
        ph = entry.get("password_hash")
        if ph and str(ph).strip():
            if not verify_password(password, str(ph).strip()):
                return False
    st.session_state["username"] = username
    st.session_state["user_role"] = get_user_role(username)
    st.session_state["user_team"] = get_user_team(username)
    return True


def logout():
    """Logout user."""
    if "username" in st.session_state:
        del st.session_state["username"]
    if "user_role" in st.session_state:
        del st.session_state["user_role"]
    if "user_team" in st.session_state:
        del st.session_state["user_team"]


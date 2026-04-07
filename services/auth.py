"""Simple RBAC authentication service."""
import yaml
import os
from typing import Optional, Dict, List
import streamlit as st


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
        with open(config_path, 'r') as f:
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


def login(username: str, password: str = "") -> bool:
    """
    Simple login (MVP - no real password check).
    In production, implement proper authentication.
    """
    config = load_rbac_config()
    if username in config.get("users", {}):
        st.session_state["username"] = username
        st.session_state["user_role"] = get_user_role(username)
        st.session_state["user_team"] = get_user_team(username)
        return True
    return False


def logout():
    """Logout user."""
    if "username" in st.session_state:
        del st.session_state["username"]
    if "user_role" in st.session_state:
        del st.session_state["user_role"]
    if "user_team" in st.session_state:
        del st.session_state["user_team"]


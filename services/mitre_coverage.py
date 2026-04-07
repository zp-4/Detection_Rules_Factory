"""MITRE coverage service wrapper."""
import streamlit as st
from src.mitre_engine import MitreEngine
from typing import Dict, Any, List


# Bump when MitreEngine API changes so session picks up new class/methods.
_MITRE_ENGINE_SESSION_KEY = "mitre_engine_v2"


def get_mitre_engine() -> MitreEngine:
    """Get MITRE engine instance (singleton pattern)."""
    if _MITRE_ENGINE_SESSION_KEY not in st.session_state:
        st.session_state[_MITRE_ENGINE_SESSION_KEY] = MitreEngine()
    return st.session_state[_MITRE_ENGINE_SESSION_KEY]


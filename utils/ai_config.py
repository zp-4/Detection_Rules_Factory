"""AI configuration utilities for storing and retrieving API keys."""
import json
import os
from typing import Optional, Dict, Any, List

# Curated model lists for AI Configuration dropdowns (update as providers ship new models).
# Users can pick "Custom" to enter any model id supported by the API.
OPENAI_MODEL_OPTIONS: List[str] = [
    "gpt-4o",
    "gpt-4o-mini",
    "gpt-4-turbo",
    "gpt-4",
    "gpt-3.5-turbo",
    "o1",
    "o1-mini",
    "o3-mini",
]
GEMINI_MODEL_OPTIONS: List[str] = [
    "gemini-2.0-flash",
    "gemini-1.5-flash",
    "gemini-1.5-pro",
    "gemini-pro",
]
CUSTOM_MODEL_LABEL = "Custom (enter model id)..."

# Optional streamlit import (only used for error messages)
try:
    import streamlit as st
except ImportError:
    st = None

AI_CONFIG_FILE = ".streamlit/ai_config.json"

# Defaults when keys are missing (file or older config without model fields)
DEFAULT_AI_CONFIG: Dict[str, Any] = {
    "provider": None,
    "openai_api_key": None,
    "gemini_api_key": None,
    "openai_model_name": "gpt-4o",
    "gemini_model_name": "gemini-1.5-flash",
    "llama_api_key": None,
    "llama_base_url": None,
    "llama_model_name": None,
}


def get_ai_config() -> Dict[str, Any]:
    """Load AI configuration from file, merged with defaults."""
    try:
        if not os.path.exists(AI_CONFIG_FILE):
            return dict(DEFAULT_AI_CONFIG)

        with open(AI_CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
        merged = {**DEFAULT_AI_CONFIG, **config}
        return merged
    except Exception:
        return dict(DEFAULT_AI_CONFIG)


def get_openai_model_name() -> str:
    """OpenAI model id (e.g. gpt-4o)."""
    name = get_ai_config().get("openai_model_name")
    if not name:
        return DEFAULT_AI_CONFIG["openai_model_name"]
    s = str(name).strip()
    return s or DEFAULT_AI_CONFIG["openai_model_name"]


def get_gemini_model_name() -> str:
    """Gemini model id (e.g. gemini-1.5-flash)."""
    name = get_ai_config().get("gemini_model_name")
    if not name:
        return DEFAULT_AI_CONFIG["gemini_model_name"]
    s = str(name).strip()
    return s or DEFAULT_AI_CONFIG["gemini_model_name"]

def save_ai_config(config: Dict[str, Any]) -> bool:
    """Save AI configuration to file."""
    try:
        os.makedirs('.streamlit', exist_ok=True)
        with open(AI_CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        if st:
            st.error(f"Error saving configuration: {e}")
        return False

def clear_ai_config() -> bool:
    """Clear AI configuration file."""
    try:
        if os.path.exists(AI_CONFIG_FILE):
            os.remove(AI_CONFIG_FILE)
        return True
    except Exception as e:
        if st:
            st.error(f"Error clearing configuration: {e}")
        return False

def get_api_key_for_provider(provider: str) -> Optional[str]:
    """Get API key for a specific provider from saved config."""
    config = get_ai_config()
    
    if provider.lower() == "openai":
        return config.get("openai_api_key")
    elif provider.lower() == "gemini":
        return config.get("gemini_api_key")
    elif provider.lower() == "llama":
        return config.get("llama_api_key")
    
    return None

def get_llama_config() -> Dict[str, Optional[str]]:
    """Get Llama-specific configuration."""
    config = get_ai_config()
    return {
        "base_url": config.get("llama_base_url"),
        "model_name": config.get("llama_model_name"),
        "api_key": config.get("llama_api_key"),
    }

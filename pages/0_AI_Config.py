"""AI Configuration Page - Configure and save AI provider API keys."""
import streamlit as st
from utils.ai_config import (
    get_ai_config,
    save_ai_config,
    clear_ai_config,
    OPENAI_MODEL_OPTIONS,
    GEMINI_MODEL_OPTIONS,
    CUSTOM_MODEL_LABEL,
)
from services.auth import get_current_user, require_sign_in
from utils.app_navigation import render_app_sidebar

st.set_page_config(
    page_title="AI Configuration",
    page_icon="🤖",
    layout="wide"
)

require_sign_in("AI Configuration")
username = get_current_user()
render_app_sidebar(username)

st.title("🤖 AI Configuration")

st.markdown("""
Configure your API keys for different AI providers. 
These settings will be saved and automatically used in all pages requiring AI analysis.
""")

# Load current configuration
config = get_ai_config()

# Provider selection
st.subheader("AI Provider")
ai_provider = st.selectbox(
    "Select AI Provider",
    ["OpenAI", "Gemini", "Llama (Custom LLM)"],
    index=0 if config.get("provider") == "OpenAI" else (1 if config.get("provider") == "Gemini" else 2) if config.get("provider") else 0,
    help="Select the AI provider you want to use"
)

# OpenAI configuration
if ai_provider == "OpenAI":
    st.subheader("OpenAI Configuration")
    openai_key = st.text_input(
        "OpenAI API Key",
        value=config.get("openai_api_key", "") if config.get("openai_api_key") else "",
        type="password",
        help="Enter your OpenAI API key. You can find it at https://platform.openai.com/api-keys"
    )
    saved_openai_model = (config.get("openai_model_name") or "gpt-4o").strip()
    openai_dd_options = OPENAI_MODEL_OPTIONS + [CUSTOM_MODEL_LABEL]
    if saved_openai_model in OPENAI_MODEL_OPTIONS:
        _openai_idx = OPENAI_MODEL_OPTIONS.index(saved_openai_model)
    else:
        _openai_idx = len(OPENAI_MODEL_OPTIONS)
    openai_choice = st.selectbox(
        "Model name",
        options=openai_dd_options,
        index=_openai_idx,
        help="Current OpenAI models (see https://platform.openai.com/docs/models). Use Custom for any other model id.",
        key="cfg_openai_model_dd",
    )
    openai_custom = ""
    if openai_choice == CUSTOM_MODEL_LABEL:
        openai_custom = st.text_input(
            "Custom OpenAI model id",
            value=saved_openai_model if saved_openai_model not in OPENAI_MODEL_OPTIONS else "",
            placeholder="e.g. gpt-4.1-mini",
            help="Exact model name as returned by the OpenAI API.",
            key="cfg_openai_model_custom",
        )
    
    if st.button("💾 Save OpenAI Configuration", type="primary"):
        new_config = config.copy()
        new_config["provider"] = "OpenAI"
        new_config["openai_api_key"] = openai_key if openai_key else None
        if openai_choice == CUSTOM_MODEL_LABEL:
            new_config["openai_model_name"] = (openai_custom or "").strip() or "gpt-4o"
        else:
            new_config["openai_model_name"] = openai_choice
        if save_ai_config(new_config):
            st.success("✅ OpenAI configuration saved successfully!")
            st.rerun()

# Gemini configuration
elif ai_provider == "Gemini":
    st.subheader("Gemini Configuration")
    gemini_key = st.text_input(
        "Gemini API Key",
        value=config.get("gemini_api_key", "") if config.get("gemini_api_key") else "",
        type="password",
        help="Enter your Google AI (Gemini) API key. You can find it at https://makersuite.google.com/app/apikey"
    )
    saved_gemini_model = (config.get("gemini_model_name") or "gemini-1.5-flash").strip()
    gemini_dd_options = GEMINI_MODEL_OPTIONS + [CUSTOM_MODEL_LABEL]
    if saved_gemini_model in GEMINI_MODEL_OPTIONS:
        _gemini_idx = GEMINI_MODEL_OPTIONS.index(saved_gemini_model)
    else:
        _gemini_idx = len(GEMINI_MODEL_OPTIONS)
    gemini_choice = st.selectbox(
        "Model name",
        options=gemini_dd_options,
        index=_gemini_idx,
        help="Current Google AI Gemini models. Use Custom for preview or newer ids from Google AI Studio.",
        key="cfg_gemini_model_dd",
    )
    gemini_custom = ""
    if gemini_choice == CUSTOM_MODEL_LABEL:
        gemini_custom = st.text_input(
            "Custom Gemini model id",
            value=saved_gemini_model if saved_gemini_model not in GEMINI_MODEL_OPTIONS else "",
            placeholder="e.g. gemini-2.5-flash-preview-05-20",
            help="Exact model id for the Generative Language API.",
            key="cfg_gemini_model_custom",
        )
    
    if st.button("💾 Save Gemini Configuration", type="primary"):
        new_config = config.copy()
        new_config["provider"] = "Gemini"
        new_config["gemini_api_key"] = gemini_key if gemini_key else None
        if gemini_choice == CUSTOM_MODEL_LABEL:
            new_config["gemini_model_name"] = (gemini_custom or "").strip() or "gemini-1.5-flash"
        else:
            new_config["gemini_model_name"] = gemini_choice
        if save_ai_config(new_config):
            st.success("✅ Gemini configuration saved successfully!")
            st.rerun()

# Llama configuration
elif ai_provider == "Llama (Custom LLM)":
    st.subheader("Llama (Custom LLM) Configuration")
    st.info("""
    **Configuration for Custom LLM** (Ollama, vLLM, text-generation-inference, LM Studio, etc.)
    
    These LLMs use an OpenAI-compatible API. Configure the base URL and model name.
    """)
    
    llama_base_url = st.text_input(
        "API Base URL",
        value=config.get("llama_base_url", "http://localhost:11434/v1") if config.get("llama_base_url") else "http://localhost:11434/v1",
        placeholder="http://localhost:11434/v1",
        help="OpenAI-compatible API endpoint URL (e.g., Ollama: http://localhost:11434/v1)"
    )
    
    llama_model_name = st.text_input(
        "Model Name",
        value=config.get("llama_model_name", "llama3") if config.get("llama_model_name") else "llama3",
        placeholder="llama3, mistral, codellama, etc.",
        help="Model name as configured on your LLM server"
    )
    
    llama_key = st.text_input(
        "API Key (optional)",
        value=config.get("llama_api_key", "") if config.get("llama_api_key") else "",
        type="password",
        help="Leave empty if your LLM server doesn't require authentication"
    )
    
    if st.button("💾 Save Llama Configuration", type="primary"):
        new_config = config.copy()
        new_config["provider"] = "Llama (Custom LLM)"
        new_config["llama_base_url"] = llama_base_url if llama_base_url else None
        new_config["llama_model_name"] = llama_model_name if llama_model_name else None
        new_config["llama_api_key"] = llama_key if llama_key else None
        if save_ai_config(new_config):
            st.success("✅ Llama configuration saved successfully!")
            st.rerun()

# Display current configuration status
st.divider()
st.subheader("📋 Current Configuration Status")

col1, col2 = st.columns(2)

with col1:
    st.markdown("**Configured Provider:**")
    if config.get("provider"):
        st.success(f"✅ {config.get('provider')}")
    else:
        st.warning("⚠️ No provider configured")

with col2:
    st.markdown("**Configured API Keys:**")
    keys_status = []
    if config.get("openai_api_key"):
        om = config.get("openai_model_name") or "gpt-4o"
        keys_status.append(f"✅ OpenAI (model: `{om}`)")
    if config.get("gemini_api_key"):
        gm = config.get("gemini_model_name") or "gemini-1.5-flash"
        keys_status.append(f"✅ Gemini (model: `{gm}`)")
    if config.get("llama_api_key") or config.get("llama_base_url"):
        lm = config.get("llama_model_name") or "llama3"
        keys_status.append(f"✅ Llama (model: `{lm}`)")
    
    if keys_status:
        st.success("\n".join(keys_status))
    else:
        st.warning("⚠️ No API keys configured")

# Clear configuration button
st.divider()
st.subheader("🗑️ Clear Configuration")

st.warning("⚠️ This action will delete all saved configurations.")

if st.button("🗑️ Clear All Configuration", type="secondary"):
    if clear_ai_config():
        st.success("✅ Configuration cleared successfully!")
        st.rerun()

# Help section
st.divider()
with st.expander("ℹ️ Help"):
    st.markdown("""
    ### How to use this page:
    
    1. **Select a provider** from the dropdown menu
    2. **Enter your API key** (or configure the URL for Llama)
    3. **Click "Save"** to save the configuration
    4. Keys will be automatically used in all pages requiring AI analysis
    
    ### Supported Providers:
    
    - **OpenAI**: Set your API key and pick a model from the list (or **Custom** for any model id)
    - **Gemini**: Set your API key and pick a model from the list (or **Custom** for preview / newer ids)
    - **Llama (Custom LLM)**: For self-hosted LLMs with OpenAI-compatible API
    
    ### Security:
    
    - API keys are stored locally in `.streamlit/ai_config.json`
    - Keys are never displayed in plain text (except during input)
    - You can delete the configuration at any time
    """)

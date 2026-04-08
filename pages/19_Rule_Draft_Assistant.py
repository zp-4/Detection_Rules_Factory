"""AI assistant: natural language → rule skeleton + MITRE + FP checklist."""
import streamlit as st

from db.session import SessionLocal
from src.ai_engine import AIEngine
from services.auth import has_permission, require_sign_in
from services.rule_draft_assistant import run_rule_draft_assistant
from utils.ai_config import (
    get_ai_config,
    get_api_key_for_provider,
    get_gemini_model_name,
    get_llama_config,
    get_openai_model_name,
)
from utils.session_persistence import restore_session_state

restore_session_state()

st.set_page_config(
    page_title="Rule draft assistant",
    page_icon="✍️",
    layout="wide",
)

require_sign_in("Rule draft assistant")

if not has_permission("trigger_ai"):
    st.error("**trigger_ai** permission is required (e.g. reviewer or admin).")
    st.stop()

st.title("✍️ Rule draft assistant")
st.caption(
    "Describe what you want to detect in plain language. The model returns a **rule skeleton**, "
    "**suggested MITRE technique IDs**, and a **false-positive checklist**. Uses your team AI quota."
)
st.caption("Configure API keys in **pages/0_AI_Config.py** or another AI page’s sidebar (saved under `.streamlit/ai_config.json`).")

saved = get_ai_config()
st.sidebar.header("🤖 AI Configuration")
ai_provider = st.sidebar.selectbox(
    "AI Provider",
    ["OpenAI", "Gemini", "Llama (Custom LLM)"],
    index=0 if saved.get("provider") != "Gemini" else 1,
)
openai_api_key = get_api_key_for_provider("OpenAI")
gemini_api_key = get_api_key_for_provider("Gemini")
_llama = get_llama_config()
llama_api_key = _llama.get("api_key")
llama_base_url = _llama.get("base_url")
llama_model_name = _llama.get("model_name")
openai_model_name = get_openai_model_name()
gemini_model_name = get_gemini_model_name()

platform = st.selectbox(
    "Target platform",
    ["Windows", "Linux", "macOS", "Cloud", "SaaS", "Network", "Sigma"],
    index=0,
)
rule_format = st.selectbox(
    "Preferred format",
    ["sigma", "splunk", "kql", "other"],
    index=0,
)

description = st.text_area(
    "What should this rule detect?",
    height=180,
    placeholder="Example: Detect PowerShell downloading a script and executing it within one minute on Windows endpoints, excluding known patch management paths.",
)

db = SessionLocal()
try:
    if st.button("Generate draft", type="primary"):
        if not description.strip():
            st.warning("Enter a description.")
        else:
            team_kw = st.session_state.get("user_team")
            try:
                if ai_provider == "OpenAI":
                    if not openai_api_key:
                        st.error("OpenAI API key missing in sidebar / AI config.")
                        st.stop()
                    engine = AIEngine(
                        openai_api_key,
                        provider="openai",
                        model_name=openai_model_name,
                        team=team_kw,
                    )
                elif ai_provider == "Gemini":
                    if not gemini_api_key:
                        st.error("Gemini API key missing.")
                        st.stop()
                    engine = AIEngine(
                        gemini_api_key,
                        provider="gemini",
                        model_name=gemini_model_name,
                        team=team_kw,
                    )
                else:
                    if not llama_base_url:
                        st.error("Llama base URL required.")
                        st.stop()
                    engine = AIEngine(
                        api_key=llama_api_key or "",
                        provider="llama",
                        base_url=llama_base_url,
                        model_name=llama_model_name or "llama3",
                        team=team_kw,
                    )
            except RuntimeError as ex:
                st.error(str(ex))
                st.stop()

            with st.spinner("Generating draft…"):
                result = run_rule_draft_assistant(
                    db,
                    engine,
                    description,
                    preferred_platform=platform,
                    preferred_format=rule_format,
                )

            if result.get("error"):
                st.error(result["error"])
            elif result.get("not_applicable"):
                st.warning(result.get("summary") or "Not applicable.")
            else:
                if result.get("rule_name"):
                    st.subheader(result["rule_name"])
                if result.get("summary"):
                    st.info(result["summary"])

                col_m, col_fp = st.columns(2)
                with col_m:
                    st.markdown("#### MITRE")
                    if result.get("mitre_technique_id"):
                        st.write(f"**Primary:** `{result['mitre_technique_id']}`")
                    ids = result.get("mitre_technique_ids") or []
                    if ids:
                        st.write("**IDs:** " + ", ".join(f"`{x}`" for x in ids))
                    if result.get("mitre_rationale"):
                        st.write(result["mitre_rationale"])

                with col_fp:
                    st.markdown("#### False-positive checklist")
                    for item in result.get("fp_checklist") or []:
                        st.markdown(f"- {item}")

                if result.get("rule_text"):
                    st.markdown("#### Rule skeleton")
                    st.code(
                        result["rule_text"],
                        language="yaml" if rule_format == "sigma" else None,
                    )
finally:
    db.close()

st.divider()
if st.button("← Home"):
    st.switch_page("app.py")

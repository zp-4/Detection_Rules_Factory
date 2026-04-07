"""CTI Detection Opportunity - AI-powered rule extraction from threat intelligence."""
# -*- coding: utf-8 -*-
import sys
import os
# Set UTF-8 encoding for Windows compatibility
if sys.platform == 'win32':
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    # Ensure UTF-8 encoding is used
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    if hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8')

import streamlit as st
import pandas as pd
import requests
from bs4 import BeautifulSoup
from io import BytesIO
import PyPDF2
from typing import Optional, Dict, Any
from datetime import datetime
from db.session import SessionLocal
from db.models import RuleImplementation, UseCase
from db.repo import RuleRepository, UseCaseRepository
from src.ai_engine import AIEngine
from services.auth import get_current_user, login, has_permission
from db.repo import RuleChangeLogRepository
from utils.hashing import compute_rule_hash
from sqlalchemy.orm.attributes import flag_modified

st.set_page_config(
    page_title="CTI Detection Opportunity",
    page_icon="🔍",
    layout="wide"
)

# Authentication check
username = get_current_user()
if not username:
    st.warning("Please login to access CTI Detection Opportunity")
    st.divider()
    
    # Login form
    with st.form("login_form_cti"):
        st.subheader("Login")
        login_username = st.text_input("Username", placeholder="Enter your username")
        if st.form_submit_button("Login", type="primary"):
            if login_username:
                if login(login_username):
                    st.success(f"Logged in as {login_username}")
                    st.rerun()
                else:
                    st.error("Invalid username. Please check your credentials.")
            else:
                st.error("Please enter a username")
    
    st.info("💡 **Demo users:** admin, reviewer1, contributor1, reader1")
    st.stop()

st.title("🔍 CTI Detection Opportunity")
st.markdown("""
**AI-Powered Detection Rule Extraction from Threat Intelligence**

Upload CTI content (text, PDF, Excel, or URL) and let AI analyze it to propose detection rules for your catalogue.
""")

# Helper functions for content extraction
def extract_text_from_pdf(uploaded_file) -> str:
    """Extract text from PDF file."""
    try:
        pdf_reader = PyPDF2.PdfReader(uploaded_file)
        text = ""
        for page in pdf_reader.pages:
            text += page.extract_text() + "\n"
        return text
    except Exception as e:
        st.error(f"Error reading PDF: {e}")
        return ""

def extract_text_from_excel(uploaded_file) -> str:
    """Extract text from Excel file."""
    try:
        df = pd.read_excel(uploaded_file, sheet_name=None)
        text_parts = []
        for sheet_name, sheet_df in df.items():
            text_parts.append(f"Sheet: {sheet_name}\n")
            text_parts.append(sheet_df.to_string())
            text_parts.append("\n")
        return "\n".join(text_parts)
    except Exception as e:
        st.error(f"Error reading Excel: {e}")
        return ""

def extract_text_from_url(url: str) -> str:
    """Extract text content from a URL."""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.decompose()
        
        # Get text
        text = soup.get_text()
        
        # Clean up whitespace
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        text = ' '.join(chunk for chunk in chunks if chunk)
        
        return text
    except Exception as e:
        st.error(f"Error fetching URL: {e}")
        return ""

# Sidebar - AI Configuration
st.sidebar.header("🤖 AI Configuration")

# Load saved AI configuration
from utils.ai_config import (
    get_ai_config,
    get_api_key_for_provider,
    get_llama_config,
    get_openai_model_name,
    get_gemini_model_name,
)
saved_config = get_ai_config()
saved_provider = saved_config.get("provider")

ai_provider = st.sidebar.selectbox(
    "AI Provider",
    ["None", "OpenAI", "Gemini", "Llama (Custom LLM)"],
    index=0 if not saved_provider else (1 if saved_provider == "OpenAI" else (2 if saved_provider == "Gemini" else 3)),
    help="Select AI provider for CTI analysis"
)

# Link to AI config page
if st.sidebar.button("⚙️ Configure API Keys", use_container_width=True):
    st.switch_page("pages/0_AI_Config.py")

openai_api_key = None
gemini_api_key = None
openai_model_name = None
gemini_model_name = None
llama_api_key = None
llama_base_url = None
llama_model_name = None

# Load from saved config if available, otherwise allow manual input
if ai_provider == "OpenAI":
    saved_key = get_api_key_for_provider("OpenAI")
    if saved_key:
        st.sidebar.success("✅ OpenAI API key loaded from configuration")
        openai_api_key = saved_key
        openai_model_name = get_openai_model_name()
        st.sidebar.caption(f"Model from config: **{openai_model_name}**")
    else:
        openai_api_key = st.sidebar.text_input("OpenAI API Key", type="password", key="cti_openai_key", help="Or configure in the 'AI Configuration' page")
        openai_model_name = st.sidebar.text_input(
            "OpenAI model",
            value="gpt-4o",
            key="cti_openai_model_manual",
            help="Model id, e.g. gpt-4o, gpt-4o-mini",
        )
elif ai_provider == "Gemini":
    saved_key = get_api_key_for_provider("Gemini")
    if saved_key:
        st.sidebar.success("✅ Gemini API key loaded from configuration")
        gemini_api_key = saved_key
        gemini_model_name = get_gemini_model_name()
        st.sidebar.caption(f"Model from config: **{gemini_model_name}**")
    else:
        gemini_api_key = st.sidebar.text_input("Gemini API Key", type="password", key="cti_gemini_key", help="Or configure in the 'AI Configuration' page")
        gemini_model_name = st.sidebar.text_input(
            "Gemini model",
            value="gemini-1.5-flash",
            key="cti_gemini_model_manual",
            help="Model id, e.g. gemini-1.5-flash, gemini-1.5-pro",
        )
elif ai_provider == "Llama (Custom LLM)":
    llama_config = get_llama_config()
    if llama_config.get("base_url"):
        st.sidebar.success("✅ Llama configuration loaded from configuration")
        llama_base_url = llama_config.get("base_url")
        llama_model_name = llama_config.get("model_name") or "llama3"
        llama_api_key = llama_config.get("api_key")
    else:
        st.sidebar.markdown("**Custom LLM Configuration**")
        llama_base_url = st.sidebar.text_input(
            "API Base URL", 
            value="http://localhost:11434/v1",
            placeholder="http://localhost:11434/v1",
            key="cti_llama_base_url",
            help="OpenAI-compatible API endpoint (Ollama, vLLM, text-generation-inference, LM Studio)"
        )
        llama_model_name = st.sidebar.text_input(
            "Model Name",
            value="llama3",
            placeholder="llama3, mistral, codellama, etc.",
            key="cti_llama_model_name",
            help="Model name as configured in your LLM server"
        )
        llama_api_key = st.sidebar.text_input(
            "API Key (optional)",
            type="password",
            key="cti_llama_api_key",
            help="Leave empty if your LLM server doesn't require authentication"
        )

# Main content area
# Reorder tabs to show Proposed Rules first if analysis is complete
if 'cti_analysis_result' in st.session_state:
    # Show Proposed Rules tab first after analysis
    tab2, tab1 = st.tabs(["📊 Proposed Rules", "📥 Input CTI Content"])
else:
    # Normal order: Input first
    tab1, tab2 = st.tabs(["📥 Input CTI Content", "📊 Proposed Rules"])

with tab1:
    st.header("📥 Input CTI Content")
    
    input_method = st.radio(
        "Select Input Method",
        ["Text", "PDF File", "Excel File", "URL"],
        horizontal=True
    )
    
    cti_content = ""
    source_type = "text"
    
    if input_method == "Text":
        cti_content = st.text_area(
            "Paste CTI Content",
            height=300,
            placeholder="Paste threat intelligence content, article text, or report here...",
            key="cti_main_text_input",
            help="Paste your content, then use the **Run analysis** button below (no Ctrl+Enter).",
        )
        source_type = "text"
    
    elif input_method == "PDF File":
        uploaded_file = st.file_uploader("Upload PDF File", type=["pdf"])
        if uploaded_file:
            with st.spinner("Extracting text from PDF..."):
                cti_content = extract_text_from_pdf(uploaded_file)
            if cti_content:
                st.success(f"✅ Extracted {len(cti_content)} characters from PDF")
                st.text_area("Extracted Content (Preview)", cti_content[:1000] + "..." if len(cti_content) > 1000 else cti_content, height=200)
            source_type = "pdf"
    
    elif input_method == "Excel File":
        uploaded_file = st.file_uploader("Upload Excel File", type=["xlsx", "xls"])
        if uploaded_file:
            with st.spinner("Extracting text from Excel..."):
                cti_content = extract_text_from_excel(uploaded_file)
            if cti_content:
                st.success(f"✅ Extracted {len(cti_content)} characters from Excel")
                st.text_area("Extracted Content (Preview)", cti_content[:1000] + "..." if len(cti_content) > 1000 else cti_content, height=200)
            source_type = "excel"
    
    elif input_method == "URL":
        url = st.text_input("Enter URL", placeholder="https://example.com/threat-report", key="cti_url_input")
        if url:
            with st.spinner("Fetching content from URL..."):
                cti_content = extract_text_from_url(url)
            if cti_content:
                st.success(f"✅ Extracted {len(cti_content)} characters from URL")
                st.text_area("Extracted Content (Preview)", cti_content[:1000] + "..." if len(cti_content) > 1000 else cti_content, height=200)
                st.info(f"🔗 **Source URL:** {url}")
                # Store URL in session state for later use
                st.session_state['cti_source_url'] = url
            source_type = "url"
    
    # Analyze button (explicit click — no keyboard shortcut)
    if cti_content and len(cti_content.strip()) > 50:
        st.divider()
        st.subheader("Run analysis")
        st.caption(
            "When your content is ready, click the button below. "
            "The AI will only propose rules if the text looks like usable threat intelligence."
        )
        # Check AI configuration
        ai_configured = False
        if ai_provider == "OpenAI" and openai_api_key:
            ai_configured = True
        elif ai_provider == "Gemini" and gemini_api_key:
            ai_configured = True
        elif ai_provider == "Llama (Custom LLM)" and llama_base_url:
            ai_configured = True
        
        if not ai_configured:
            st.warning("⚠️ Please configure an AI provider and API key in the sidebar to analyze CTI.")
        else:
            if st.button("🔍 Analyze CTI and Propose Rules", type="primary", width='stretch', key="cti_analyze_main_btn"):
                with st.spinner("🤖 AI is analyzing the CTI content and proposing detection rules..."):
                    # Initialize AI Engine
                    if ai_provider == "Llama (Custom LLM)":
                        ai_engine = AIEngine(
                            api_key=llama_api_key or "",
                            provider="llama",
                            base_url=llama_base_url,
                            model_name=llama_model_name or "llama3"
                        )
                    elif ai_provider == "OpenAI":
                        ai_engine = AIEngine(
                            openai_api_key,
                            provider="openai",
                            model_name=openai_model_name,
                        )
                    else:
                        ai_engine = AIEngine(
                            gemini_api_key,
                            provider="gemini",
                            model_name=gemini_model_name,
                        )
                    
                    # Limit content size to avoid token limits (keep last 10000 chars for context)
                    content_to_analyze = cti_content[-10000:] if len(cti_content) > 10000 else cti_content
                    
                    # Get URL if source is URL
                    source_url = st.session_state.get('cti_source_url', None) if input_method == "URL" else None
                    
                    result = ai_engine.analyze_cti_for_detection_rules(content_to_analyze, source_type, source_url=source_url)
                    
                    # Store in session state
                    st.session_state['cti_analysis_result'] = result
                    st.session_state['cti_source_type'] = source_type
                    st.session_state['cti_content'] = cti_content
                    if source_url:
                        st.session_state['cti_source_url'] = source_url
                    
                    # Rerun will automatically switch to Proposed Rules tab
                    st.rerun()
    elif cti_content and len(cti_content.strip()) <= 50:
        st.warning("⚠️ Content is too short. Please provide more CTI content (at least 50 characters).")
    else:
        st.info("💡 Enter or upload CTI content to begin analysis.")

with tab2:
    st.header("📊 Proposed Detection Rules")
    
    if 'cti_analysis_result' not in st.session_state:
        st.info("👆 Go to the 'Input CTI Content' tab to analyze CTI and get proposed rules.")
    else:
        result = st.session_state['cti_analysis_result']
        
        if 'error' in result:
            st.error(f"❌ Error: {result.get('error', 'Unknown error')}")
            st.info(result.get('summary', ''))
        elif result.get("not_applicable"):
            st.warning(
                result.get(
                    "summary",
                    "This content is not exploitable as cyber threat intelligence. "
                    "No detection rules were proposed.",
                )
            )
        elif 'rules' in result and result['rules']:
            # Display summary
            if 'summary' in result:
                st.info(f"📋 **Analysis Summary:** {result['summary']}")
            
            st.divider()
            
            # Display each proposed rule
            for idx, rule_data in enumerate(result['rules'], 1):
                # Check if this rule was just added or rejected
                rule_added_key = f'rule_added_{idx}'
                rule_rejected_key = f'rule_rejected_{idx}'
                
                # Show success message if rule was added
                if rule_added_key in st.session_state:
                    added_info = st.session_state[rule_added_key]
                    st.success(f"✅ **Rule '{added_info['rule_name']}' successfully added to catalogue!** (ID: {added_info['rule_id']})")
                    # Clear the message after showing
                    del st.session_state[rule_added_key]
                
                # Show rejection message if rule was rejected
                if rule_rejected_key in st.session_state:
                    rejected_info = st.session_state[rule_rejected_key]
                    st.info(f"❌ **Rule #{idx} '{rejected_info['rule_name']}' was rejected.** You can modify it above and add it manually if needed.")
                    # Clear the message after showing
                    del st.session_state[rule_rejected_key]
                
                with st.expander(f"🔍 Proposed Rule #{idx}: {rule_data.get('rule_name', 'Unnamed Rule')}", expanded=True):
                    # Rule details
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("**Rule Name:**")
                        rule_name = st.text_input(
                            "Name",
                            value=rule_data.get('rule_name', ''),
                            key=f"rule_name_{idx}",
                            label_visibility="collapsed"
                        )
                        
                        st.markdown("**Platform:**")
                        platform = st.text_input(
                            "Platform",
                            value=rule_data.get('platform', ''),
                            key=f"platform_{idx}",
                            label_visibility="collapsed"
                        )
                        
                        st.markdown("**Rule Format:**")
                        rule_format = st.selectbox(
                            "Format",
                            ["sigma", "splunk", "kql", "yara", "snort", "other"],
                            index=["sigma", "splunk", "kql", "yara", "snort", "other"].index(rule_data.get('rule_format', 'sigma')) if rule_data.get('rule_format', 'sigma') in ["sigma", "splunk", "kql", "yara", "snort", "other"] else 0,
                            key=f"format_{idx}",
                            label_visibility="collapsed"
                        )
                    
                    with col2:
                        st.markdown("**MITRE Technique ID:**")
                        mitre_technique_id = st.text_input(
                            "MITRE Technique",
                            value=rule_data.get('mitre_technique_id', '') or '',
                            placeholder="e.g., T1059.001",
                            key=f"mitre_{idx}",
                            label_visibility="collapsed"
                        )
                        
                        st.markdown("**Tags:**")
                        tags_input = st.text_input(
                            "Tags",
                            value=", ".join(rule_data.get('tags', [])) if rule_data.get('tags') else '',
                            placeholder="comma-separated tags",
                            key=f"tags_{idx}",
                            label_visibility="collapsed"
                        )
                        tags_list = [t.strip() for t in tags_input.split(",")] if tags_input else []
                        
                        # Confidence badge
                        confidence = rule_data.get('confidence', 'medium')
                        if confidence == 'high':
                            st.success(f"✅ Confidence: {confidence.upper()}")
                        elif confidence == 'medium':
                            st.warning(f"⚠️ Confidence: {confidence.upper()}")
                        else:
                            st.info(f"ℹ️ Confidence: {confidence.upper()}")
                    
                    st.markdown("**Detection Query/Logic:**")
                    rule_text = st.text_area(
                        "Query",
                        value=rule_data.get('rule_text', ''),
                        height=150,
                        key=f"rule_text_{idx}",
                        label_visibility="collapsed"
                    )
                    
                    # Reasoning
                    if rule_data.get('reasoning'):
                        st.markdown("**💡 AI Reasoning:**")
                        st.info(rule_data.get('reasoning', ''))
                    
                    st.divider()
                    
                    # Action buttons
                    col_accept, col_reject, col_spacer = st.columns([2, 2, 6])
                    
                    # RBAC check - require "create" permission to add rules
                    can_create = has_permission("create")
                    if not can_create:
                        st.warning("🔒 You do not have permission to create rules (requires **create** permission).")
                    
                    with col_accept:
                        if st.button(f"✅ Add to Catalogue", key=f"accept_{idx}", type="primary", width='stretch', disabled=not can_create):
                            if not rule_name or not rule_text or not platform:
                                st.error("Rule name, query, and platform are required!")
                            else:
                                try:
                                    db = SessionLocal()
                                    
                                    # Compute hash
                                    rule_hash = compute_rule_hash(rule_text, platform, rule_format)
                                    
                                    # Check for duplicates
                                    existing_rule = RuleRepository.get_by_hash(db, rule_hash)
                                    if existing_rule:
                                        st.warning(f"⚠️ A similar rule already exists: '{existing_rule.rule_name}' (ID: {existing_rule.id})")
                                        db.close()
                                    else:
                                        # Get or create default use case
                                        default_ucs = UseCaseRepository.list_all(db, limit=1)
                                        use_case_id = default_ucs[0].id if default_ucs else None
                                        
                                        if not use_case_id:
                                            default_uc = UseCaseRepository.create(
                                                db,
                                                name="Default Rules Collection",
                                                description="Default collection for standalone rules",
                                                status="approved"
                                            )
                                            use_case_id = default_uc.id
                                        
                                        # Create rule
                                        new_rule = RuleRepository.create(
                                            db,
                                            use_case_id=use_case_id,
                                            platform=platform,
                                            rule_name=rule_name,
                                            rule_text=rule_text,
                                            rule_format=rule_format,
                                            rule_hash=rule_hash,
                                            tags=tags_list if tags_list else None,
                                            mitre_technique_id=mitre_technique_id if mitre_technique_id else None
                                        )
                                        
                                        # Log to audit trail
                                        current_user = get_current_user() or "system"
                                        RuleChangeLogRepository.log_create(
                                            db, new_rule, current_user,
                                            reason="Created from CTI Detection page"
                                        )
                                        
                                        # Get the rule ID before closing the session
                                        rule_id = new_rule.id
                                        
                                        # Commit any pending changes and close
                                        db.commit()
                                        db.close()
                                        
                                        # Store success message in session state to show after rerun
                                        st.session_state[f'rule_added_{idx}'] = {
                                            'rule_name': rule_name,
                                            'rule_id': rule_id,
                                            'timestamp': datetime.now()
                                        }
                                        
                                        st.balloons()
                                        st.rerun()
                                except Exception as e:
                                    st.error(f"❌ **Error adding rule:** {e}")
                                    if 'db' in locals():
                                        db.close()
                    
                    with col_reject:
                        if st.button(f"❌ Reject", key=f"reject_{idx}", width='stretch'):
                            # Store rejection in session state to show after rerun
                            st.session_state[f'rule_rejected_{idx}'] = {
                                'rule_name': rule_name,
                                'timestamp': datetime.now()
                            }
                            st.rerun()
            
            # Clear analysis button
            st.divider()
            if st.button("🔄 Clear Analysis and Start Over", width='stretch'):
                if 'cti_analysis_result' in st.session_state:
                    del st.session_state['cti_analysis_result']
                if 'cti_source_type' in st.session_state:
                    del st.session_state['cti_source_type']
                if 'cti_content' in st.session_state:
                    del st.session_state['cti_content']
                st.rerun()
        else:
            st.warning(
                "⚠️ No rules were proposed. The content may not contain actionable detection opportunities, "
                "or the model could not derive behavioral rules from it."
            )
            if result.get("summary"):
                st.info(f"📋 **Analysis summary:** {result['summary']}")

# Add admin link at bottom of sidebar
st.sidebar.divider()
if st.sidebar.button("⚙️ Admin", width='stretch'):
    st.switch_page("pages/8_Admin.py")

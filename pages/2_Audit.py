"""Audit page - Unified interface for adding rules and running analysis."""
import streamlit as st
import pandas as pd
from io import BytesIO
from datetime import datetime
from fpdf import FPDF
from fpdf.fonts import FontFace
from fpdf.enums import TableCellFillMode, XPos, YPos
from src.data_ingestion import load_data, standardize_columns
from src.mitre_engine import MitreEngine
from src.ai_engine import AIEngine
from services.auth import get_current_user, has_permission, require_sign_in
from db.repo import RuleChangeLogRepository
from db.session import SessionLocal
from db.repo import UseCaseRepository, RuleRepository
from db.models import RuleImplementation
from utils.hashing import compute_rule_hash
from utils.session_persistence import restore_session_state, persist_session_state
from utils.app_navigation import render_app_sidebar
from utils.ai_config import (
    get_ai_config,
    get_api_key_for_provider,
    get_llama_config,
    get_openai_model_name,
    get_gemini_model_name,
)

# Restore session state
restore_session_state()

require_sign_in("the Audit page")
username = get_current_user()

# Import PDF generation function
def generate_pdf_report(results, mitre_info):
    """Generate a PDF report from the analysis results."""
    from fpdf import FPDF
    from fpdf.fonts import FontFace
    from fpdf.enums import TableCellFillMode, XPos, YPos
    from datetime import datetime
    from io import BytesIO
    import unicodedata
    
    def clean_text_for_pdf(text):
        """Replace Unicode characters that aren't supported by Helvetica with ASCII equivalents."""
        if not text:
            return ""
        
        # Replace common Unicode characters with ASCII equivalents
        replacements = {
            '–': '-',  # En dash
            '—': '-',  # Em dash
            '…': '...',  # Ellipsis
            '"': '"',  # Left double quotation mark
            '"': '"',  # Right double quotation mark
            ''': "'",  # Left single quotation mark
            ''': "'",  # Right single quotation mark
            '©': '(c)',  # Copyright
            '®': '(R)',  # Registered
            '™': '(TM)',  # Trademark
            '°': 'deg',  # Degree
            '€': 'EUR',  # Euro
            '£': 'GBP',  # Pound
            '¥': 'JPY',  # Yen
            '→': '->',  # Right arrow
            '←': '<-',  # Left arrow
            '×': 'x',  # Multiplication
            '÷': '/',  # Division
        }
        
        # Apply replacements
        cleaned = str(text)
        for unicode_char, ascii_char in replacements.items():
            cleaned = cleaned.replace(unicode_char, ascii_char)
        
        # Remove or replace any remaining non-ASCII characters
        try:
            # Try to encode as latin-1 (which only supports 0-255)
            cleaned.encode('latin-1')
            return cleaned
        except UnicodeEncodeError:
            # If there are still problematic characters, replace them
            cleaned_ascii = ""
            for char in cleaned:
                try:
                    char.encode('latin-1')
                    cleaned_ascii += char
                except UnicodeEncodeError:
                    # Replace with '?' or similar character
                    cleaned_ascii += '?'
            return cleaned_ascii
    
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    
    # Title page with better styling
    pdf.add_page()
    
    # Header with colored background
    pdf.set_fill_color(41, 128, 185)  # Blue color
    pdf.rect(0, 0, 210, 50, style='F')
    
    pdf.set_text_color(255, 255, 255)  # White text
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_y(15)
    pdf.cell(0, 10, "MITRE ATT&CK", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 8, "Coverage & Gap Analysis Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    
    # Reset text color
    pdf.set_text_color(0, 0, 0)
    pdf.set_y(60)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 6, f"Generated on {datetime.now().strftime('%B %d, %Y at %H:%M')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.ln(15)
    
    # Executive Summary with colored table
    satisfied = sum(1 for r in results if r.get("AI_Analysis_Status") == "Satisfied")
    gaps = sum(1 for r in results if r.get("AI_Analysis_Status") == "Gap Found")
    platform_gaps = sum(1 for r in results if len(r.get("Missing_Platforms", [])) > 0)
    total_rules = len(results)
    
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_fill_color(245, 245, 245)
    pdf.cell(0, 10, "Executive Summary", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(5)
    
    # Summary table with colors
    with pdf.table(width=190, headings_style=FontFace(emphasis="BOLD", color=(255, 255, 255)), 
                   col_widths=(120, 70), cell_fill_color=(41, 128, 185), 
                   cell_fill_mode=TableCellFillMode.ROWS, first_row_as_headings=True) as table:
        row = table.row()
        row.cell("Metric")
        row.cell("Count")
        
        row = table.row()
        row.cell("Total Rules Analyzed")
        row.cell(str(total_rules))
        
        row = table.row()
        row.cell("[OK] Rules Satisfied")
        row.cell(str(satisfied))
        
        row = table.row()
        row.cell("[GAP] Rules with Gaps")
        row.cell(str(gaps))
        
        row = table.row()
        row.cell("[WARN] Rules with Platform Gaps")
        row.cell(str(platform_gaps))
    
    pdf.ln(10)
    
    # Detailed results for each rule
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 10, "Detailed Analysis", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(8)
    
    for idx, result in enumerate(results):
        if pdf.get_y() > 250:
            pdf.add_page()
            pdf.ln(5)
        
        rule_name = clean_text_for_pdf(result.get("Rule_Name", "Unknown"))
        tech_id = result.get("Technique_ID", "")
        tech_name = clean_text_for_pdf(result.get("Technique_Name", ""))
        ai_status = result.get("AI_Analysis_Status", "N/A")
        missing_platforms = result.get("Missing_Platforms", [])
        gap_analysis = result.get("AI_Gap_Analysis", "N/A")
        improvement = result.get("AI_Improvement", "N/A")
        pseudo_code = result.get("AI_Pseudo_Code", "N/A")
        
        # Determine status color and text
        if ai_status == "Satisfied" and not missing_platforms:
            status_color = (46, 204, 113)  # Green
            status_text = "[OK] SATISFIED"
        elif ai_status == "Gap Found":
            status_color = (231, 76, 60)  # Red
            status_text = "[GAP] GAP FOUND"
        else:
            status_color = (241, 196, 15)  # Yellow/Orange
            status_text = "[WARN] NEEDS ATTENTION"
        
        # Rule header with colored background
        pdf.set_fill_color(*status_color)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 9, f"Rule {idx + 1}: {rule_name}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
        
        # Reset colors
        pdf.set_text_color(0, 0, 0)
        pdf.set_fill_color(250, 250, 250)
        
        # Technique info box
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 6, f"MITRE Technique: {tech_id}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5, f"Technique Name: {tech_name}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(3)
        
        # Status badge
        pdf.set_fill_color(*status_color)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(60, 6, status_text, new_x=XPos.RIGHT, new_y=YPos.TOP, fill=True)
        pdf.set_text_color(0, 0, 0)
        pdf.set_fill_color(255, 255, 255)
        
        # Platform info
        if missing_platforms:
            pdf.set_text_color(231, 76, 60)  # Red for missing platforms
            pdf.set_font("Helvetica", "B", 9)
            missing_platforms_text = clean_text_for_pdf(f"Missing Platforms: {', '.join(missing_platforms)}")
            pdf.multi_cell(0, 6, missing_platforms_text)
            pdf.set_text_color(0, 0, 0)
        else:
            pdf.set_text_color(46, 204, 113)  # Green for all platforms covered
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(0, 6, "[OK] All MITRE platforms covered", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_text_color(0, 0, 0)
        
        pdf.ln(5)
        
        # AI Analysis section
        if ai_status not in ["Disabled", "Skipped", "Skipped (Empty Query)", "N/A"]:
            # Gap Analysis
            pdf.set_fill_color(240, 240, 240)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 7, "Gap Analysis", new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
            pdf.set_fill_color(255, 255, 255)
            pdf.set_font("Helvetica", "", 9)
            pdf.ln(2)
            
            if gap_analysis and gap_analysis != "N/A":
                clean_text = clean_text_for_pdf(gap_analysis)
                pdf.multi_cell(0, 5, clean_text)
            else:
                pdf.cell(0, 5, "No gap analysis available.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            
            pdf.ln(4)
            
            # Improvement Suggestions
            pdf.set_fill_color(240, 240, 240)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 7, "Improvement Suggestions", new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
            pdf.set_fill_color(255, 255, 255)
            pdf.set_font("Helvetica", "", 9)
            pdf.ln(2)
            
            if improvement and improvement != "N/A":
                clean_text = clean_text_for_pdf(improvement)
                pdf.multi_cell(0, 5, clean_text)
            else:
                pdf.cell(0, 5, "No improvement suggestions available.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            
            pdf.ln(4)
            
            # Recommended Detection Query
            pdf.set_fill_color(240, 240, 240)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 7, "Recommended Detection Query", new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
            pdf.set_fill_color(255, 255, 255)
            pdf.set_font("Helvetica", "", 9)
            pdf.ln(2)
            
            if pseudo_code and pseudo_code != "N/A":
                clean_text = clean_text_for_pdf(pseudo_code)
                pdf.multi_cell(0, 5, clean_text)
            else:
                pdf.cell(0, 5, "No recommended query available.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            
            pdf.ln(5)
        
        # MITRE Details section
        if tech_id in mitre_info:
            info = mitre_info[tech_id]
            if info.get("detection_strategies"):
                pdf.set_fill_color(240, 240, 240)
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(0, 7, "Detection Strategies", new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
                pdf.set_fill_color(255, 255, 255)
                pdf.set_font("Helvetica", "", 8)
                pdf.ln(2)
                for ds in info["detection_strategies"]:
                    det_id = ds.get('det_id', '')
                    name = ds.get('name', '')
                    pdf.set_font("Helvetica", "B", 8)
                    pdf.cell(20, 4, f"{det_id}:", new_x=XPos.RIGHT, new_y=YPos.TOP)
                    pdf.set_font("Helvetica", "", 8)
                    clean_name = clean_text_for_pdf(name)
                    pdf.multi_cell(0, 4, clean_name)
                pdf.ln(3)
        
        # Separator line
        pdf.set_draw_color(200, 200, 200)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(8)
    
    # Output to bytes
    pdf_buffer = BytesIO()
    pdf.output(pdf_buffer)
    pdf_buffer.seek(0)
    return pdf_buffer.getvalue()

st.set_page_config(
    page_title="MITRE Coverage & Gap Analyzer",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ MITRE Coverage & Gap Analyzer")
st.markdown("""
This tool ingests SOC detection rules and performs gap analysis against the MITRE ATT&CK framework.
It provides **Offline** platform coverage checks and **Online** AI-based logic analysis.
""")

render_app_sidebar(username)

# Sidebar
st.sidebar.header("Configuration")

# Load saved AI configuration
saved_config = get_ai_config()
saved_provider = saved_config.get("provider")

# AI Provider Selection
ai_provider = st.sidebar.selectbox(
    "AI Provider (Optional for AI Analysis)",
    ["None", "OpenAI", "Gemini", "Llama (Custom LLM)"],
    index=0 if not saved_provider else (1 if saved_provider == "OpenAI" else (2 if saved_provider == "Gemini" else 3)),
    help="Configure in the 'AI Configuration' page to save your API keys"
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
        openai_api_key = st.sidebar.text_input("OpenAI API Key", type="password", key="openai_key", help="Or configure in the 'AI Configuration' page")
        openai_model_name = st.sidebar.text_input(
            "OpenAI model",
            value="gpt-4o",
            key="audit_openai_model_manual",
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
        gemini_api_key = st.sidebar.text_input("Gemini API Key", type="password", key="gemini_key", help="Or configure in the 'AI Configuration' page")
        gemini_model_name = st.sidebar.text_input(
            "Gemini model",
            value="gemini-1.5-flash",
            key="audit_gemini_model_manual",
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
            key="llama_base_url",
            help="OpenAI-compatible API endpoint (Ollama, vLLM, text-generation-inference, LM Studio)"
        )
        llama_model_name = st.sidebar.text_input(
            "Model Name",
            value="llama3",
            placeholder="llama3, mistral, codellama, etc.",
            key="llama_model_name",
            help="Model name as configured in your LLM server"
        )
        llama_api_key = st.sidebar.text_input(
            "API Key (optional)",
            type="password",
            key="llama_api_key",
            help="Leave empty if your LLM server doesn't require authentication"
        )

# Store in session state for use in other pages
# Note: llama_base_url and llama_model_name are already stored via widget keys
st.session_state["ai_provider"] = ai_provider
st.session_state["ai_api_key"] = openai_api_key or gemini_api_key or llama_api_key

# Initialize MITRE Engine (cached to avoid reloading on every rerun)
# The cache ensures the engine is only created once and reused
@st.cache_resource
def get_mitre_engine(force_refresh=False, _api_version: int = 2):
    return MitreEngine(force_refresh=force_refresh)

# Load MITRE engine silently (cached, won't reload unless needed)
# The cache ensures the file is only downloaded once
try:
    mitre_engine = get_mitre_engine(force_refresh=False)
    # Only show success message once, not on every rerun
    if 'mitre_loaded' not in st.session_state:
        st.sidebar.success("✅ MITRE Data Ready")
        st.session_state['mitre_loaded'] = True
except Exception as e:
    st.error(f"Failed to load MITRE Data: {e}")
    st.stop()

# Clear cache button (only downloads if file doesn't exist or is corrupted)
if st.sidebar.button("🔄 Reload MITRE Data"):
    # Clear the cache to force reload
    st.cache_resource.clear()
    # Force refresh the MITRE data file
    try:
        # Get a fresh engine instance with force_refresh
        temp_engine = get_mitre_engine(force_refresh=True)
        st.sidebar.success("✅ MITRE Data refreshed successfully!")
    except Exception as e:
        st.sidebar.error(f"❌ Error refreshing MITRE data: {e}")
    st.rerun()

# Initialize session state for manual rules and uploaded data
if 'manual_rules' not in st.session_state:
    st.session_state.manual_rules = []
if 'uploaded_df' not in st.session_state:
    st.session_state.uploaded_df = None
if 'last_uploaded_file_name' not in st.session_state:
    st.session_state.last_uploaded_file_name = None

# Helper function to check if a rule is a duplicate based on Rule_Name, Query, and Technique_ID
def is_duplicate_rule(new_rule, existing_rules_list):
    """
    Check if a rule is a duplicate based on Rule_Name, Query, and Technique_ID.
    Returns (is_duplicate, index_of_existing) if duplicate found.
    """
    new_name = str(new_rule.get('Rule_Name', '')).strip().lower()
    new_query = str(new_rule.get('Query', '')).strip().lower()
    new_tech_id = str(new_rule.get('Technique_ID', '')).strip().lower()
    
    for idx, existing_rule in enumerate(existing_rules_list):
        existing_name = str(existing_rule.get('Rule_Name', '')).strip().lower()
        existing_query = str(existing_rule.get('Query', '')).strip().lower()
        existing_tech_id = str(existing_rule.get('Technique_ID', '')).strip().lower()
        
        # Check if all three match (ignoring case and whitespace)
        if (new_name == existing_name and 
            new_query == existing_query and 
            new_tech_id == existing_tech_id and 
            new_tech_id != ''):  # Only match if Technique_ID is not empty
            return True, idx
    
    return False, None

# Helper function to add or replace rule in manual_rules
def add_or_replace_rule(new_rule, rules_list):
    """
    Add a rule to the list, or replace if duplicate found.
    Returns (was_replaced, message)
    """
    is_dup, existing_idx = is_duplicate_rule(new_rule, rules_list)
    
    if is_dup:
        # Replace existing rule
        rules_list[existing_idx] = new_rule
        return True, f"Rule '{new_rule.get('Rule_Name', 'Unknown')}' replaced (duplicate found)"
    else:
        # Add new rule
        rules_list.append(new_rule)
        return False, f"Rule '{new_rule.get('Rule_Name', 'Unknown')}' added"

# Show notification if rules were added from Rules page
if st.session_state.get("audit_rule_added") or st.session_state.get("audit_rules_added"):
    st.success(f"✅ {len(st.session_state.manual_rules)} rule(s) added to audit!")
    st.session_state["audit_rule_added"] = False
    st.session_state["audit_rules_added"] = False

# ========== SECTION 1: ADD RULES (Unified Form) ==========
st.subheader("📥 Add Detection Rules to Audit")

# Unified input method selector
input_method = st.radio(
    "Choose how to add rules:",
    ["📁 Upload CSV/Excel File", "✏️ Add Rule Manually", "📋 Load from Detection Rules Catalogue"],
    horizontal=True,
    help="Select the method to add detection rules for audit"
)

st.divider()

# Method 1: File Upload
if input_method == "📁 Upload CSV/Excel File":
    st.markdown("### 📁 Upload CSV/Excel File")
    
    uploaded_file = st.file_uploader(
        "Choose a file to upload", 
        type=['csv', 'xlsx', 'xls'], 
        key="file_uploader",
        help="Upload a CSV or Excel file with detection rules"
    )
    
    if uploaded_file is not None:
        # Check if this is a new file upload (different from the last one)
        if st.session_state.last_uploaded_file_name != uploaded_file.name:
            # This is a new file, process it
            with st.spinner("Loading file..."):
                raw_df = load_data(uploaded_file)
                
                if raw_df is not None:
                    new_df = standardize_columns(raw_df)
                    
                    # Check for duplicates and replace them
                    # First, convert uploaded_df to list format for comparison
                    existing_rules = []
                    if st.session_state.uploaded_df is not None:
                        for idx, row in st.session_state.uploaded_df.iterrows():
                            existing_rules.append({
                                'Rule_Name': row.get('Rule_Name', ''),
                                'Query': row.get('Query', ''),
                                'Technique_ID': row.get('Technique_ID', ''),
                                'Platform': row.get('Platform', ''),
                                'Tactic': row.get('Tactic', ''),
                                'Format': row.get('Format', 'unknown')
                            })
                    
                    # Also check against manual_rules
                    if st.session_state.manual_rules:
                        existing_rules.extend(st.session_state.manual_rules)
                    
                    # Process new rules: replace duplicates, add new ones
                    replaced_count = 0
                    added_count = 0
                    final_rules = []
                    
                    for idx, row in new_df.iterrows():
                        new_rule = {
                            'Rule_Name': row.get('Rule_Name', ''),
                            'Query': row.get('Query', ''),
                            'Technique_ID': row.get('Technique_ID', ''),
                            'Platform': row.get('Platform', ''),
                            'Tactic': row.get('Tactic', ''),
                            'Format': row.get('Format', 'unknown')
                        }
                        
                        is_dup, existing_idx = is_duplicate_rule(new_rule, existing_rules)
                        if is_dup:
                            # Replace in existing_rules list
                            existing_rules[existing_idx] = new_rule
                            replaced_count += 1
                        else:
                            existing_rules.append(new_rule)
                            added_count += 1
                        
                        final_rules.append(new_rule)
                    
                    # Update uploaded_df with final rules
                    st.session_state.uploaded_df = pd.DataFrame(final_rules)
                    st.session_state.last_uploaded_file_name = uploaded_file.name
                    persist_session_state()
                    
                    msg_parts = []
                    if added_count > 0:
                        msg_parts.append(f"{added_count} new rule(s) added")
                    if replaced_count > 0:
                        msg_parts.append(f"{replaced_count} duplicate rule(s) replaced")
                    st.success(f"✅ Successfully processed {len(new_df)} rules from {uploaded_file.name}: {', '.join(msg_parts)}")
                else:
                    st.error("Failed to load the file. Please check the file format.")
        else:
            # Same file, just show the already loaded data
            if st.session_state.uploaded_df is not None:
                st.info(f"📁 File '{uploaded_file.name}' already loaded ({len(st.session_state.uploaded_df)} rules)")

# Method 2: Manual Rule Entry
elif input_method == "✏️ Add Rule Manually":
    st.markdown("### ✏️ Add Detection Rule Manually")
    
    with st.form("add_rule_form", clear_on_submit=True):
        col1, col2 = st.columns(2)
        
        with col1:
            rule_name = st.text_input("Rule Name *", placeholder="e.g., Suspicious PowerShell Webhook")
            technique_id = st.text_input("MITRE Technique ID *", placeholder="e.g., T1567.004")
            tactic = st.text_input("Tactic", placeholder="e.g., Exfiltration")
        
        with col2:
            from utils.platform_mapping import MITRE_PLATFORMS
            platforms = st.multiselect(
                "Platform(s) *",
                options=MITRE_PLATFORMS + ["Other (specify)"],
                help="Select one or multiple platforms for this detection rule"
            )
            
            # Handle "Other (specify)" option
            other_platform = None
            if "Other (specify)" in platforms:
                platforms.remove("Other (specify)")
                other_platform = st.text_input("Specify custom platform", placeholder="e.g., Custom Platform")
                if other_platform:
                    platforms.append(other_platform)
            
            # Join platforms with comma for storage
            platform = ", ".join(platforms) if platforms else ""
            
            if not platform:
                st.warning("⚠️ Please select at least one platform")
            
            query = st.text_area("Detection Query/Logic *", placeholder='e.g., ProcessName == "powershell.exe" AND CommandLine contains "webhook"', height=100)
        
        submitted = st.form_submit_button("➕ Add Rule", width='stretch')
        
        if submitted:
            if rule_name and technique_id and platform and query:
                new_rule = {
                    'Rule_Name': rule_name,
                    'Technique_ID': technique_id,
                    'Tactic': tactic if tactic else '',
                    'Platform': platform,
                    'Query': query,
                    'Format': 'unknown'  # Default format for manually added rules
                }
                
                # Check for duplicates in both manual_rules and uploaded_df
                existing_rules = list(st.session_state.manual_rules)
                if st.session_state.uploaded_df is not None:
                    for idx, row in st.session_state.uploaded_df.iterrows():
                        existing_rules.append({
                            'Rule_Name': row.get('Rule_Name', ''),
                            'Query': row.get('Query', ''),
                            'Technique_ID': row.get('Technique_ID', ''),
                            'Platform': row.get('Platform', ''),
                            'Tactic': row.get('Tactic', ''),
                            'Format': row.get('Format', 'unknown')
                        })
                
                was_replaced, message = add_or_replace_rule(new_rule, st.session_state.manual_rules)
                persist_session_state()
                
                if was_replaced:
                    st.success(f"✅ {message}")
                else:
                    st.success(f"✅ {message}")
                st.rerun()
            else:
                st.error("Please fill in all required fields (marked with *)")

# Method 3: Load from Rules Catalogue
elif input_method == "📋 Load from Detection Rules Catalogue":
    st.markdown("### 📋 Load Rules from Detection Rules Catalogue")
    
    db_rules = SessionLocal()
    try:
        all_rules_db = db_rules.query(RuleImplementation).order_by(RuleImplementation.created_at.desc()).all()
        
        if all_rules_db:
            # Create options for multiselect
            rule_options = {f"{rule.id}: {rule.rule_name} ({rule.platform})": rule for rule in all_rules_db}
            rule_labels = list(rule_options.keys())
            
            if rule_labels:
                # Use a counter to force multiselect reset when needed
                if 'rules_catalogue_reset_counter' not in st.session_state:
                    st.session_state.rules_catalogue_reset_counter = 0
                
                # Create unique key that changes when we want to reset
                multiselect_key = f"rules_catalogue_multiselect_{st.session_state.rules_catalogue_reset_counter}"
                
                selected_rules_labels = st.multiselect(
                    "Select Rules (you can select multiple)",
                    options=rule_labels,
                    help="Select one or more rules to load into the audit",
                    key=multiselect_key,
                    default=[]
                )
                
                if selected_rules_labels:
                    selected_rules_list = [rule_options[label] for label in selected_rules_labels]
                    
                    col1, col2 = st.columns([1, 1])
                    with col1:
                        load_clicked = st.button("📥 Load Selected Rules", type="primary", width='stretch', key="load_rules_btn")
                    with col2:
                        clear_selection = st.button("🗑️ Clear Selection", width='stretch', key="clear_selection_btn")
                    
                    if load_clicked:
                        # Convert rules to the format expected by audit
                        loaded_rules = []
                        replaced_count = 0
                        added_count = 0
                        
                        # Get existing rules for duplicate checking
                        existing_rules = list(st.session_state.manual_rules)
                        if st.session_state.uploaded_df is not None:
                            for idx, row in st.session_state.uploaded_df.iterrows():
                                existing_rules.append({
                                    'Rule_Name': row.get('Rule_Name', ''),
                                    'Query': row.get('Query', ''),
                                    'Technique_ID': row.get('Technique_ID', ''),
                                    'Platform': row.get('Platform', ''),
                                    'Tactic': row.get('Tactic', ''),
                                    'Format': row.get('Format', 'unknown')
                                })
                        
                        # Process each selected rule
                        for rule in selected_rules_list:
                            new_rule = {
                                'Rule_Name': rule.rule_name,
                                'Query': rule.rule_text,
                                'Platform': rule.platform,
                                'Technique_ID': str(rule.mitre_technique_id) if rule.mitre_technique_id else '',
                                'Tactic': '',
                                'Format': rule.rule_format or 'unknown',
                                '_rule_id': rule.id,  # Store the database ID for direct lookup
                                '_rule_hash': compute_rule_hash(rule.rule_text, rule.platform, rule.rule_format or '')  # Store the hash for lookup
                            }
                            
                            # Check if duplicate in existing rules
                            is_dup, existing_idx = is_duplicate_rule(new_rule, existing_rules)
                            
                            if is_dup:
                                # Check if it's in manual_rules or uploaded_df
                                found_in_manual = False
                                for idx, manual_rule in enumerate(st.session_state.manual_rules):
                                    if (str(manual_rule.get('Rule_Name', '')).strip().lower() == str(new_rule['Rule_Name']).strip().lower() and
                                        str(manual_rule.get('Query', '')).strip().lower() == str(new_rule['Query']).strip().lower() and
                                        str(manual_rule.get('Technique_ID', '')).strip().lower() == str(new_rule['Technique_ID']).strip().lower() and
                                        str(new_rule['Technique_ID']).strip().lower() != ''):
                                        # Replace in manual_rules
                                        st.session_state.manual_rules[idx] = new_rule
                                        found_in_manual = True
                                        replaced_count += 1
                                        break
                                
                                if not found_in_manual and st.session_state.uploaded_df is not None:
                                    # Try to replace in uploaded_df
                                    for idx, row in st.session_state.uploaded_df.iterrows():
                                        if (str(row.get('Rule_Name', '')).strip().lower() == str(new_rule['Rule_Name']).strip().lower() and
                                            str(row.get('Query', '')).strip().lower() == str(new_rule['Query']).strip().lower() and
                                            str(row.get('Technique_ID', '')).strip().lower() == str(new_rule['Technique_ID']).strip().lower() and
                                            str(new_rule['Technique_ID']).strip().lower() != ''):
                                            # Replace in uploaded_df
                                            for col in new_rule:
                                                if col not in ['_rule_id', '_rule_hash']:
                                                    st.session_state.uploaded_df.at[idx, col] = new_rule[col]
                                            replaced_count += 1
                                            break
                            else:
                                # Add new rule
                                st.session_state.manual_rules.append(new_rule)
                                existing_rules.append(new_rule)
                                added_count += 1
                        
                        if added_count > 0 or replaced_count > 0:
                            persist_session_state()
                            
                            msg_parts = []
                            if added_count > 0:
                                msg_parts.append(f"{added_count} new rule(s) added")
                            if replaced_count > 0:
                                msg_parts.append(f"{replaced_count} duplicate rule(s) replaced")
                            st.success(f"✅ {' and '.join(msg_parts)}.")
                            
                            # Reset multiselect by incrementing counter
                            st.session_state.rules_catalogue_reset_counter += 1
                            st.rerun()
                        else:
                            st.info("No rules to load.")
                    
                    if clear_selection:
                        # Reset multiselect by incrementing counter
                        st.session_state.rules_catalogue_reset_counter += 1
                        st.rerun()
        else:
            st.info("No rules found. Create rules first in the 'Rules' page.")
    finally:
        db_rules.close()

# ========== SECTION 2: UNIFIED RULES LIST ==========
st.divider()
st.subheader("📋 Rules to Analyze")

# Combine uploaded and manual rules into a single list
all_rules_list = []

# Add uploaded rules
if st.session_state.uploaded_df is not None:
    for idx, row in st.session_state.uploaded_df.iterrows():
        rule_dict = {
            'Rule_Name': row.get('Rule_Name', ''),
            'Query': row.get('Query', ''),
            'Platform': row.get('Platform', ''),
            'Technique_ID': row.get('Technique_ID', ''),
            'Tactic': row.get('Tactic', ''),
            'Format': row.get('Format', 'unknown'),
            'Source': '📁 Uploaded'
        }
        all_rules_list.append(rule_dict)

# Add manual rules
if st.session_state.manual_rules:
    for rule in st.session_state.manual_rules:
        rule_dict = {
            'Rule_Name': rule.get('Rule_Name', ''),
            'Query': rule.get('Query', ''),
            'Platform': rule.get('Platform', ''),
            'Technique_ID': rule.get('Technique_ID', ''),
            'Tactic': rule.get('Tactic', ''),
            'Format': rule.get('Format', 'unknown'),
            'Source': '✏️ Manual'
        }
        all_rules_list.append(rule_dict)

# Display unified rules list
if all_rules_list:
    # Summary metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        uploaded_count = sum(1 for r in all_rules_list if r['Source'] == '📁 Uploaded')
        st.metric("📁 Uploaded Rules", uploaded_count)
    with col2:
        manual_count = sum(1 for r in all_rules_list if r['Source'] == '✏️ Manual')
        st.metric("✏️ Manual Rules", manual_count)
    with col3:
        st.metric("📊 Total Rules", len(all_rules_list))
    
    st.divider()
    
    # Initialize selected rules for deletion
    if 'selected_rules_to_delete' not in st.session_state:
        st.session_state.selected_rules_to_delete = []
    
    # Display rules in a table with checkboxes
    rules_df = pd.DataFrame(all_rules_list)
    
    # Ensure Technique_ID is displayed, even if empty
    display_columns = ['Rule_Name', 'Platform', 'Technique_ID', 'Source']
    # Filter to only include columns that exist
    available_columns = [col for col in display_columns if col in rules_df.columns]
    
    # Replace NaN and None values with empty string for display
    if 'Technique_ID' in rules_df.columns:
        rules_df['Technique_ID'] = rules_df['Technique_ID'].fillna('').astype(str).replace('nan', '').replace('None', '')
    
    # Add selection column
    st.markdown("**Select rules to delete:**")
    
    # Create a container for the rules with checkboxes
    selected_indices = []
    for idx, rule in enumerate(all_rules_list):
        rule_key = f"select_rule_{idx}"
        rule_name = rule.get('Rule_Name', f'Rule {idx}')
        rule_platform = rule.get('Platform', '')
        rule_tech = rule.get('Technique_ID', '')
        rule_source = rule.get('Source', '')
        
        # Create a unique identifier for the rule
        rule_identifier = f"{rule_name}|{rule.get('Query', '')}|{rule_platform}"
        
        col_check, col_name, col_platform, col_tech, col_source = st.columns([0.5, 3, 2, 1.5, 1])
        
        with col_check:
            is_selected = st.checkbox(
                f"Select {rule_name}",
                key=rule_key,
                value=rule_identifier in st.session_state.selected_rules_to_delete,
                label_visibility="collapsed"
            )
            if is_selected and rule_identifier not in st.session_state.selected_rules_to_delete:
                st.session_state.selected_rules_to_delete.append(rule_identifier)
            elif not is_selected and rule_identifier in st.session_state.selected_rules_to_delete:
                st.session_state.selected_rules_to_delete.remove(rule_identifier)
        
        with col_name:
            st.write(rule_name)
        with col_platform:
            st.write(rule_platform)
        with col_tech:
            st.write(rule_tech if rule_tech else '-')
        with col_source:
            st.write(rule_source)
    
    # Also show the dataframe for reference
    st.dataframe(
        rules_df[available_columns],
        width='stretch',
        hide_index=True
    )
    
    # Show info if any rules are missing Technique_ID
    if 'Technique_ID' in rules_df.columns:
        empty_techniques = rules_df[(rules_df['Technique_ID'] == '') | (rules_df['Technique_ID'].isna())]
        if len(empty_techniques) > 0:
            missing_rules = empty_techniques['Rule_Name'].tolist()
            st.warning(f"⚠️ {len(empty_techniques)} rule(s) without MITRE Technique ID: {', '.join(missing_rules[:3])}{'...' if len(missing_rules) > 3 else ''}")
            st.info("💡 **Tip:** Edit these rules in the Rules page to add MITRE Technique IDs for better analysis.")
    
    # Action buttons
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        if st.button("🗑️ Delete Selected", width='stretch', disabled=len(st.session_state.selected_rules_to_delete) == 0):
            if st.session_state.selected_rules_to_delete:
                deleted_count = 0
                
                # Create a list of rules to keep
                rules_to_keep = []
                
                # Process manual rules
                for rule in st.session_state.manual_rules:
                    rule_identifier = f"{rule.get('Rule_Name', '')}|{rule.get('Query', '')}|{rule.get('Platform', '')}"
                    if rule_identifier not in st.session_state.selected_rules_to_delete:
                        rules_to_keep.append(rule)
                    else:
                        deleted_count += 1
                
                st.session_state.manual_rules = rules_to_keep
                
                # Process uploaded rules
                if st.session_state.uploaded_df is not None:
                    rows_to_keep = []
                    for idx, row in st.session_state.uploaded_df.iterrows():
                        rule_identifier = f"{row.get('Rule_Name', '')}|{row.get('Query', '')}|{row.get('Platform', '')}"
                        if rule_identifier not in st.session_state.selected_rules_to_delete:
                            rows_to_keep.append(idx)
                        else:
                            deleted_count += 1
                    
                    if rows_to_keep:
                        st.session_state.uploaded_df = st.session_state.uploaded_df.loc[rows_to_keep].reset_index(drop=True)
                    else:
                        st.session_state.uploaded_df = None
                        st.session_state.last_uploaded_file_name = None
                
                # Clear selection
                st.session_state.selected_rules_to_delete = []
                persist_session_state()
                
                if deleted_count > 0:
                    st.success(f"✅ {deleted_count} rule(s) deleted successfully!")
                st.rerun()
    
    with col2:
        if st.button("🗑️ Clear All Rules", width='stretch'):
            st.session_state.uploaded_df = None
            st.session_state.manual_rules = []
            st.session_state.last_uploaded_file_name = None
            st.session_state.selected_rules_to_delete = []
            persist_session_state()
            st.rerun()
    
    with col3:
        if st.button("📥 Export Rules as CSV", width='stretch'):
            csv = rules_df.to_csv(index=False).encode('utf-8')
            st.download_button(
                "Download CSV",
                csv,
                "audit_rules.csv",
                "text/csv",
                key='download-rules-csv',
                width='stretch'
            )
    
    with col4:
        if len(st.session_state.selected_rules_to_delete) > 0:
            st.info(f"📌 {len(st.session_state.selected_rules_to_delete)} rule(s) selected")
    
    st.divider()
    
    # Analysis Configuration
    st.subheader("⚙️ Analysis Configuration")
    col1, col2 = st.columns(2)
    with col1:
        enable_ai = st.checkbox("Enable AI Logic Analysis", value=bool(openai_api_key or gemini_api_key))
    
    # Initialize session state for results
    if 'analysis_results' not in st.session_state:
        st.session_state.analysis_results = None
    if 'analysis_mitre_info' not in st.session_state:
        st.session_state.analysis_mitre_info = None
    
    # Run Analysis Button
    if st.button("🛡️ Run Coverage Analysis", type="primary", width='stretch'):
        
        # Prepare AI Engine if key is provided and enabled
        ai_engine = None
        if enable_ai:
            if ai_provider == "OpenAI":
                if not openai_api_key:
                    st.error("Please provide an OpenAI API Key in the sidebar to use AI Analysis.")
                    st.stop()
                ai_engine = AIEngine(
                    openai_api_key,
                    provider="openai",
                    model_name=openai_model_name,
                    team=st.session_state.get("user_team"),
                )
            elif ai_provider == "Gemini":
                if not gemini_api_key:
                    st.error("Please provide a Gemini API Key in the sidebar to use AI Analysis.")
                    st.stop()
                ai_engine = AIEngine(
                    gemini_api_key,
                    provider="gemini",
                    model_name=gemini_model_name,
                    team=st.session_state.get("user_team"),
                )
            elif ai_provider == "Llama (Custom LLM)":
                if not llama_base_url:
                    st.error("Please provide the LLM API Base URL in the sidebar.")
                    st.stop()
                ai_engine = AIEngine(
                    api_key=llama_api_key or "",
                    provider="llama",
                    base_url=llama_base_url,
                    model_name=llama_model_name or "llama3",
                    team=st.session_state.get("user_team"),
                )
            else:
                st.error("Please select an AI provider in the sidebar.")
                st.stop()
        
        results = []
        mitre_info = {}
        
        # Progress Bar
        progress_bar = st.progress(0)
        total_rules = len(all_rules_list)
        
        for index, rule_dict in enumerate(all_rules_list):
            # Update progress
            progress_bar.progress((index + 1) / total_rules)
            
            tech_id = rule_dict['Technique_ID']
            rule_name = rule_dict['Rule_Name']
            query = rule_dict['Query']
            user_platform = rule_dict['Platform']
            rule_format = rule_dict.get('Format', 'unknown')
            
            # Store original rule_dict for later database update
            rule_dict['_original_index'] = index
            
            # Fetch MITRE Details
            mitre_details = mitre_engine.get_technique_details(tech_id)
            
            result_entry = {
                "Rule_Name": rule_name,
                "Technique_ID": tech_id,
                "Technique_Name": mitre_details.get('name', 'Unknown'),
                "MITRE_Platforms": ", ".join(mitre_details.get('platforms', [])),
                "User_Platform": user_platform,
                "Missing_Platforms": [],
                "AI_Analysis_Status": "Skipped",
                "AI_Gap_Analysis": "N/A",
                "AI_Improvement": "N/A",
                "AI_Pseudo_Code": "N/A"
            }
            
            if mitre_details:
                # Module 2: Offline Analysis (Platform Gaps)
                user_platforms_list = [p.strip() for p in str(user_platform).split(',')] if user_platform else []
                missing = mitre_engine.compare_platforms(tech_id, user_platforms_list)
                
                # Add platform mapping suggestions
                from utils.platform_mapping import suggest_platforms_for_missing
                platform_suggestions = suggest_platforms_for_missing(missing, user_platforms_list)
                
                # Format missing platforms with suggestions
                missing_with_suggestions = []
                for mp in missing:
                    if mp in platform_suggestions:
                        missing_with_suggestions.append(f"{mp} (covered by: {platform_suggestions[mp]})")
                    else:
                        missing_with_suggestions.append(mp)
                
                result_entry["Missing_Platforms"] = missing_with_suggestions
                result_entry["Missing_Platforms_Raw"] = missing  # Keep original for filtering

                # Cache MITRE details for display
                mitre_info[tech_id] = {
                    "name": mitre_details.get("name", ""),
                    "url": mitre_details.get("technique_url", ""),
                    "detection_strategies": mitre_details.get("detection_strategies", []),
                    "analytics": mitre_details.get("analytics", []),
                    "data_sources": mitre_details.get("data_sources", []),
                    "data_components": mitre_details.get("data_components", []),
                    "detection": mitre_details.get("detection", "")
                }
                
                # Module 3: AI Analysis (Online)
                if enable_ai:
                    if ai_engine and query:
                        detection_desc = mitre_details.get('detection', 'No detection guidance available.')
                        
                        with st.spinner(f"Analyzing {rule_name}..."):
                            analysis = ai_engine.analyze_coverage(
                                tech_id,
                                mitre_details.get('name', ''),
                                detection_desc,
                                mitre_details.get('data_components', []),
                                mitre_details.get('analytics', []),
                                query,
                                str(user_platform),
                                mitre_details.get('detection_strategies', []),
                                mitre_details.get('data_sources', []),
                                mitre_details.get('technique_url', ''),
                                missing_platforms=missing,  # Pass missing platforms
                                mitre_platforms=mitre_details.get('platforms', [])  # Pass MITRE required platforms
                            )
                        
                        result_entry["AI_Analysis_Status"] = "Satisfied" if analysis.get("satisfies_requirements") else "Gap Found"
                        result_entry["AI_Gap_Analysis"] = analysis.get("gap_analysis")
                        result_entry["AI_Improvement"] = analysis.get("improvement_suggestion")
                        result_entry["AI_Pseudo_Code"] = analysis.get("pseudo_code_recommendation", "")
                        result_entry["AI_Recommended_Tags"] = analysis.get("recommended_tags", [])
                        result_entry["AI_Platform_Recommendations"] = analysis.get("platform_recommendations", "")
                    elif not query:
                         result_entry["AI_Analysis_Status"] = "Skipped (Empty Query)"
                         result_entry["AI_Gap_Analysis"] = "Query field was empty"
                else:
                    result_entry["AI_Analysis_Status"] = "Disabled"
                    result_entry["AI_Gap_Analysis"] = "AI Analysis Disabled"
                    result_entry["AI_Improvement"] = "N/A"
                    result_entry["AI_Pseudo_Code"] = "N/A"
                    result_entry["AI_Recommended_Tags"] = []
                    result_entry["AI_Platform_Recommendations"] = ""
            else:
                result_entry["Technique_Name"] = "Invalid ID / Not Found"
            
            results.append(result_entry)
        
        # Module 4: Visualization & Reporting
        results_df = pd.DataFrame(results)
        
        # Save results to session state so they persist after download
        st.session_state.analysis_results = results
        st.session_state.analysis_mitre_info = mitre_info
        persist_session_state()
        
        # Update rules in database with audit results and tags
        from db.session import SessionLocal
        from db.repo import RuleRepository
        from utils.hashing import compute_rule_hash
        
        # Check RBAC permission before updating database
        can_update_rules = has_permission("update")
        can_create_rules = has_permission("create")
        
        if not can_update_rules and not can_create_rules:
            st.warning("🔒 Vous n'avez pas la permission de mettre à jour les règles. Les résultats sont affichés mais ne seront pas sauvegardés en base de données.")
        
        # Update rules in database with audit results and tags (only if user has permission)
        db_audit = SessionLocal()
        updated_count = 0
        created_count = 0
        not_found_rules = []
        debug_info = []
        current_audit_user = get_current_user() or "system"
        try:
            for idx, result in enumerate(results):
                # Check if rule needs improvement: Gap Found, has improvement suggestions, or has missing platforms
                has_gap = result.get('AI_Analysis_Status') == 'Gap Found'
                ai_improvement = result.get('AI_Improvement', '')
                has_improvement = ai_improvement and ai_improvement != 'N/A' and str(ai_improvement).strip()
                # Use Missing_Platforms_Raw if available (original list), otherwise use Missing_Platforms
                missing_platforms_raw = result.get('Missing_Platforms_Raw', result.get('Missing_Platforms', []))
                # Handle both list format and raw list format
                if isinstance(missing_platforms_raw, list):
                    has_missing_platforms = len(missing_platforms_raw) > 0
                else:
                    has_missing_platforms = False
                
                # Add tag if any improvement condition is met
                if has_gap or has_improvement or has_missing_platforms:
                    # Get the original rule_dict to find the rule
                    if idx < len(all_rules_list):
                        original_rule = all_rules_list[idx]
                        rule_name = original_rule.get('Rule_Name', '')
                        query = original_rule.get('Query', '')
                        rule_platform = original_rule.get('Platform', '')
                        rule_format = original_rule.get('Format', 'unknown')
                        tech_id = original_rule.get('Technique_ID', '')
                        
                        # Try to find rule by stored ID first (if loaded from catalogue)
                        matching_rule = None
                        rule_id = original_rule.get('_rule_id')
                        rule_hash = None
                        
                        if rule_id:
                            matching_rule = RuleRepository.get_by_id(db_audit, rule_id)
                        
                        if not matching_rule and query:
                            # Compute hash first (we'll need it anyway)
                            stored_hash = original_rule.get('_rule_hash')
                            if stored_hash:
                                rule_hash = stored_hash
                            else:
                                rule_hash = compute_rule_hash(query, rule_platform, rule_format)
                            
                            # Try to find rule by hash
                            if rule_hash:
                                matching_rule = RuleRepository.get_by_hash(db_audit, rule_hash)
                            
                            # If not found by hash, try by name and platform
                            if not matching_rule:
                                from db.models import RuleImplementation
                                matching_rules = db_audit.query(RuleImplementation).filter(
                                    RuleImplementation.rule_name == rule_name,
                                    RuleImplementation.platform == rule_platform
                                ).all()
                                if matching_rules:
                                    matching_rule = matching_rules[0]  # Take first match
                            
                            if matching_rule and can_update_rules:
                                # Store previous state for audit log
                                previous_state = RuleChangeLogRepository._rule_to_dict(matching_rule)
                                
                                # Update tags to include "to_improve" if not already present
                                current_tags = matching_rule.tags if matching_rule.tags else []
                                if not isinstance(current_tags, list):
                                    # Handle case where tags might be stored as string
                                    if isinstance(current_tags, str):
                                        try:
                                            import json
                                            current_tags = json.loads(current_tags)
                                        except:
                                            current_tags = [current_tags] if current_tags else []
                                    else:
                                        current_tags = []
                                
                                tag_added = False
                                if 'to_improve' not in current_tags:
                                    current_tags.append('to_improve')
                                    tag_added = True
                                
                                # Add AI recommended tags
                                ai_recommended_tags = result.get('AI_Recommended_Tags', [])
                                tags_added_count = 0
                                if ai_recommended_tags and isinstance(ai_recommended_tags, list):
                                    for recommended_tag in ai_recommended_tags:
                                        if recommended_tag and recommended_tag not in current_tags:
                                            current_tags.append(recommended_tag)
                                            tags_added_count += 1
                                
                                # Save audit results
                                audit_results = {
                                    'gap_analysis': result.get('AI_Gap_Analysis', ''),
                                    'improvement_suggestion': result.get('AI_Improvement', ''),
                                    'pseudo_code_recommendation': result.get('AI_Pseudo_Code', ''),
                                    'recommended_tags': result.get('AI_Recommended_Tags', []),
                                    'platform_recommendations': result.get('AI_Platform_Recommendations', ''),
                                    'status': result.get('AI_Analysis_Status', ''),
                                    'technique_id': result.get('Technique_ID', ''),
                                    'analyzed_at': datetime.now().isoformat()
                                }
                                
                                # Update rule - ensure tags are properly saved as JSON
                                matching_rule.tags = current_tags
                                matching_rule.last_audit_results = audit_results
                                matching_rule.updated_at = datetime.now()
                                
                                # Force SQLAlchemy to detect changes in JSON fields
                                from sqlalchemy.orm.attributes import flag_modified
                                flag_modified(matching_rule, "tags")
                                flag_modified(matching_rule, "last_audit_results")
                                
                                try:
                                    # Flush to ensure SQLAlchemy detects the change
                                    db_audit.flush()
                                    db_audit.commit()
                                    
                                    # Refresh and verify the tags were saved
                                    db_audit.refresh(matching_rule)
                                    
                                    # Verify tags were actually saved
                                    saved_tags = matching_rule.tags
                                    if isinstance(saved_tags, str):
                                        try:
                                            import json
                                            saved_tags = json.loads(saved_tags)
                                        except:
                                            saved_tags = [saved_tags] if saved_tags else []
                                    elif not isinstance(saved_tags, list):
                                        saved_tags = []
                                    
                                    has_to_improve = 'to_improve' in saved_tags
                                    
                                    # Log to audit trail
                                    RuleChangeLogRepository.log_update(
                                        db_audit, matching_rule, previous_state, current_audit_user,
                                        reason="Audit analysis - tagged for improvement"
                                    )
                                    
                                    updated_count += 1
                                    if tag_added:
                                        if has_to_improve:
                                            debug_info.append(f"✓ Rule '{rule_name}' (ID: {matching_rule.id}) updated with 'to_improve' tag - VERIFIED")
                                        else:
                                            debug_info.append(f"⚠️ Rule '{rule_name}' (ID: {matching_rule.id}) - tag added but NOT saved! Tags: {saved_tags}")
                                            st.error(f"❌ Tag 'to_improve' was not saved for rule '{rule_name}'!")
                                    else:
                                        if has_to_improve:
                                            debug_info.append(f"✓ Rule '{rule_name}' (ID: {matching_rule.id}) already had 'to_improve' tag")
                                        else:
                                            debug_info.append(f"⚠️ Rule '{rule_name}' (ID: {matching_rule.id}) - tag should exist but doesn't! Tags: {saved_tags}")
                                except Exception as commit_error:
                                    db_audit.rollback()
                                    debug_info.append(f"✗ Error updating rule '{rule_name}': {commit_error}")
                                    st.warning(f"⚠️ Error updating rule '{rule_name}': {commit_error}")
                            elif not matching_rule and can_create_rules:
                                # Rule not found in database - create it (only if user has permission)
                                try:
                                    # Ensure we have a hash (should already be computed above)
                                    if not rule_hash and query:
                                        rule_hash = compute_rule_hash(query, rule_platform, rule_format)
                                    
                                    from db.models import UseCase
                                    # Get or create a default use case
                                    default_usecase = db_audit.query(UseCase).filter(UseCase.name == "Default").first()
                                    if not default_usecase:
                                        default_usecase = UseCase(name="Default", description="Default use case for imported rules")
                                        db_audit.add(default_usecase)
                                        db_audit.commit()
                                        db_audit.refresh(default_usecase)
                                    
                                    # Prepare tags for new rule (include AI recommended tags)
                                    new_rule_tags = ['to_improve']
                                    ai_recommended_tags_new = result.get('AI_Recommended_Tags', [])
                                    if ai_recommended_tags_new and isinstance(ai_recommended_tags_new, list):
                                        for recommended_tag in ai_recommended_tags_new:
                                            if recommended_tag and recommended_tag not in new_rule_tags:
                                                new_rule_tags.append(recommended_tag)
                                    
                                    # Create new rule
                                    new_rule = RuleImplementation(
                                        use_case_id=default_usecase.id,
                                        platform=rule_platform,
                                        rule_name=rule_name,
                                        rule_text=query,
                                        rule_format=rule_format,
                                        rule_hash=rule_hash,
                                        tags=new_rule_tags,
                                        mitre_technique_id=tech_id if tech_id else None,
                                        last_audit_results={
                                            'gap_analysis': result.get('AI_Gap_Analysis', ''),
                                            'improvement_suggestion': result.get('AI_Improvement', ''),
                                            'pseudo_code_recommendation': result.get('AI_Pseudo_Code', ''),
                                            'recommended_tags': result.get('AI_Recommended_Tags', []),
                                            'platform_recommendations': result.get('AI_Platform_Recommendations', ''),
                                            'status': result.get('AI_Analysis_Status', ''),
                                            'technique_id': result.get('Technique_ID', ''),
                                            'analyzed_at': datetime.now().isoformat()
                                        }
                                    )
                                    db_audit.add(new_rule)
                                    db_audit.flush()
                                    db_audit.commit()
                                    db_audit.refresh(new_rule)
                                    
                                    # Verify tags were saved
                                    saved_tags = new_rule.tags
                                    if isinstance(saved_tags, str):
                                        try:
                                            import json
                                            saved_tags = json.loads(saved_tags)
                                        except:
                                            saved_tags = [saved_tags] if saved_tags else []
                                    elif not isinstance(saved_tags, list):
                                        saved_tags = []
                                    
                                    has_to_improve = 'to_improve' in saved_tags
                                    if has_to_improve:
                                        debug_info.append(f"✓ Rule '{rule_name}' (ID: {new_rule.id}) created with 'to_improve' tag - VERIFIED")
                                    else:
                                        debug_info.append(f"⚠️ Rule '{rule_name}' (ID: {new_rule.id}) created but tag NOT saved! Tags: {saved_tags}")
                                        st.error(f"❌ Tag 'to_improve' was not saved for new rule '{rule_name}'!")
                                    
                                    # Log to audit trail
                                    RuleChangeLogRepository.log_create(
                                        db_audit, new_rule, current_audit_user,
                                        reason="Created from Audit page - gaps/improvements detected"
                                    )
                                    
                                    created_count += 1
                                except Exception as create_error:
                                    not_found_rules.append(rule_name)
                                    debug_info.append(f"✗ Could not create rule '{rule_name}': {create_error}")
                                    st.warning(f"⚠️ Could not create rule '{rule_name}' in database: {create_error}")
                    else:
                        debug_info.append(f"⚠️ Rule '{result.get('Rule_Name', 'Unknown')}' has no query text, skipping database update")
                else:
                    # Rule doesn't need improvement, but we should still save audit results if rule exists
                    if idx < len(all_rules_list):
                        original_rule = all_rules_list[idx]
                        rule_name = original_rule.get('Rule_Name', '')
                        query = original_rule.get('Query', '')
                        rule_platform = original_rule.get('Platform', '')
                        rule_format = original_rule.get('Format', 'unknown')
                        
                        if query:
                            rule_hash = compute_rule_hash(query, rule_platform, rule_format)
                            matching_rule = RuleRepository.get_by_hash(db_audit, rule_hash)
                            
                            if matching_rule:
                                # Save audit results even if no improvement needed
                                audit_results = {
                                    'gap_analysis': result.get('AI_Gap_Analysis', ''),
                                    'improvement_suggestion': result.get('AI_Improvement', ''),
                                    'status': result.get('AI_Analysis_Status', ''),
                                    'technique_id': result.get('Technique_ID', ''),
                                    'analyzed_at': datetime.now().isoformat()
                                }
                                matching_rule.last_audit_results = audit_results
                                matching_rule.updated_at = datetime.now()
                                try:
                                    db_audit.commit()
                                    db_audit.refresh(matching_rule)
                                except Exception as e:
                                    db_audit.rollback()
            
            # Display summary
            if updated_count > 0 or created_count > 0:
                msg_parts = []
                if updated_count > 0:
                    msg_parts.append(f"{updated_count} rule(s) updated")
                if created_count > 0:
                    msg_parts.append(f"{created_count} rule(s) created")
                st.success(f"✅ {' and '.join(msg_parts)} with 'to_improve' tag and audit results saved.")
                if created_count > 0:
                    st.info(f"💡 {created_count} new rule(s) have been added to the Rules Catalogue. You can find them there.")
                
                # Show debug info in expander
                if debug_info:
                    with st.expander("🔍 Debug Information", expanded=False):
                        for info in debug_info:
                            st.text(info)
            
            if not_found_rules:
                st.warning(f"⚠️ Could not save {len(not_found_rules)} rule(s) to database: {', '.join(not_found_rules[:3])}{'...' if len(not_found_rules) > 3 else ''}")
        except Exception as e:
            st.warning(f"⚠️ Could not update all rules in database: {e}")
            import traceback
            st.error(traceback.format_exc())
        finally:
            db_audit.close()
        
        # Display results
        st.subheader("📊 Coverage Report")
        
        # Metrics
        col1, col2, col3, col4 = st.columns(4)
        covered_techniques = results_df[results_df['Technique_Name'] != "Invalid ID / Not Found"]['Technique_ID'].nunique()
        col1.metric("Techniques Covered", covered_techniques)
        
        satisfied_count = results_df[results_df['AI_Analysis_Status'] == "Satisfied"].shape[0]
        col2.metric("✅ Satisfied", satisfied_count)
        
        critical_gaps = results_df[results_df['AI_Analysis_Status'] == "Gap Found"].shape[0]
        col3.metric("🔴 Gaps Found", critical_gaps)

        missing_plat_count = results_df[results_df['Missing_Platforms'].apply(lambda x: len(x) > 0 if isinstance(x, list) else False)].shape[0]
        col4.metric("⚠️ Platform Gaps", missing_plat_count)
        
        # Display detailed results with expandable sections
        st.subheader("📋 Detailed Results")
        for idx, result in enumerate(results):
            tech_id = result.get('Technique_ID', '')
            with st.expander(f"{result['Rule_Name']} - {tech_id} ({result['AI_Analysis_Status']})", expanded=False):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown(f"**Technique:** {result['Technique_Name']}")
                    st.markdown(f"**Platform:** {result['User_Platform']}")
                    st.markdown(f"**MITRE Platforms:** {result['MITRE_Platforms']}")
                    
                    if result.get('Missing_Platforms'):
                        st.warning("⚠️ **Missing Platforms:**")
                        for mp in result['Missing_Platforms']:
                            st.write(f"  - {mp}")
                    
                    # Display Detection Strategies if available
                    if tech_id and tech_id in mitre_info:
                        info = mitre_info[tech_id]
                        if info.get("detection_strategies"):
                            st.markdown("**🔍 Detection Strategies:**")
                            for ds in info["detection_strategies"]:
                                det_id = ds.get('det_id', 'N/A')
                                name = ds.get('name', 'N/A')
                                st.markdown(f"- **{det_id}**: {name}")
                
                with col2:
                    if result.get('AI_Gap_Analysis') and result['AI_Gap_Analysis'] != 'N/A':
                        st.markdown("**Gap Analysis:**")
                        st.info(result['AI_Gap_Analysis'])
                    
                    if result.get('AI_Improvement') and result['AI_Improvement'] != 'N/A':
                        st.markdown("**Improvement Suggestions:**")
                        st.success(result['AI_Improvement'])
                    
                    if result.get('AI_Pseudo_Code') and result['AI_Pseudo_Code'] != 'N/A':
                        st.markdown("**Recommended Detection Query:**")
                        st.code(result['AI_Pseudo_Code'], language="sql")
                    
                    if result.get('AI_Recommended_Tags') and len(result.get('AI_Recommended_Tags', [])) > 0:
                        st.markdown("**🏷️ Recommended Tags:**")
                        tags_display = " ".join([f"`{tag}`" for tag in result['AI_Recommended_Tags']])
                        st.markdown(tags_display)
                    
                    if result.get('AI_Platform_Recommendations') and result['AI_Platform_Recommendations'] and result['AI_Platform_Recommendations'] != 'N/A':
                        st.markdown("**🌐 Platform Recommendations:**")
                        st.info(result['AI_Platform_Recommendations'])
        
        # Download Reports
        st.subheader("📥 Download Reports")
        col1, col2 = st.columns(2)
        
        with col1:
            csv = results_df.to_csv(index=False).encode('utf-8')
            st.download_button(
                "📄 Download as CSV",
                csv,
                "coverage_report.csv",
                "text/csv",
                key='download-csv',
                width='stretch'
            )
        
        with col2:
            pdf_data = generate_pdf_report(results, mitre_info)
            st.download_button(
                "📑 Download as PDF",
                pdf_data,
                f"mitre_coverage_report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
                "application/pdf",
                key='download-pdf',
                width='stretch'
            )
    
    # Display results if they exist in session state (only show if analysis was run, not before)
    elif st.session_state.analysis_results is not None and len(st.session_state.analysis_results) > 0:
        results = st.session_state.analysis_results
        mitre_info = st.session_state.analysis_mitre_info
        results_df = pd.DataFrame(results)
        
        # Display results
        st.subheader("📊 Coverage Report")
        
        # Metrics
        col1, col2, col3, col4 = st.columns(4)
        covered_techniques = results_df[results_df['Technique_Name'] != "Invalid ID / Not Found"]['Technique_ID'].nunique()
        col1.metric("Techniques Covered", covered_techniques)
        
        satisfied_count = results_df[results_df['AI_Analysis_Status'] == "Satisfied"].shape[0]
        col2.metric("✅ Satisfied", satisfied_count)
        
        critical_gaps = results_df[results_df['AI_Analysis_Status'] == "Gap Found"].shape[0]
        col3.metric("🔴 Gaps Found", critical_gaps)

        missing_plat_count = results_df[results_df['Missing_Platforms'].apply(lambda x: len(x) > 0)].shape[0]
        col4.metric("⚠️ Platform Gaps", missing_plat_count)
        
        # Display detailed results with expandable sections
        st.subheader("📋 Detailed Results")
        for idx, result in enumerate(results):
            tech_id = result.get('Technique_ID', '')
            with st.expander(f"{result['Rule_Name']} - {tech_id} ({result['AI_Analysis_Status']})", expanded=False):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown(f"**Technique:** {result['Technique_Name']}")
                    st.markdown(f"**Platform:** {result['User_Platform']}")
                    st.markdown(f"**MITRE Platforms:** {result['MITRE_Platforms']}")
                    
                    if result.get('Missing_Platforms'):
                        st.warning("⚠️ **Missing Platforms:**")
                        for mp in result['Missing_Platforms']:
                            st.write(f"  - {mp}")
                    
                    # Display Detection Strategies if available
                    if tech_id and tech_id in mitre_info:
                        info = mitre_info[tech_id]
                        if info.get("detection_strategies"):
                            st.markdown("**🔍 Detection Strategies:**")
                            for ds in info["detection_strategies"]:
                                det_id = ds.get('det_id', 'N/A')
                                name = ds.get('name', 'N/A')
                                st.markdown(f"- **{det_id}**: {name}")
                
                with col2:
                    if result.get('AI_Gap_Analysis') and result['AI_Gap_Analysis'] != 'N/A':
                        st.markdown("**Gap Analysis:**")
                        st.info(result['AI_Gap_Analysis'])
                    
                    if result.get('AI_Improvement') and result['AI_Improvement'] != 'N/A':
                        st.markdown("**Improvement Suggestions:**")
                        st.success(result['AI_Improvement'])
                    
                    if result.get('AI_Pseudo_Code') and result['AI_Pseudo_Code'] != 'N/A':
                        st.markdown("**Recommended Detection Query:**")
                        st.code(result['AI_Pseudo_Code'], language="sql")
                    
                    if result.get('AI_Recommended_Tags') and len(result.get('AI_Recommended_Tags', [])) > 0:
                        st.markdown("**🏷️ Recommended Tags:**")
                        tags_display = " ".join([f"`{tag}`" for tag in result['AI_Recommended_Tags']])
                        st.markdown(tags_display)
                    
                    if result.get('AI_Platform_Recommendations') and result['AI_Platform_Recommendations'] and result['AI_Platform_Recommendations'] != 'N/A':
                        st.markdown("**🌐 Platform Recommendations:**")
                        st.info(result['AI_Platform_Recommendations'])
        
        # Download Reports (always available)
        st.subheader("📥 Download Reports")
        col1, col2 = st.columns(2)
        
        with col1:
            csv = results_df.to_csv(index=False).encode('utf-8')
            st.download_button(
                "📄 Download as CSV",
                csv,
                "coverage_report.csv",
                "text/csv",
                key='download-csv-persistent',
                width='stretch'
            )
        
        with col2:
            pdf_data = generate_pdf_report(results, mitre_info)
            st.download_button(
                "📑 Download as PDF",
                pdf_data,
                f"mitre_coverage_report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
                "application/pdf",
                key='download-pdf-persistent',
                width='stretch'
            )
        
        # Button to clear results
        if st.button("🔄 Clear Results and Run New Analysis", width='stretch'):
            st.session_state.analysis_results = None
            st.session_state.analysis_mitre_info = None
            st.rerun()

else:
    st.info("👆 Add rules using one of the methods above to begin analysis.")
    
    # Template download
    sample_data = pd.DataFrame({
        'Detection Name': ['Example Rule 1'],
        'Logic': ['ProcessName == "cmd.exe"'],
        'MITRE Technique ID': ['T1059.003'],
        'MITRE Tactic': ['Execution'],
        'Operational Modes': ['Windows']
    })
    csv_template = sample_data.to_csv(index=False).encode('utf-8')
    st.download_button(
        "Download Template CSV",
        csv_template,
        "template.csv",
        "text/csv"
    )

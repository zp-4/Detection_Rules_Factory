"""MITRE Mapping Analysis - AI-powered mapping verification and improvement."""
import streamlit as st
import pandas as pd
from datetime import datetime
from db.session import SessionLocal
from db.repo import RuleRepository
from db.models import RuleImplementation, MappingReview
from src.ai_engine import AIEngine
from src.mitre_engine import MitreEngine
from sqlalchemy.orm.attributes import flag_modified
from services.auth import get_current_user, has_permission, require_sign_in
from db.repo import RuleChangeLogRepository

st.set_page_config(
    page_title="MITRE Mapping Analysis",
    page_icon="🎯",
    layout="wide"
)

require_sign_in("MITRE Mapping Analysis")
username = get_current_user()

st.title("🎯 MITRE Mapping Analysis")
st.markdown("""
**AI-Powered MITRE Technique Mapping Verification**

This tool analyzes your detection rules and verifies their MITRE ATT&CK technique mappings.
It can suggest:
- **Alternative techniques** if the current mapping is incorrect
- **Multi-mapping** (2-3 techniques) if the rule detects multiple attack patterns
- **Mapping improvements** based on the actual rule logic
""")

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
    help="Select AI provider for mapping analysis"
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
        openai_api_key = st.sidebar.text_input("OpenAI API Key", type="password", key="mapping_openai_key", help="Or configure in the 'AI Configuration' page")
        openai_model_name = st.sidebar.text_input(
            "OpenAI model",
            value="gpt-4o",
            key="mapping_openai_model_manual",
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
        gemini_api_key = st.sidebar.text_input("Gemini API Key", type="password", key="mapping_gemini_key", help="Or configure in the 'AI Configuration' page")
        gemini_model_name = st.sidebar.text_input(
            "Gemini model",
            value="gemini-1.5-flash",
            key="mapping_gemini_model_manual",
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
            key="mapping_llama_base_url",
            help="OpenAI-compatible API endpoint (Ollama, vLLM, text-generation-inference, LM Studio)"
        )
        llama_model_name = st.sidebar.text_input(
            "Model Name",
            value="llama3",
            placeholder="llama3, mistral, codellama, etc.",
            key="mapping_llama_model_name",
            help="Model name as configured in your LLM server"
        )
        llama_api_key = st.sidebar.text_input(
            "API Key (optional)",
            type="password",
            key="mapping_llama_api_key",
            help="Leave empty if your LLM server doesn't require authentication"
        )

# Initialize MITRE Engine
@st.cache_resource
def get_mitre_engine(force_refresh=False, _api_version: int = 2):
    return MitreEngine(force_refresh=force_refresh)

try:
    mitre_engine = get_mitre_engine(force_refresh=False)
except Exception as e:
    st.error(f"Failed to load MITRE Data: {e}")
    st.stop()

# Database connection
db = SessionLocal()
try:
    # Get all enabled rules only
    all_rules = db.query(RuleImplementation).filter(
        RuleImplementation.enabled == True
    ).order_by(RuleImplementation.updated_at.desc()).all()
    
    if not all_rules:
        st.info("📋 No rules found. Add rules in the Rules page first.")
        st.stop()
    
    # Filter options
    st.header("📋 Select Rules to Analyze")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        filter_mapping = st.selectbox(
            "Filter by Mapping Status",
            ["All", "Mapped", "Not Mapped", "Needs Review (to_update_mapping tag)"],
            help="Filter rules by their MITRE mapping status"
        )
    
    with col2:
        filter_platform = st.selectbox(
            "Filter by Platform",
            ["All"] + sorted(list(set([r.platform for r in all_rules if r.platform]))),
            help="Filter rules by platform"
        )
    
    with col3:
        filter_format = st.selectbox(
            "Filter by Format",
            ["All"] + sorted(list(set([r.rule_format for r in all_rules if r.rule_format]))),
            help="Filter rules by format"
        )
    
    # Apply filters
    filtered_rules = all_rules
    if filter_mapping == "Mapped":
        # Check both mitre_technique_id and mitre_technique_ids
        filtered_rules = [r for r in filtered_rules if r.mitre_technique_id or (r.mitre_technique_ids and len(r.mitre_technique_ids) > 0)]
    elif filter_mapping == "Not Mapped":
        # Check both mitre_technique_id and mitre_technique_ids
        filtered_rules = [r for r in filtered_rules if not r.mitre_technique_id and (not r.mitre_technique_ids or len(r.mitre_technique_ids) == 0)]
    elif filter_mapping == "Needs Review (to_update_mapping tag)":
        filtered_rules = [r for r in filtered_rules if r.tags and 'to_update_mapping' in r.tags]
    
    if filter_platform != "All":
        filtered_rules = [r for r in filtered_rules if r.platform == filter_platform]
    
    if filter_format != "All":
        filtered_rules = [r for r in filtered_rules if r.rule_format == filter_format]
    
    st.info(f"📊 Found {len(filtered_rules)} rule(s) matching filters")
    
    # Rule selection
    if filtered_rules:
        # Create rule options with current mapping display
        rule_options = {}
        for r in filtered_rules:
            current_mappings = []
            if r.mitre_technique_ids and isinstance(r.mitre_technique_ids, list):
                current_mappings = r.mitre_technique_ids
            elif r.mitre_technique_id:
                current_mappings = [r.mitre_technique_id]
            mapping_display = ", ".join(current_mappings) if current_mappings else "Not Mapped"
            rule_options[f"{r.id}: {r.rule_name} ({r.platform}) - Current: {mapping_display}"] = r
        rule_labels = list(rule_options.keys())
        
        selected_rules_labels = st.multiselect(
            "Select Rules to Analyze",
            options=rule_labels,
            help="Select one or more rules to analyze their MITRE mapping",
            default=rule_labels
        )
        
        if selected_rules_labels:
            selected_rules = [rule_options[label] for label in selected_rules_labels]
            
            # Check AI configuration
            ai_configured = False
            if ai_provider == "OpenAI" and openai_api_key:
                ai_configured = True
            elif ai_provider == "Gemini" and gemini_api_key:
                ai_configured = True
            elif ai_provider == "Llama (Custom LLM)" and llama_base_url:
                ai_configured = True
            
            if not ai_configured:
                st.warning("⚠️ Please configure an AI provider and API key in the sidebar to analyze mappings.")
            else:
                # Initialize AI Engine
                if ai_provider == "Llama (Custom LLM)":
                    ai_engine = AIEngine(
                        api_key=llama_api_key or "",
                        provider="llama",
                        base_url=llama_base_url,
                        model_name=llama_model_name or "llama3",
                        team=st.session_state.get("user_team"),
                    )
                elif ai_provider == "OpenAI":
                    ai_engine = AIEngine(
                        openai_api_key,
                        provider="openai",
                        model_name=openai_model_name,
                        team=st.session_state.get("user_team"),
                    )
                else:
                    ai_engine = AIEngine(
                        gemini_api_key,
                        provider="gemini",
                        model_name=gemini_model_name,
                        team=st.session_state.get("user_team"),
                    )
                
                # Analyze button
                if st.button("🔍 Analyze Selected Rules", type="primary", width='stretch'):
                    results = []
                    
                    progress_bar = st.progress(0)
                    total_rules = len(selected_rules)
                    
                    for idx, rule in enumerate(selected_rules):
                        progress_bar.progress((idx + 1) / total_rules)
                        
                        # Get current technique details if mapped (check both mitre_technique_id and mitre_technique_ids)
                        current_tech_name = None
                        current_tech_ids = []
                        
                        # Get from mitre_technique_ids (multi-mapping) or mitre_technique_id (legacy)
                        if rule.mitre_technique_ids and isinstance(rule.mitre_technique_ids, list):
                            current_tech_ids = rule.mitre_technique_ids
                        elif rule.mitre_technique_id:
                            current_tech_ids = [rule.mitre_technique_id]
                        
                        # Get name from first technique for display
                        if current_tech_ids:
                            tech_details = mitre_engine.get_technique_details(current_tech_ids[0])
                            current_tech_name = tech_details.get('name', 'Unknown') if tech_details else 'Unknown'
                        
                        with st.spinner(f"Analyzing {rule.rule_name}..."):
                            # Analyze mapping (use first technique ID for compatibility)
                            current_tech_id_for_analysis = current_tech_ids[0] if current_tech_ids else None
                            analysis = ai_engine.analyze_mitre_mapping(
                                rule_name=rule.rule_name,
                                rule_text=rule.rule_text,
                                current_technique_id=current_tech_id_for_analysis,
                                current_technique_name=current_tech_name,
                                platform=rule.platform,
                                rule_format=rule.rule_format or "unknown"
                            )
                            
                            # Save analysis to database
                            rule.last_mapping_analysis = analysis
                            flag_modified(rule, "last_mapping_analysis")
                            db.commit()
                            
                            results.append({
                                "rule": rule,
                                "analysis": analysis
                            })
                    
                    st.success(f"✅ Analysis complete for {len(results)} rule(s)!")
                    st.rerun()
                
                # Load results from database for selected rules
                results = []
                for rule in selected_rules:
                    if rule.last_mapping_analysis:
                        results.append({
                            "rule": rule,
                            "analysis": rule.last_mapping_analysis
                        })
                
                # Display results if available
                if results:
                    st.divider()
                    st.header("📊 Mapping Analysis Results")
                    
                    for result in results:
                        rule = result["rule"]
                        analysis = result["analysis"]
                        
                        # Get current mappings (multi-mapping support)
                        current_mappings = []
                        if rule.mitre_technique_ids and isinstance(rule.mitre_technique_ids, list):
                            current_mappings = rule.mitre_technique_ids
                        elif rule.mitre_technique_id:
                            current_mappings = [rule.mitre_technique_id]
                        
                        current_mapping_display = ", ".join(current_mappings) if current_mappings else "Not Mapped"
                        
                        with st.expander(
                            f"🔍 {rule.rule_name} (ID: {rule.id}) - Current: {current_mapping_display}",
                            expanded=False
                        ):
                            # Current mapping status
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.markdown("**Current Mapping:**")
                                if current_mappings:
                                    for tech_id in current_mappings:
                                        tech_details = mitre_engine.get_technique_details(tech_id)
                                        st.info(f"**{tech_id}**: {tech_details.get('name', 'Unknown') if tech_details else 'Unknown'}")
                                else:
                                    st.warning("⚠️ Not mapped to any MITRE technique")
                            
                            with col2:
                                accuracy = analysis.get("current_mapping_accuracy", "Unknown")
                                if accuracy == "Correct":
                                    st.success(f"✅ Mapping Accuracy: **{accuracy}**")
                                elif accuracy == "Incorrect":
                                    st.error(f"❌ Mapping Accuracy: **{accuracy}**")
                                elif accuracy == "Partially Correct":
                                    st.warning(f"⚠️ Mapping Accuracy: **{accuracy}**")
                                else:
                                    st.info(f"ℹ️ Mapping Accuracy: **{accuracy}**")
                            
                            st.divider()
                            
                            # Primary technique recommendation
                            primary = analysis.get("primary_technique")
                            if primary:
                                st.subheader("🎯 Primary Technique Recommendation")
                                col_a, col_b = st.columns([2, 1])
                                
                                with col_a:
                                    st.markdown(f"**{primary.get('technique_id', 'N/A')}**: {primary.get('technique_name', 'N/A')}")
                                    st.markdown(f"**Tactics**: {', '.join(primary.get('tactics', []))}")
                                    st.markdown(f"**Confidence**: {primary.get('confidence', 'N/A')}")
                                
                                with col_b:
                                    st.markdown(f"**Reasoning:**")
                                    st.info(primary.get('reasoning', 'N/A'))
                            
                            # Alternative technique
                            alternative = analysis.get("alternative_technique")
                            if alternative and alternative.get("technique_id"):
                                st.subheader("🔄 Alternative Technique")
                                col_c, col_d = st.columns([2, 1])
                                
                                with col_c:
                                    st.markdown(f"**{alternative.get('technique_id', 'N/A')}**: {alternative.get('technique_name', 'N/A')}")
                                    st.markdown(f"**Tactics**: {', '.join(alternative.get('tactics', []))}")
                                    st.markdown(f"**Confidence**: {alternative.get('confidence', 'N/A')}")
                                
                                with col_d:
                                    st.markdown(f"**Reasoning:**")
                                    st.info(alternative.get('reasoning', 'N/A'))
                            
                            # Multi-mapping
                            multi_mapping = analysis.get("multi_mapping", [])
                            if multi_mapping:
                                st.subheader("🔗 Multi-Mapping (2-3 Techniques)")
                                st.info("This rule detects multiple distinct attack patterns and should be mapped to multiple techniques.")
                                
                                for tech in multi_mapping:
                                    with st.container():
                                        col_e, col_f = st.columns([2, 1])
                                        
                                        with col_e:
                                            st.markdown(f"**{tech.get('technique_id', 'N/A')}**: {tech.get('technique_name', 'N/A')}")
                                            st.markdown(f"**Tactics**: {', '.join(tech.get('tactics', []))}")
                                            st.markdown(f"**Confidence**: {tech.get('confidence', 'N/A')}")
                                        
                                        with col_f:
                                            st.info(tech.get('reasoning', 'N/A'))
                            
                            # Overall recommendation
                            st.divider()
                            st.subheader("💡 Overall Recommendation")
                            recommendation = analysis.get("recommendation", "N/A")
                            reasoning = analysis.get("recommendation_reasoning", "N/A")
                            
                            if "change" in recommendation.lower() or "alternative" in recommendation.lower():
                                st.warning(f"**{recommendation}**")
                            elif "multi" in recommendation.lower():
                                st.info(f"**{recommendation}**")
                            else:
                                st.success(f"**{recommendation}**")
                            
                            st.markdown(f"**Reasoning:** {reasoning}")
                            
                            # Action buttons
                            st.divider()
                            st.subheader("⚙️ Actions")
                            
                            # RBAC check - require "update" permission to modify mappings
                            can_modify = has_permission("update")
                            if not can_modify:
                                st.warning("🔒 Vous n'avez pas la permission de modifier les mappings (permission 'update' requise)")
                            
                            # Get current user for history
                            current_user = get_current_user() or "system"
                            
                            # Get current mappings
                            current_mappings_list = []
                            if rule.mitre_technique_ids and isinstance(rule.mitre_technique_ids, list):
                                current_mappings_list = rule.mitre_technique_ids.copy()
                            elif rule.mitre_technique_id:
                                current_mappings_list = [rule.mitre_technique_id]
                            
                            primary_tech_id = primary.get("technique_id") if primary else None
                            is_primary_in_current = primary_tech_id in current_mappings_list if primary_tech_id else False
                            
                            action_col1, action_col2, action_col3 = st.columns(3)
                            
                            with action_col1:
                                # Apply primary technique (Add or Replace)
                                if primary and primary.get("technique_id"):
                                    if current_mappings_list and not is_primary_in_current:
                                        button_label = f"🔄 Replace: {primary.get('technique_id')}"
                                        action_type = "replace"
                                    elif not current_mappings_list:
                                        button_label = f"➕ Add: {primary.get('technique_id')}"
                                        action_type = "add"
                                    else:
                                        button_label = f"✅ Already mapped: {primary.get('technique_id')}"
                                        action_type = None
                                    
                                    if action_type and st.button(button_label, key=f"apply_primary_{rule.id}", width='stretch', disabled=not can_modify):
                                        # Store previous state for audit log
                                        previous_state = RuleChangeLogRepository._rule_to_dict(rule)
                                        
                                        # Get previous mappings for history
                                        previous_tech_ids = current_mappings_list.copy() if current_mappings_list else []
                                        previous_tech_id = previous_tech_ids[0] if previous_tech_ids else None
                                        previous_tech_name = None
                                        if previous_tech_id:
                                            prev_details = mitre_engine.get_technique_details(previous_tech_id)
                                            previous_tech_name = prev_details.get('name', 'Unknown') if prev_details else 'Unknown'
                                        
                                        # Update rule with multi-mapping support
                                        if action_type == "replace":
                                            # Replace all with primary
                                            rule.mitre_technique_ids = [primary.get("technique_id")]
                                            rule.mitre_technique_id = primary.get("technique_id")  # Keep for backward compatibility
                                        else:  # add
                                            # Add to existing list
                                            if not rule.mitre_technique_ids:
                                                rule.mitre_technique_ids = []
                                            if primary_tech_id not in rule.mitre_technique_ids:
                                                rule.mitre_technique_ids.append(primary_tech_id)
                                            rule.mitre_technique_id = rule.mitre_technique_ids[0]  # Keep first for backward compatibility
                                        
                                        # Remove to_update_mapping tag if present
                                        if not rule.tags:
                                            rule.tags = []
                                        elif not isinstance(rule.tags, list):
                                            rule.tags = list(rule.tags) if rule.tags else []
                                        
                                        if 'to_update_mapping' in rule.tags:
                                            rule.tags.remove('to_update_mapping')
                                        
                                        rule.updated_at = datetime.now()
                                        flag_modified(rule, "tags")
                                        flag_modified(rule, "mitre_technique_ids")
                                        
                                        # Create mapping review history
                                        review = MappingReview(
                                            rule_id=rule.id,
                                            reviewed_by=current_user,
                                            previous_technique_id=previous_tech_id,
                                            previous_technique_name=previous_tech_name,
                                            action_type=action_type,
                                            new_technique_id=primary.get("technique_id"),
                                            new_technique_name=primary.get("technique_name", "Unknown"),
                                            ai_analysis=analysis,
                                            recommendation=analysis.get("recommendation", "")
                                        )
                                        db.add(review)
                                        db.commit()
                                        
                                        # Log to audit trail
                                        RuleChangeLogRepository.log_update(
                                            db, rule, previous_state, current_user,
                                            reason=f"Mapping {action_type}: {primary.get('technique_id')}"
                                        )
                                        
                                        st.success(f"✅ Updated rule {rule.id} with primary technique {primary.get('technique_id')}")
                                        st.rerun()
                            
                            with action_col2:
                                # Apply multi-mapping (if suggested)
                                if multi_mapping and len(multi_mapping) > 0:
                                    multi_tech_ids = [tech.get("technique_id") for tech in multi_mapping if tech.get("technique_id")]
                                    button_label = f"🔗 Apply Multi-Mapping ({len(multi_tech_ids)} techniques)"
                                    
                                    if st.button(button_label, key=f"apply_multi_{rule.id}", width='stretch', disabled=not can_modify):
                                        # Store previous state for audit log
                                        previous_state = RuleChangeLogRepository._rule_to_dict(rule)
                                        
                                        # Get previous mappings for history
                                        previous_tech_ids = current_mappings_list.copy() if current_mappings_list else []
                                        previous_tech_id = previous_tech_ids[0] if previous_tech_ids else None
                                        previous_tech_name = None
                                        if previous_tech_id:
                                            prev_details = mitre_engine.get_technique_details(previous_tech_id)
                                            previous_tech_name = prev_details.get('name', 'Unknown') if prev_details else 'Unknown'
                                        
                                        # Update rule with multi-mapping
                                        rule.mitre_technique_ids = multi_tech_ids
                                        rule.mitre_technique_id = multi_tech_ids[0] if multi_tech_ids else None  # Keep first for backward compatibility
                                        
                                        # Remove to_update_mapping tag if present
                                        if not rule.tags:
                                            rule.tags = []
                                        elif not isinstance(rule.tags, list):
                                            rule.tags = list(rule.tags) if rule.tags else []
                                        
                                        if 'to_update_mapping' in rule.tags:
                                            rule.tags.remove('to_update_mapping')
                                        
                                        rule.updated_at = datetime.now()
                                        flag_modified(rule, "tags")
                                        flag_modified(rule, "mitre_technique_ids")
                                        
                                        # Create mapping review history
                                        review = MappingReview(
                                            rule_id=rule.id,
                                            reviewed_by=current_user,
                                            previous_technique_id=previous_tech_id,
                                            previous_technique_name=previous_tech_name,
                                            action_type="multi-mapping",
                                            new_technique_id=multi_tech_ids[0] if multi_tech_ids else None,
                                            new_technique_name=multi_mapping[0].get("technique_name", "Unknown") if multi_mapping else "Unknown",
                                            additional_techniques=[{"technique_id": tech.get("technique_id"), "technique_name": tech.get("technique_name")} for tech in multi_mapping[1:] if tech.get("technique_id")],
                                            ai_analysis=analysis,
                                            recommendation=analysis.get("recommendation", "")
                                        )
                                        db.add(review)
                                        db.commit()
                                        
                                        # Log to audit trail
                                        RuleChangeLogRepository.log_update(
                                            db, rule, previous_state, current_user,
                                            reason=f"Multi-mapping: {', '.join(multi_tech_ids)}"
                                        )
                                        
                                        st.success(f"✅ Updated rule {rule.id} with {len(multi_tech_ids)} techniques (multi-mapping)")
                                        st.rerun()
                                
                                # Apply alternative technique (Replace only)
                                elif alternative and alternative.get("technique_id"):
                                    if st.button(f"🔄 Replace: {alternative.get('technique_id')}", key=f"apply_alt_{rule.id}", width='stretch', disabled=not can_modify):
                                        # Store previous state for audit log
                                        previous_state = RuleChangeLogRepository._rule_to_dict(rule)
                                        
                                        # Get previous mappings for history
                                        previous_tech_ids = current_mappings_list.copy() if current_mappings_list else []
                                        previous_tech_id = previous_tech_ids[0] if previous_tech_ids else None
                                        previous_tech_name = None
                                        if previous_tech_id:
                                            prev_details = mitre_engine.get_technique_details(previous_tech_id)
                                            previous_tech_name = prev_details.get('name', 'Unknown') if prev_details else 'Unknown'
                                        
                                        # Update rule
                                        rule.mitre_technique_ids = [alternative.get("technique_id")]
                                        rule.mitre_technique_id = alternative.get("technique_id")
                                        
                                        # Remove to_update_mapping tag if present
                                        if not rule.tags:
                                            rule.tags = []
                                        elif not isinstance(rule.tags, list):
                                            rule.tags = list(rule.tags) if rule.tags else []
                                        
                                        if 'to_update_mapping' in rule.tags:
                                            rule.tags.remove('to_update_mapping')
                                        
                                        rule.updated_at = datetime.now()
                                        flag_modified(rule, "tags")
                                        flag_modified(rule, "mitre_technique_ids")
                                        
                                        # Create mapping review history
                                        review = MappingReview(
                                            rule_id=rule.id,
                                            reviewed_by=current_user,
                                            previous_technique_id=previous_tech_id,
                                            previous_technique_name=previous_tech_name,
                                            action_type="replace",
                                            new_technique_id=alternative.get("technique_id"),
                                            new_technique_name=alternative.get("technique_name", "Unknown"),
                                            ai_analysis=analysis,
                                            recommendation=analysis.get("recommendation", "")
                                        )
                                        db.add(review)
                                        db.commit()
                                        
                                        # Log to audit trail
                                        RuleChangeLogRepository.log_update(
                                            db, rule, previous_state, current_user,
                                            reason=f"Mapping replace: {alternative.get('technique_id')}"
                                        )
                                        
                                        st.success(f"✅ Updated rule {rule.id} with alternative technique {alternative.get('technique_id')}")
                                        st.rerun()
                            
                            with action_col3:
                                # Tag for manual review
                                if st.button(f"🏷️ Tag for Review", key=f"tag_review_{rule.id}", width='stretch', disabled=not can_modify):
                                    # Store previous state for audit log
                                    previous_state = RuleChangeLogRepository._rule_to_dict(rule)
                                    
                                    # Ensure tags is a list
                                    if not rule.tags:
                                        rule.tags = []
                                    elif not isinstance(rule.tags, list):
                                        # Handle case where tags might be stored as string
                                        if isinstance(rule.tags, str):
                                            try:
                                                import json
                                                rule.tags = json.loads(rule.tags)
                                            except:
                                                rule.tags = [rule.tags] if rule.tags else []
                                        else:
                                            rule.tags = list(rule.tags) if rule.tags else []
                                    
                                    if 'to_update_mapping' not in rule.tags:
                                        rule.tags.append('to_update_mapping')
                                    
                                    rule.updated_at = datetime.now()
                                    flag_modified(rule, "tags")
                                    db.commit()
                                    
                                    # Log to audit trail
                                    RuleChangeLogRepository.log_update(
                                        db, rule, previous_state, current_user,
                                        reason="Tagged for mapping review"
                                    )
                                    
                                    st.success(f"✅ Tagged rule {rule.id} for mapping review")
                                    st.rerun()
                            
                            # Display mapping history
                            st.divider()
                            st.subheader("📜 Mapping Review History")
                            mapping_history = db.query(MappingReview).filter(
                                MappingReview.rule_id == rule.id
                            ).order_by(MappingReview.reviewed_at.desc()).limit(10).all()
                            
                            if mapping_history:
                                for hist in mapping_history:
                                    with st.expander(f"Review by {hist.reviewed_by} on {hist.reviewed_at.strftime('%Y-%m-%d %H:%M')}", expanded=False):
                                        col_h1, col_h2 = st.columns(2)
                                        with col_h1:
                                            if hist.previous_technique_id:
                                                st.markdown(f"**Previous:** {hist.previous_technique_id} - {hist.previous_technique_name or 'N/A'}")
                                            else:
                                                st.markdown("**Previous:** Not mapped")
                                        
                                        with col_h2:
                                            st.markdown(f"**Action:** {hist.action_type.title()}")
                                        
                                        if hist.new_technique_id:
                                            st.markdown(f"**New:** {hist.new_technique_id} - {hist.new_technique_name or 'N/A'}")
                                        
                                        if hist.recommendation:
                                            st.info(f"**Recommendation:** {hist.recommendation}")
                            else:
                                st.info("No mapping review history for this rule.")
                            
                            # Display rule details
                            with st.expander("📋 Rule Details", expanded=False):
                                st.code(f"Name: {rule.rule_name}\nPlatform: {rule.platform}\nFormat: {rule.rule_format}\n\nQuery:\n{rule.rule_text}", language="text")
                    
                    # Re-analyze button
                    if st.button("🔄 Re-analyze Selected Rules", width='stretch'):
                        # Clear last_mapping_analysis to force re-analysis
                        for result in results:
                            result["rule"].last_mapping_analysis = None
                            flag_modified(result["rule"], "last_mapping_analysis")
                        db.commit()
                        st.rerun()
    
    else:
        st.warning("⚠️ No rules match the selected filters.")

finally:
    db.close()

# Add admin link at bottom of sidebar
st.sidebar.divider()
if st.sidebar.button("⚙️ Admin", width='stretch'):
    st.switch_page("pages/8_Admin.py")

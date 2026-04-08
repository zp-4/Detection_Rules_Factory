"""MITRE Coverage Dashboard - SOC Edition."""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from sqlalchemy.orm import Session
from db.session import SessionLocal
from db.models import RuleImplementation, UseCase
from db.repo import UseCaseRepository, RuleRepository
from services.mitre_coverage import get_mitre_engine
from services.auth import get_current_user, require_sign_in
from services.exec_metrics import collect_executive_metrics
from services.exec_report_pdf import build_executive_pdf
from datetime import datetime, timedelta, timezone
import json
from collections import Counter, defaultdict

st.set_page_config(page_title="MITRE Dashboard", page_icon="📊", layout="wide")

require_sign_in("the MITRE Dashboard")
username = get_current_user()

# Custom CSS for SOC-style dashboard
st.markdown("""
<style>
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
    }
    .stMetric {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #667eea;
    }
    h1 {
        color: #1f2937;
        border-bottom: 3px solid #667eea;
        padding-bottom: 0.5rem;
    }
    .tactic-badge {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        border-radius: 12px;
        font-size: 0.85rem;
        font-weight: 600;
        margin: 0.2rem;
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ MITRE ATT&CK Coverage Dashboard")
st.markdown("**Security Operations Center - Threat Detection Coverage Analysis**")

db = SessionLocal()
try:
    # Get all use cases and rules
    use_cases = UseCaseRepository.list_all(db, limit=1000)
    all_rules = (
        db.query(RuleImplementation)
        .filter(RuleImplementation.archived_at.is_(None))
        .all()
    )
    
    # Initialize MITRE engine
    mitre_engine = get_mitre_engine()
    
    # ========== SECTION 1: KEY METRICS ==========
    st.header("📊 Executive Summary")
    
    # Calculate key metrics
    total_techniques_claimed = set()
    techniques_with_rules = set()
    rules_by_technique = defaultdict(int)
    platforms_used = set()
    rules_by_platform = defaultdict(int)
    
    for uc in use_cases:
        if uc.mitre_claimed:
            for tech_id in uc.mitre_claimed:
                total_techniques_claimed.add(tech_id)
    
    for rule in all_rules:
        if rule.mitre_technique_id:
            techniques_with_rules.add(rule.mitre_technique_id)
            rules_by_technique[rule.mitre_technique_id] += 1
        if rule.platform:
            platforms_used.add(rule.platform)
            rules_by_platform[rule.platform] += 1
    
    # Get total techniques in MITRE Enterprise
    all_mitre_techniques = mitre_engine.mitre_attack_data.get_techniques(include_subtechniques=True, remove_revoked_deprecated=True)
    total_mitre_techniques = len(all_mitre_techniques)
    
    # Calculate coverage percentage
    coverage_percent = (len(total_techniques_claimed) / total_mitre_techniques * 100) if total_mitre_techniques > 0 else 0
    
    # Display metrics in columns
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric(
            "📋 Use Cases",
            len(use_cases),
            help="Total number of use cases defined"
        )
    
    with col2:
        st.metric(
            "🔍 Detection Rules",
            len(all_rules),
            help="Total number of detection rules implemented"
        )
    
    with col3:
        st.metric(
            "🎯 Techniques Covered",
            len(total_techniques_claimed),
            f"{coverage_percent:.1f}% of {total_mitre_techniques}",
            help="MITRE techniques covered by use cases"
        )
    
    with col4:
        enabled_rules = sum(1 for r in all_rules if r.enabled)
        st.metric(
            "✅ Active Rules",
            enabled_rules,
            f"{len(all_rules) - enabled_rules} disabled",
            help="Number of enabled detection rules"
        )
    
    with col5:
        rules_needing_improvement = sum(1 for r in all_rules if r.tags and 'to_improve' in r.tags)
        st.metric(
            "⚠️ Rules to Improve",
            rules_needing_improvement,
            help="Rules tagged for improvement"
        )

    _em = collect_executive_metrics(db, include_archived=False)
    _pdf = build_executive_pdf(_em, title="MITRE coverage — executive summary")
    st.download_button(
        "📄 Download executive PDF",
        data=_pdf,
        file_name=f"executive_summary_{datetime.now(timezone.utc).strftime('%Y%m%d')}.pdf",
        mime="application/pdf",
        help="One-page PDF with catalogue metrics (same family as Governance page).",
    )
    
    st.divider()
    
    # ========== SECTION 2: COVERAGE VISUALIZATIONS ==========
    st.header("📈 Coverage Analysis")
    
    if total_techniques_claimed:
        # Rules Distribution by Platform
        if rules_by_platform:
            col1, col2 = st.columns(2)
            with col1:
                platforms_df = pd.DataFrame([
                    {"Platform": platform, "Rules": count}
                    for platform, count in sorted(rules_by_platform.items(), key=lambda x: x[1], reverse=True)
                ])
                
                fig_platforms = px.pie(
                    platforms_df,
                    values="Rules",
                    names="Platform",
                    title="🖥️ Rules Distribution by Platform",
                    hole=0.4
                )
                fig_platforms.update_traces(textposition='inside', textinfo='percent+label')
                fig_platforms.update_layout(height=400)
                st.plotly_chart(fig_platforms, width='stretch')
            
            with col2:
                # Coverage Progress Gauge
                fig_gauge = go.Figure(go.Indicator(
                    mode="gauge+number+delta",
                    value=coverage_percent,
                    domain={'x': [0, 1], 'y': [0, 1]},
                    title={'text': "Overall MITRE Coverage"},
                    delta={'reference': 50},
                    gauge={
                        'axis': {'range': [None, 100]},
                        'bar': {'color': "darkblue"},
                        'steps': [
                            {'range': [0, 50], 'color': "lightgray"},
                            {'range': [50, 75], 'color': "gray"},
                            {'range': [75, 100], 'color': "lightgreen"}
                        ],
                        'threshold': {
                            'line': {'color': "red", 'width': 4},
                            'thickness': 0.75,
                            'value': 90
                        }
                    }
                ))
                fig_gauge.update_layout(height=400)
                st.plotly_chart(fig_gauge, width='stretch')
        
        st.divider()
        
        # ========== SECTION 3: DETAILED STATISTICS ==========
        st.header("📋 Detailed Statistics")
        
        tab1, tab2, tab3, tab4 = st.tabs(["🎯 Techniques", "📊 Rules", "🏷️ Tags", "📅 Timeline"])
        
        with tab1:
            # Techniques table with details
            techniques_data = []
            for tech_id in sorted(total_techniques_claimed):
                tech_details = mitre_engine.get_technique_details(tech_id)
                rule_count = rules_by_technique.get(tech_id, 0)
                techniques_data.append({
                    "Technique ID": tech_id,
                    "Name": tech_details.get('name', 'Unknown'),
                    "Rules": rule_count,
                    "Platforms": ", ".join(tech_details.get('platforms', [])[:3]) + ("..." if len(tech_details.get('platforms', [])) > 3 else ""),
                    "Covered": "✅" if rule_count > 0 else "⚠️"
                })
            
            techniques_df = pd.DataFrame(techniques_data)
            st.dataframe(
                techniques_df,
                width='stretch',
                hide_index=True,
                height=400
            )
            
            # Techniques with most rules
            if rules_by_technique:
                top_techniques = sorted(rules_by_technique.items(), key=lambda x: x[1], reverse=True)[:10]
                top_tech_df = pd.DataFrame([
                    {
                        "Technique ID": tech_id,
                        "Rules Count": count,
                        "Details": mitre_engine.get_technique_details(tech_id).get('name', 'Unknown')
                    }
                    for tech_id, count in top_techniques
                ])
                
                st.subheader("🔝 Top 10 Techniques by Rule Count")
                fig_top = px.bar(
                    top_tech_df,
                    x="Technique ID",
                    y="Rules Count",
                    title="Most Covered Techniques",
                    color="Rules Count",
                    color_continuous_scale="Blues",
                    text="Rules Count"
                )
                fig_top.update_traces(textposition='outside')
                fig_top.update_layout(height=400, showlegend=False)
                st.plotly_chart(fig_top, width='stretch')
        
        with tab2:
            # Rules statistics
            rules_data = []
            for rule in all_rules:
                rules_data.append({
                    "ID": rule.id,
                    "Name": rule.rule_name,
                    "Platform": rule.platform,
                    "Technique": rule.mitre_technique_id or "N/A",
                    "Format": rule.rule_format or "unknown",
                    "Status": "✅ Enabled" if rule.enabled else "❌ Disabled",
                    "Tags": ", ".join(rule.tags) if rule.tags else "None",
                    "Updated": rule.updated_at.strftime("%Y-%m-%d") if rule.updated_at else "N/A"
                })
            
            rules_df = pd.DataFrame(rules_data)
            
            # Filters
            col1, col2, col3 = st.columns(3)
            with col1:
                platform_filter = st.multiselect("Filter by Platform", options=sorted(platforms_used), default=[])
            with col2:
                status_filter = st.multiselect("Filter by Status", options=["✅ Enabled", "❌ Disabled"], default=[])
            with col3:
                format_filter = st.multiselect("Filter by Format", options=sorted(rules_df["Format"].unique()), default=[])
            
            # Apply filters
            filtered_df = rules_df.copy()
            if platform_filter:
                filtered_df = filtered_df[filtered_df["Platform"].isin(platform_filter)]
            if status_filter:
                filtered_df = filtered_df[filtered_df["Status"].isin(status_filter)]
            if format_filter:
                filtered_df = filtered_df[filtered_df["Format"].isin(format_filter)]
            
            st.dataframe(
                filtered_df,
                width='stretch',
                hide_index=True,
                height=400
            )
            
            # Rules by format
            if rules_data:
                format_counts = Counter([r["Format"] for r in rules_data])
                format_df = pd.DataFrame([
                    {"Format": fmt, "Count": count}
                    for fmt, count in format_counts.items()
                ])
                
                fig_format = px.bar(
                    format_df,
                    x="Format",
                    y="Count",
                    title="Rules by Format",
                    color="Count",
                    color_continuous_scale="Purples"
                )
                fig_format.update_layout(height=300)
                st.plotly_chart(fig_format, width='stretch')
        
        with tab3:
            # Tags analysis
            all_tags = []
            for rule in all_rules:
                if rule.tags:
                    all_tags.extend(rule.tags)
            
            if all_tags:
                tag_counts = Counter(all_tags)
                tags_df = pd.DataFrame([
                    {"Tag": tag, "Count": count}
                    for tag, count in tag_counts.most_common(20)
                ])
                
                fig_tags = px.bar(
                    tags_df,
                    x="Tag",
                    y="Count",
                    title="🏷️ Most Used Tags",
                    color="Count",
                    color_continuous_scale="Oranges"
                )
                fig_tags.update_layout(xaxis_tickangle=-45, height=400)
                st.plotly_chart(fig_tags, width='stretch')
                
                st.dataframe(tags_df, width='stretch', hide_index=True)
            else:
                st.info("No tags found in rules.")
        
        with tab4:
            # Timeline of rule creation/updates
            if all_rules:
                timeline_data = []
                for rule in all_rules:
                    timeline_data.append({
                        "Date": rule.created_at.date() if rule.created_at else datetime.now().date(),
                        "Type": "Created",
                        "Rule": rule.rule_name
                    })
                    if rule.updated_at and rule.updated_at != rule.created_at:
                        timeline_data.append({
                            "Date": rule.updated_at.date(),
                            "Type": "Updated",
                            "Rule": rule.rule_name
                        })
                
                timeline_df = pd.DataFrame(timeline_data)
                timeline_df = timeline_df.groupby(["Date", "Type"]).size().reset_index(name="Count")
                timeline_df["Date"] = pd.to_datetime(timeline_df["Date"])
                timeline_df = timeline_df.sort_values("Date")
                
                fig_timeline = px.line(
                    timeline_df,
                    x="Date",
                    y="Count",
                    color="Type",
                    title="📅 Rules Activity Timeline",
                    markers=True
                )
                fig_timeline.update_layout(height=400)
                st.plotly_chart(fig_timeline, width='stretch')
        
        st.divider()
        
        # ========== SECTION 4: GAP ANALYSIS ==========
        st.header("⚠️ Gap Analysis")
        
        # Calculate gaps
        all_mitre_tech_ids = set()
        for tech in all_mitre_techniques:
            try:
                tech_obj = tech.object if hasattr(tech, 'object') else tech
                ext_refs = []
                if isinstance(tech_obj, dict):
                    ext_refs = tech_obj.get('external_references', [])
                else:
                    ext_refs = getattr(tech_obj, 'external_references', [])
                
                for ref in ext_refs:
                    ref_source = ref.get('source_name') if isinstance(ref, dict) else getattr(ref, 'source_name', '')
                    ref_id = ref.get('external_id') if isinstance(ref, dict) else getattr(ref, 'external_id', '')
                    if ref_source == 'mitre-attack' and ref_id:
                        all_mitre_tech_ids.add(ref_id)
                        break
            except Exception:
                # Skip if error processing technique
                pass
        
        uncovered_techniques = all_mitre_tech_ids - total_techniques_claimed
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("✅ Covered Techniques", len(total_techniques_claimed))
            st.metric("❌ Uncovered Techniques", len(uncovered_techniques))
        
        with col2:
            coverage_ratio = len(total_techniques_claimed) / len(all_mitre_tech_ids) * 100 if all_mitre_tech_ids else 0
            st.metric("📊 Coverage Ratio", f"{coverage_ratio:.1f}%")
            
            if uncovered_techniques:
                st.warning(f"⚠️ {len(uncovered_techniques)} techniques are not yet covered by any use case or rule.")
        
        # Show sample of uncovered techniques
        if uncovered_techniques:
            with st.expander("🔍 View Uncovered Techniques (Sample)", expanded=False):
                uncovered_sample = list(uncovered_techniques)[:20]
                uncovered_data = []
                for tech_id in uncovered_sample:
                    tech_details = mitre_engine.get_technique_details(tech_id)
                    uncovered_data.append({
                        "Technique ID": tech_id,
                        "Name": tech_details.get('name', 'Unknown'),
                        "Platforms": ", ".join(tech_details.get('platforms', [])[:3])
                    })
                
                uncovered_df = pd.DataFrame(uncovered_data)
                st.dataframe(uncovered_df, width='stretch', hide_index=True)
        
        st.divider()
    
    else:
        st.warning("⚠️ No MITRE techniques found. Add use cases with MITRE techniques to see coverage analysis.")
    
    st.divider()
    
    # ========== SECTION 6: MITRE NAVIGATOR EXPORT (KEEP AS IS) ==========
    st.subheader("🗺️ MITRE ATT&CK Navigator Export")
    st.markdown("Generate a Navigator layer JSON file compatible with [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)")
    
    # Get all techniques from use cases
    all_techniques = {}
    
    for uc in use_cases:
        if uc.mitre_claimed:
            for tech_id in uc.mitre_claimed:
                if tech_id not in all_techniques:
                    all_techniques[tech_id] = {
                        "use_cases": [],
                        "rules_count": 0
                    }
                all_techniques[tech_id]["use_cases"].append(uc.name)
                # Count rules for this technique
                if uc.rules:
                    all_techniques[tech_id]["rules_count"] += len(uc.rules)
    
    if all_techniques:
        # Generate Navigator layer JSON
        layer_name = st.text_input(
            "Layer Name",
            value=f"Use Case Factory Coverage - {datetime.now().strftime('%Y-%m-%d')}",
            help="Name for the Navigator layer"
        )
        
        layer_description = st.text_area(
            "Layer Description",
            value=f"MITRE ATT&CK coverage from {len(use_cases)} use cases covering {len(all_techniques)} techniques",
            help="Description for the Navigator layer"
        )
        
        # Scoring options
        scoring_method = st.radio(
            "Scoring Method",
            ["Binary (covered/not covered)", "By number of use cases", "By number of rules"],
            help="How to score techniques in the Navigator"
        )
        
        # Generate techniques array for Navigator
        techniques_list = []
        for tech_id, data in all_techniques.items():
            # Get technique object to extract tactics
            tactics_list = []
            try:
                technique_obj = mitre_engine.mitre_attack_data.get_object_by_attack_id(tech_id, 'attack-pattern')
                if technique_obj:
                    # Handle different object types
                    if hasattr(technique_obj, 'kill_chain_phases'):
                        phases = technique_obj.kill_chain_phases
                    elif hasattr(technique_obj, 'object') and hasattr(technique_obj.object, 'kill_chain_phases'):
                        phases = technique_obj.object.kill_chain_phases
                    else:
                        phases = []
                    
                    for phase in phases:
                        phase_name = getattr(phase, 'kill_chain_name', None) if hasattr(phase, 'kill_chain_name') else (phase.get('kill_chain_name') if isinstance(phase, dict) else None)
                        if phase_name == "mitre-attack":
                            tactic_name = getattr(phase, 'phase_name', None) if hasattr(phase, 'phase_name') else (phase.get('phase_name') if isinstance(phase, dict) else None)
                            if tactic_name:
                                tactics_list.append(tactic_name)
            except Exception:
                # Skip if technique not found
                pass
            
            # Calculate score based on method
            if scoring_method == "Binary (covered/not covered)":
                score = 1
            elif scoring_method == "By number of use cases":
                score = len(data["use_cases"])
            else:  # By number of rules
                score = data["rules_count"]
            
            # Create technique entry
            technique_entry = {
                "techniqueID": tech_id,
                "score": score,
                "enabled": True,
                "comment": f"Covered by: {', '.join(data['use_cases'][:3])}" + ("..." if len(data['use_cases']) > 3 else ""),
                "metadata": [
                    {
                        "name": "Use Cases",
                        "value": ", ".join(data['use_cases'])
                    },
                    {
                        "name": "Rules Count",
                        "value": str(data['rules_count'])
                    }
                ]
            }
            
            # Add tactics if available (Navigator can use this for filtering)
            if tactics_list:
                technique_entry["tactic"] = tactics_list[0]  # Navigator uses primary tactic
            
            techniques_list.append(technique_entry)
        
        # Create Navigator layer JSON structure
        navigator_layer = {
            "name": layer_name,
            "versions": {
                "attack": "18",
                "navigator": "4.9.0",
                "layer": "4.4"
            },
            "domain": "enterprise-attack",
            "description": layer_description,
            "techniques": techniques_list,
            "gradient": {
                "colors": ["#ff6666", "#ffe766", "#8ec843"],
                "minValue": 0,
                "maxValue": max([t["score"] for t in techniques_list], default=100)
            },
            "metadata": [],
            "showTacticRowBackground": False,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False
        }
        
        # Display preview
        with st.expander("📋 Preview Navigator Layer JSON", expanded=False):
            st.json(navigator_layer)
        
        # Download button
        navigator_json = json.dumps(navigator_layer, indent=2)
        st.download_button(
            "📥 Download Navigator Layer JSON",
            navigator_json.encode('utf-8'),
            f"mitre_navigator_layer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "application/json",
            width='stretch',
            help="Download the layer JSON file and import it into MITRE ATT&CK Navigator"
        )
        
        st.info("💡 **How to use:** Download the JSON file and import it into [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) using the 'Open Existing Layer' button.")
    else:
        st.info("No techniques found. Add use cases with MITRE techniques to generate a Navigator layer.")

finally:
    db.close()

# Add admin link at bottom of sidebar
st.sidebar.divider()
if st.sidebar.button("⚙️ Admin", width='stretch'):
    st.switch_page("pages/8_Admin.py")

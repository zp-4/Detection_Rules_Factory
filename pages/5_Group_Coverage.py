"""MITRE Group Coverage Analysis - APT Coverage Assessment."""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from db.session import SessionLocal
from db.models import RuleImplementation
from src.mitre_engine import MitreEngine, list_software_for_group
from services.auth import get_current_user, login

st.set_page_config(
    page_title="Group Coverage Analysis",
    page_icon="🎯",
    layout="wide"
)

# Authentication check
username = get_current_user()
if not username:
    st.warning("Please login to access Group Coverage Analysis")
    st.divider()
    
    # Login form
    with st.form("login_form_group_coverage"):
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

st.title("🎯 MITRE Group Coverage Analysis")
st.markdown("""
**APT Group Coverage Assessment**

This page analyzes how well your detection rules cover the techniques used by known APT groups (threat actors).
It calculates the percentage of each group's techniques that are covered by your rules.
""")

# Initialize MITRE Engine (_api_version invalidates cache when MitreEngine gains new methods)
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
    # Get all enabled rules with MITRE mappings
    all_rules = db.query(RuleImplementation).filter(
        RuleImplementation.enabled == True
    ).all()
    
    # Collect all techniques covered by rules
    covered_techniques = set()
    for rule in all_rules:
        # Check multi-mapping first
        if rule.mitre_technique_ids and isinstance(rule.mitre_technique_ids, list):
            covered_techniques.update(rule.mitre_technique_ids)
        # Fallback to single mapping
        elif rule.mitre_technique_id:
            covered_techniques.add(rule.mitre_technique_id)
    
    st.info(f"📊 **Your rules cover {len(covered_techniques)} unique MITRE techniques**")
    
    # Get all groups
    with st.spinner("Loading MITRE groups..."):
        groups = mitre_engine.get_all_groups(remove_revoked_deprecated=True)
    
    if not groups:
        st.error("No groups found in MITRE data")
        st.stop()
    
    st.success(f"✅ Loaded {len(groups)} MITRE groups")
    
    # Calculate coverage for each group
    st.header("📈 Coverage Analysis")
    
    coverage_data = []
    
    with st.spinner("Calculating coverage for all groups..."):
        progress_bar = st.progress(0)
        total_groups = len(groups)
        
        for idx, group in enumerate(groups):
            progress_bar.progress((idx + 1) / total_groups)
            
            # Get techniques used by this group
            group_techniques = mitre_engine.get_techniques_used_by_group(group['id'])
            
            if not group_techniques:
                continue  # Skip groups with no techniques
            
            # Calculate coverage
            covered_count = len([t for t in group_techniques if t in covered_techniques])
            total_count = len(group_techniques)
            coverage_percent = (covered_count / total_count * 100) if total_count > 0 else 0
            
            uncovered_techniques = [t for t in group_techniques if t not in covered_techniques]
            
            coverage_data.append({
                'Group ID': group['attack_id'],
                'Group Name': group['name'],
                'Group STIX ID': group['id'],  # Store STIX ID for later use
                'Total Techniques': total_count,
                'Covered': covered_count,
                'Uncovered': total_count - covered_count,
                'Coverage %': round(coverage_percent, 1),
                'Uncovered Techniques': uncovered_techniques,
                'Group URL': group.get('url', ''),
                'Aliases': ', '.join(group.get('aliases', [])[:3])  # First 3 aliases
            })
        
        progress_bar.empty()
    
    if not coverage_data:
        st.warning("No coverage data available. Make sure your rules have MITRE technique mappings.")
        st.stop()
    
    # Create DataFrame
    df = pd.DataFrame(coverage_data)
    
    # Sort by coverage percentage (ascending - lowest coverage first)
    df = df.sort_values('Coverage %', ascending=True)
    
    # Display summary metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        avg_coverage = df['Coverage %'].mean()
        st.metric("Average Coverage", f"{avg_coverage:.1f}%")
    
    with col2:
        fully_covered = len(df[df['Coverage %'] == 100.0])
        st.metric("Fully Covered Groups", fully_covered)
    
    with col3:
        partially_covered = len(df[(df['Coverage %'] > 0) & (df['Coverage %'] < 100)])
        st.metric("Partially Covered", partially_covered)
    
    with col4:
        not_covered = len(df[df['Coverage %'] == 0.0])
        st.metric("Not Covered", not_covered)
    
    st.divider()
    
    # Filters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        min_coverage = st.slider(
            "Minimum Coverage %",
            min_value=0.0,
            max_value=100.0,
            value=0.0,
            step=1.0,
            help="Filter groups by minimum coverage percentage"
        )
    
    with col2:
        search_term = st.text_input(
            "Search Group",
            placeholder="Search by name or ID...",
            help="Filter groups by name or ID"
        )
    
    with col3:
        sort_by = st.selectbox(
            "Sort By",
            ["Coverage % (Lowest First)", "Coverage % (Highest First)", "Total Techniques", "Group Name"],
            help="Sort the results"
        )
    
    # Apply filters
    filtered_df = df.copy()
    
    if min_coverage > 0:
        filtered_df = filtered_df[filtered_df['Coverage %'] >= min_coverage]
    
    if search_term:
        search_lower = search_term.lower()
        filtered_df = filtered_df[
            filtered_df['Group Name'].str.lower().str.contains(search_lower, na=False) |
            filtered_df['Group ID'].str.lower().str.contains(search_lower, na=False) |
            filtered_df['Aliases'].str.lower().str.contains(search_lower, na=False)
        ]
    
    # Apply sorting
    if sort_by == "Coverage % (Lowest First)":
        filtered_df = filtered_df.sort_values('Coverage %', ascending=True)
    elif sort_by == "Coverage % (Highest First)":
        filtered_df = filtered_df.sort_values('Coverage %', ascending=False)
    elif sort_by == "Total Techniques":
        filtered_df = filtered_df.sort_values('Total Techniques', ascending=False)
    elif sort_by == "Group Name":
        filtered_df = filtered_df.sort_values('Group Name', ascending=True)
    
    st.info(f"📊 Showing {len(filtered_df)} of {len(df)} groups")
    
    # Visualizations
    tab1, tab2, tab3 = st.tabs(["📊 Coverage Overview", "📋 Detailed Table", "🔍 Group Details"])
    
    with tab1:
        col1, col2 = st.columns(2)
        
        with col1:
            # Coverage distribution histogram
            fig_hist = px.histogram(
                filtered_df,
                x='Coverage %',
                nbins=20,
                title="Coverage Distribution",
                labels={'Coverage %': 'Coverage Percentage', 'count': 'Number of Groups'},
                color_discrete_sequence=['#667eea']
            )
            fig_hist.update_layout(height=400)
            st.plotly_chart(fig_hist, width='stretch')
        
        with col2:
            # Top 20 groups by coverage
            top_groups = filtered_df.head(20) if sort_by.startswith("Coverage % (Lowest") else filtered_df.tail(20)
            fig_bar = px.bar(
                top_groups,
                x='Coverage %',
                y='Group Name',
                orientation='h',
                title="Top 20 Groups by Coverage",
                color='Coverage %',
                color_continuous_scale='RdYlGn',
                labels={'Coverage %': 'Coverage %', 'Group Name': 'Group'}
            )
            fig_bar.update_layout(height=400, yaxis={'categoryorder': 'total ascending'})
            st.plotly_chart(fig_bar, width='stretch')
        
        # Coverage vs Total Techniques scatter
        fig_scatter = px.scatter(
            filtered_df,
            x='Total Techniques',
            y='Coverage %',
            size='Covered',
            color='Coverage %',
            hover_data=['Group Name', 'Group ID'],
            title="Coverage vs Total Techniques",
            color_continuous_scale='RdYlGn',
            labels={'Total Techniques': 'Total Techniques Used by Group', 'Coverage %': 'Coverage Percentage'}
        )
        fig_scatter.update_layout(height=400)
        st.plotly_chart(fig_scatter, width='stretch')
    
    with tab2:
        # Display table (without uncovered techniques and STIX ID columns for readability)
        display_df = filtered_df[['Group ID', 'Group Name', 'Total Techniques', 'Covered', 'Uncovered', 'Coverage %', 'Aliases']].copy()
        
        # Format coverage with color coding
        def format_coverage(val):
            if val == 100:
                return "🟢 100%"
            elif val >= 75:
                return f"🟡 {val}%"
            elif val >= 50:
                return f"🟠 {val}%"
            elif val > 0:
                return f"🔴 {val}%"
            else:
                return "⚫ 0%"
        
        display_df['Coverage %'] = display_df['Coverage %'].apply(format_coverage)
        
        st.dataframe(
            display_df,
            width='stretch',
            hide_index=True,
            height=600
        )
        
        # Download button
        csv = filtered_df[['Group ID', 'Group Name', 'Total Techniques', 'Covered', 'Uncovered', 'Coverage %']].to_csv(index=False)
        st.download_button(
            "📥 Download Coverage Report (CSV)",
            csv.encode('utf-8'),
            f"group_coverage_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.csv",
            "text/csv",
            width='stretch'
        )
    
    with tab3:
        # Group selector
        selected_group_id = st.selectbox(
            "Select a Group to View Details",
            options=filtered_df['Group ID'].tolist(),
            format_func=lambda x: f"{x} - {filtered_df[filtered_df['Group ID'] == x]['Group Name'].iloc[0]}",
            help="Select a group to see detailed coverage information"
        )
        
        if selected_group_id:
            group_info = filtered_df[filtered_df['Group ID'] == selected_group_id].iloc[0]
            
            st.subheader(f"📋 {group_info['Group Name']} ({group_info['Group ID']})")
            
            # Metrics
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Techniques", group_info['Total Techniques'])
            
            with col2:
                st.metric("Covered", group_info['Covered'], delta=f"{group_info['Coverage %']:.1f}%")
            
            with col3:
                st.metric("Uncovered", group_info['Uncovered'])
            
            with col4:
                if group_info['Group URL']:
                    st.markdown(f"[🔗 View on MITRE]({group_info['Group URL']})")
            
            if group_info['Aliases']:
                st.info(f"**Also known as:** {group_info['Aliases']}")
            
            # Software (tools & malware) from MITRE relationships for this group
            _g_stix = group_info.get("Group STIX ID")
            if not _g_stix:
                _match = [g for g in groups if g["attack_id"] == selected_group_id]
                _g_stix = _match[0]["id"] if _match else None
            if _g_stix:
                # Use module-level helper so stale cached MitreEngine instances still work
                software_list = list_software_for_group(mitre_engine.mitre_attack_data, _g_stix)
                st.subheader("🗂️ Software linked to this group")
                st.caption(
                    "Malware and tools the group is associated with in MITRE ATT&CK "
                    "(direct use, and software used by campaigns attributed to this group)."
                )
                if software_list:
                    sw_rows = []
                    for sw in software_list:
                        plat = ", ".join(sw["platforms"]) if sw.get("platforms") else "—"
                        sw_type = sw.get("type") or "—"
                        sw_rows.append(
                            {
                                "ID": sw.get("attack_id") or "—",
                                "Name": sw.get("name") or "—",
                                "Type": sw_type,
                                "Platforms": plat,
                                "MITRE": sw.get("url") or "",
                            }
                        )
                    sw_df = pd.DataFrame(sw_rows)
                    st.dataframe(
                        sw_df,
                        width="stretch",
                        hide_index=True,
                        column_config={
                            "MITRE": st.column_config.LinkColumn(
                                "MITRE page",
                                help="Open the software page on the MITRE ATT&CK site",
                                display_text="Open ↗",
                            ),
                        },
                    )
                else:
                    st.info(
                        "No software (tool/malware) objects are linked to this group in the loaded "
                        "MITRE data, or the group only has technique associations."
                    )
            
            # Techniques breakdown
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("✅ Covered Techniques")
                # Get STIX ID from the dataframe
                group_stix_id = group_info.get('Group STIX ID', None)
                if not group_stix_id:
                    # Fallback: find it from groups list
                    matching_groups = [g for g in groups if g['attack_id'] == selected_group_id]
                    group_stix_id = matching_groups[0]['id'] if matching_groups else None
                
                if group_stix_id:
                    all_group_techniques = mitre_engine.get_techniques_used_by_group(group_stix_id)
                    covered_list = [t for t in all_group_techniques if t in covered_techniques]
                else:
                    covered_list = []
                
                if covered_list:
                    for tech_id in sorted(covered_list):
                        tech_details = mitre_engine.get_technique_details(tech_id)
                        tech_name = tech_details.get('name', 'Unknown') if tech_details else 'Unknown'
                        st.success(f"**{tech_id}**: {tech_name}")
                else:
                    st.info("No techniques covered")
            
            with col2:
                st.subheader("❌ Uncovered Techniques")
                uncovered_list = group_info['Uncovered Techniques']
                
                if uncovered_list:
                    for tech_id in sorted(uncovered_list):
                        tech_details = mitre_engine.get_technique_details(tech_id)
                        tech_name = tech_details.get('name', 'Unknown') if tech_details else 'Unknown'
                        st.error(f"**{tech_id}**: {tech_name}")
                else:
                    st.success("All techniques are covered! 🎉")

finally:
    db.close()

# Add admin link at bottom of sidebar
st.sidebar.divider()
if st.sidebar.button("⚙️ Admin", width='stretch'):
    st.switch_page("pages/8_Admin.py")
"""Rules catalogue page."""
import streamlit as st
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified
from datetime import datetime
from db.session import SessionLocal
from db.repo import RuleRepository, RuleChangeLogRepository
from db.models import RuleImplementation
from services.auth import get_current_user, has_permission, login
from utils.hashing import compute_rule_hash
from utils.session_persistence import restore_session_state, persist_session_state

# Restore session state
restore_session_state()

st.set_page_config(page_title="Detection Rules", page_icon="📋", layout="wide")

st.title("📋 Detection Rules")
st.markdown("Manage and filter your detection rules. Select rules to run MITRE ATT&CK audits.")

# Get current user
username = get_current_user()
if not username:
    st.warning("Please login to access Rules")
    st.divider()
    
    # Login form
    with st.form("login_form"):
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

# Database session
db = SessionLocal()
try:
    # Function to check and tag rules that haven't been audited in 3 months
    def check_and_tag_stale_rules(db_session):
        """Check rules and add 'to_improve' tag if not audited in 3 months."""
        from datetime import datetime, timedelta
        
        three_months_ago = datetime.now() - timedelta(days=90)
        updated_count = 0
        
        all_rules_to_check = db_session.query(RuleImplementation).all()
        
        for rule in all_rules_to_check:
            needs_tag = False
            last_audit_date = None
            
            # Check last_audit_results for analyzed_at date
            if rule.last_audit_results:
                if isinstance(rule.last_audit_results, dict):
                    analyzed_at_str = rule.last_audit_results.get('analyzed_at')
                    if analyzed_at_str:
                        try:
                            # Parse ISO format date
                            if 'Z' in analyzed_at_str:
                                analyzed_at_str = analyzed_at_str.replace('Z', '+00:00')
                            last_audit_date = datetime.fromisoformat(analyzed_at_str.replace('Z', '+00:00'))
                            if last_audit_date < three_months_ago:
                                needs_tag = True
                        except Exception as e:
                            # If date parsing fails, consider it needs audit
                            needs_tag = True
                else:
                    # If last_audit_results exists but is not a dict, consider it needs audit
                    needs_tag = True
            else:
                # No audit results at all - needs audit
                needs_tag = True
            
            # Also check updated_at as fallback (if rule was updated more than 3 months ago)
            if not needs_tag and rule.updated_at:
                if rule.updated_at < three_months_ago:
                    # Check if there's no audit results, use updated_at as indicator
                    if not rule.last_audit_results:
                        needs_tag = True
            
            if needs_tag:
                # Get current tags
                current_tags = rule.tags if rule.tags else []
                if not isinstance(current_tags, list):
                    if isinstance(current_tags, str):
                        try:
                            import json
                            current_tags = json.loads(current_tags)
                        except:
                            current_tags = [current_tags] if current_tags else []
                    else:
                        current_tags = []
                
                # Add tag if not already present
                if 'to_improve' not in current_tags:
                    current_tags.append('to_improve')
                    rule.tags = current_tags
                    flag_modified(rule, "tags")
                    
                    try:
                        db_session.commit()
                        updated_count += 1
                    except Exception as e:
                        db_session.rollback()
        
        return updated_count
    
    # Check and tag stale rules (only once per session)
    if 'stale_rules_checked' not in st.session_state:
        with st.spinner("Checking for rules that need periodic review..."):
            updated = check_and_tag_stale_rules(db)
            if updated > 0:
                st.info(f"📅 {updated} rule(s) tagged with 'to_improve' (not audited in 3+ months)")
            st.session_state['stale_rules_checked'] = True
    
    # Get all rules to extract unique tags
    all_rules = db.query(RuleImplementation).all()
    all_tags = set()
    for rule in all_rules:
        # Extract tags from JSON field, handling different formats
        if rule.tags:
            rule_tags = rule.tags
            # Handle different formats: list, string, or None
            if isinstance(rule_tags, str):
                try:
                    import json
                    rule_tags = json.loads(rule_tags)
                except:
                    rule_tags = [rule_tags]
            elif not isinstance(rule_tags, list):
                rule_tags = []
            
            if isinstance(rule_tags, list):
                all_tags.update(rule_tags)
        
        # Also add platform and format as tags for filtering
        if rule.platform:
            all_tags.add(rule.platform)
        if rule.rule_format:
            all_tags.add(rule.rule_format)
    
    # Enhanced search and filters
    st.subheader("🔍 Search & Filter Rules")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        search_query = st.text_input("Search", placeholder="Search by rule name, query, or MITRE technique", help="Search across rule names, detection queries, and MITRE techniques")
    
    with col2:
        quick_filter = st.selectbox(
            "Quick Filter",
            ["All Rules", "With MITRE Technique", "Without MITRE Technique", "Splunk Rules", "Sigma Rules", "KQL Rules"],
            help="Quick filter presets"
        )
    
    # Advanced filters in expander
    with st.expander("🔧 Advanced Filters", expanded=False):
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            platform_filter = st.multiselect(
                "Platform(s)",
                options=sorted(list(set([r.platform for r in all_rules if r.platform]))),
                help="Filter by platform"
            )
        
        with col2:
            # Ensure 'to_improve' and 'to_update_mapping' are in the tag options
            tag_options = sorted(list(all_tags))
            if 'to_improve' not in tag_options:
                tag_options.append('to_improve')
            if 'to_update_mapping' not in tag_options:
                tag_options.append('to_update_mapping')
                tag_options = sorted(tag_options)
            
            tag_filter = st.multiselect(
                "Tags",
                options=tag_options,
                help="Filter by tags (e.g., 'to_improve' for rules needing improvement)"
            )
        
        with col3:
            format_filter = st.multiselect(
                "Rule Format",
                options=sorted(list(set([r.rule_format for r in all_rules if r.rule_format]))),
                help="Filter by rule format"
            )
        
        with col4:
            mitre_filter = st.text_input("MITRE Technique", placeholder="e.g., T1059.003", help="Filter by MITRE technique ID")

    # Filter for enabled rules by default (unless user wants to see disabled)
    show_disabled = st.sidebar.checkbox("Show Disabled Rules", value=False, help="Show rules that have been disabled")
    
    # Get all rules
    rules_query = db.query(RuleImplementation)
    
    # Filter by enabled status (only if column exists)
    try:
        if not show_disabled:
            # Check if enabled column exists by trying to filter
            rules_query = rules_query.filter(RuleImplementation.enabled == True)
    except Exception:
        # Column doesn't exist yet, show all rules
        pass
    
    # Apply search query
    if search_query:
        from sqlalchemy import or_
        rules_query = rules_query.filter(
            or_(
                RuleImplementation.rule_name.ilike(f"%{search_query}%"),
                RuleImplementation.rule_text.ilike(f"%{search_query}%"),
                RuleImplementation.mitre_technique_id.ilike(f"%{search_query}%")
            )
        )
    
    # Apply quick filter
    if quick_filter == "With MITRE Technique":
        rules_query = rules_query.filter(RuleImplementation.mitre_technique_id.isnot(None))
    elif quick_filter == "Without MITRE Technique":
        rules_query = rules_query.filter(RuleImplementation.mitre_technique_id.is_(None))
    elif quick_filter == "Splunk Rules":
        rules_query = rules_query.filter(RuleImplementation.rule_format == "splunk")
    elif quick_filter == "Sigma Rules":
        rules_query = rules_query.filter(RuleImplementation.rule_format == "sigma")
    elif quick_filter == "KQL Rules":
        rules_query = rules_query.filter(RuleImplementation.rule_format == "kql")
    
    # Apply platform filter
    if platform_filter:
        from sqlalchemy import or_
        conditions = []
        for platform in platform_filter:
            conditions.append(RuleImplementation.platform.ilike(f"%{platform}%"))
        if conditions:
            rules_query = rules_query.filter(or_(*conditions))
    
    # Apply tag filter (we'll filter tags in Python after fetching, since JSON filtering is complex)
    # Note: We don't apply SQL filters for tags here, as tags are stored in JSON and need Python filtering
    tag_filter_applied = False
    if tag_filter:
        tag_filter_applied = True
    
    # Apply format filter
    if format_filter:
        rules_query = rules_query.filter(RuleImplementation.rule_format.in_(format_filter))
    
    # Apply MITRE filter
    if mitre_filter:
        rules_query = rules_query.filter(RuleImplementation.mitre_technique_id.ilike(f"%{mitre_filter}%"))
    
    # Get all rules first (before pagination) if we need to filter by tags in Python
    if tag_filter_applied and tag_filter:
        # Get all rules to filter by tags (without pagination first)
        all_rules_for_tag_filter = rules_query.order_by(RuleImplementation.created_at.desc()).all()
        # Filter by tags in Python
        filtered_rules = []
        for rule in all_rules_for_tag_filter:
            rule_tags = rule.tags if rule.tags else []
            # Handle different formats: list, string, or None
            if rule_tags is None:
                rule_tags = []
            elif isinstance(rule_tags, str):
                # If it's a string, try to parse it as JSON
                try:
                    import json
                    rule_tags = json.loads(rule_tags)
                except:
                    rule_tags = [rule_tags]
            elif not isinstance(rule_tags, list):
                rule_tags = []
            
            # Also check platform and rule_format as potential tags
            all_rule_tags = list(rule_tags)
            if rule.platform:
                all_rule_tags.append(rule.platform)
            if rule.rule_format:
                all_rule_tags.append(rule.rule_format)
            
            # Check if any of the filter tags are in the rule's tags (including platform/format)
            if any(tag in all_rule_tags for tag in tag_filter):
                filtered_rules.append(rule)
        
        # Apply pagination after filtering
        page_size = 20
        page_num = st.session_state.get("rules_page", 1)
        total_rules = len(filtered_rules)
        start_idx = (page_num - 1) * page_size
        end_idx = start_idx + page_size
        rules = filtered_rules[start_idx:end_idx]
    else:
        # Normal pagination when no tag filter
        page_size = 20
        page_num = st.session_state.get("rules_page", 1)
        total_rules = rules_query.count()
        rules = rules_query.order_by(RuleImplementation.created_at.desc()).offset((page_num - 1) * page_size).limit(page_size).all()

    # Create new rule button
    if has_permission("create"):
        if st.session_state.get("create_rule", False):
            st.subheader("➕ Create New Rule")
            with st.form("create_rule_form"):
                from utils.platform_mapping import MITRE_PLATFORMS
                
                rule_name = st.text_input("Rule Name *", placeholder="e.g., Suspicious PowerShell Execution")
                
                # Enhanced query editor with code-like styling
                st.markdown("""
                <style>
                .query-editor-label {
                    font-size: 14px;
                    font-weight: 500;
                    margin-bottom: 8px;
                    color: #fafafa;
                }
                div[data-testid="stTextArea"] textarea {
                    font-family: 'Consolas', 'Monaco', 'Courier New', monospace !important;
                    font-size: 13px !important;
                    line-height: 1.5 !important;
                    background-color: #1e1e1e !important;
                    color: #d4d4d4 !important;
                    border: 1px solid #3c3c3c !important;
                    border-radius: 6px !important;
                    padding: 12px !important;
                }
                div[data-testid="stTextArea"] textarea:focus {
                    border-color: #007acc !important;
                    box-shadow: 0 0 0 2px rgba(0, 122, 204, 0.25) !important;
                }
                </style>
                """, unsafe_allow_html=True)
                
                rule_text = st.text_area(
                    "Detection Query/Logic *", 
                    placeholder='title: My Detection Rule\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 1\n  condition: selection',
                    height=300
                )
                
                col1, col2 = st.columns(2)
                with col1:
                    platforms = st.multiselect(
                        "Platform(s) *",
                        options=MITRE_PLATFORMS + ["Other (specify)"],
                        help="Select one or multiple platforms"
                    )
                    if "Other (specify)" in platforms:
                        platforms.remove("Other (specify)")
                        other_platform = st.text_input("Specify custom platform", placeholder="e.g., Custom Platform")
                        if other_platform:
                            platforms.append(other_platform)
                    platform = ", ".join(platforms) if platforms else ""
                    
                    rule_format = st.selectbox(
                        "Rule Format",
                        ["splunk", "sigma", "kql", "yara", "snort", "other"],
                        index=0
                    )
                
                with col2:
                    mitre_technique = st.text_input("MITRE Technique ID", placeholder="e.g., T1059.001")
                    tags_input = st.text_input("Tags (comma-separated)", placeholder="e.g., endpoint, execution, powershell")
                    tags_list = [t.strip() for t in tags_input.split(",")] if tags_input else []
                
                col_submit, col_cancel = st.columns(2)
                with col_submit:
                    submit = st.form_submit_button("Create", type="primary")
                with col_cancel:
                    cancel = st.form_submit_button("Cancel")
                
                if cancel:
                    st.session_state["create_rule"] = False
                    st.rerun()
                
                if submit:
                    if not rule_name or not rule_text or not platform:
                        st.error("Rule name, query, and platform are required")
                    else:
                        try:
                            # Compute hash with all parameters
                            rule_hash = compute_rule_hash(rule_text, platform, rule_format)
                            
                            # Create a default use case if needed
                            from db.repo import UseCaseRepository
                            default_ucs = UseCaseRepository.list_all(db, limit=1)
                            use_case_id = default_ucs[0].id if default_ucs else None
                            
                            if not use_case_id:
                                # Create a default use case for standalone rules
                                default_uc = UseCaseRepository.create(
                                    db,
                                    name="Default Rules Collection",
                                    description="Default collection for standalone rules",
                                    status="approved"
                                )
                                use_case_id = default_uc.id
                                db.commit()
                            
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
                                mitre_technique_id=mitre_technique if mitre_technique else None
                            )
                            
                            # Log to audit trail
                            RuleChangeLogRepository.log_create(
                                db, new_rule, username,
                                reason="Created from Rules page"
                            )
                            
                            st.success(f"Rule '{rule_name}' created successfully!")
                            st.session_state["create_rule"] = False
                            persist_session_state()
                            st.rerun()
                        except Exception as e:
                            st.error(f"Error creating rule: {e}")
        else:
            if st.button("➕ Create New Rule", type="primary"):
                st.session_state["create_rule"] = True
                persist_session_state()
                st.rerun()

    st.divider()
    
    # Display metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Rules", total_rules)
    with col2:
        st.metric("Filtered Rules", len(rules))
    with col3:
        unique_platforms = len(set([r.platform for r in all_rules if r.platform]))
        st.metric("Unique Platforms", unique_platforms)

    st.divider()

    # Display rules in a cleaner format
    if not rules:
        st.info("No rules found matching your filters. Create your first rule or adjust filters!")
    else:
        st.subheader(f"📋 Rules ({len(rules)} found)")
        
        # Bulk actions
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("➕ Add Selected to Audit", width='stretch', help="Select rules using checkboxes below"):
                if 'selected_rules' in st.session_state and st.session_state.selected_rules:
                    if 'manual_rules' not in st.session_state:
                        st.session_state.manual_rules = []
                    
                    for rule_id in st.session_state.selected_rules:
                        rule = RuleRepository.get_by_id(db, rule_id)
                        if rule:
                            # Get MITRE technique ID, handling None, empty string, and whitespace
                            mitre_id = rule.mitre_technique_id
                            if mitre_id:
                                mitre_id = str(mitre_id).strip()
                            else:
                                mitre_id = ''
                            
                            audit_rule = {
                                'Rule_Name': rule.rule_name,
                                'Query': rule.rule_text,
                                'Platform': rule.platform,
                                'Technique_ID': mitre_id,
                                'Tactic': '',
                                'Format': rule.rule_format or 'unknown'
                            }
                            st.session_state.manual_rules.append(audit_rule)
                    
                    st.success(f"Added {len(st.session_state.selected_rules)} rules to audit!")
                    st.session_state["audit_rules_added"] = True
                    st.switch_page("pages/2_Audit.py")
        
        # Initialize selected rules
        if 'selected_rules' not in st.session_state:
            st.session_state.selected_rules = []
        
        # Rules table view
        for rule in rules:
            # Check if this rule is being edited
            is_editing = st.session_state.get("show_edit_form") and st.session_state.get("edit_rule_id") == rule.id
            
            if is_editing:
                # Show edit form in place of the rule
                st.subheader("✏️ Edit Rule")
                with st.form(f"edit_rule_form_{rule.id}"):
                    from utils.platform_mapping import MITRE_PLATFORMS
                    
                    rule_name = st.text_input("Rule Name *", value=rule.rule_name, placeholder="e.g., Suspicious PowerShell Execution")
                    
                    # Enhanced query editor with code-like styling
                    st.markdown("""
                    <style>
                    .query-editor-label {
                        font-size: 14px;
                        font-weight: 500;
                        margin-bottom: 8px;
                        color: #fafafa;
                    }
                    div[data-testid="stTextArea"] textarea {
                        font-family: 'Consolas', 'Monaco', 'Courier New', monospace !important;
                        font-size: 13px !important;
                        line-height: 1.5 !important;
                        background-color: #1e1e1e !important;
                        color: #d4d4d4 !important;
                        border: 1px solid #3c3c3c !important;
                        border-radius: 6px !important;
                        padding: 12px !important;
                    }
                    div[data-testid="stTextArea"] textarea:focus {
                        border-color: #007acc !important;
                        box-shadow: 0 0 0 2px rgba(0, 122, 204, 0.25) !important;
                    }
                    </style>
                    """, unsafe_allow_html=True)
                    
                    rule_text = st.text_area(
                        "Detection Query/Logic *", 
                        value=rule.rule_text, 
                        placeholder='title: My Detection Rule\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 1\n  condition: selection',
                        height=300
                    )
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        # Parse existing platforms
                        existing_platforms = [p.strip() for p in rule.platform.split(",")] if rule.platform else []
                        platforms = st.multiselect(
                            "Platform(s) *",
                            options=MITRE_PLATFORMS + ["Other (specify)"],
                            default=[p for p in existing_platforms if p in MITRE_PLATFORMS],
                            help="Select one or multiple platforms"
                        )
                        if "Other (specify)" in platforms:
                            platforms.remove("Other (specify)")
                            other_platform = st.text_input("Specify custom platform", placeholder="e.g., Custom Platform", value=[p for p in existing_platforms if p not in MITRE_PLATFORMS][0] if any(p not in MITRE_PLATFORMS for p in existing_platforms) else "")
                            if other_platform:
                                platforms.append(other_platform)
                        platform = ", ".join(platforms) if platforms else ""
                        
                        rule_format = st.selectbox(
                            "Rule Format",
                            ["splunk", "sigma", "kql", "yara", "snort", "other"],
                            index=["splunk", "sigma", "kql", "yara", "snort", "other"].index(rule.rule_format) if rule.rule_format in ["splunk", "sigma", "kql", "yara", "snort", "other"] else 0
                        )
                    
                    with col2:
                        mitre_technique = st.text_input("MITRE Technique ID", value=rule.mitre_technique_id or "", placeholder="e.g., T1059.001")
                        tags_input = st.text_input("Tags (comma-separated)", value=", ".join(rule.tags) if rule.tags else "", placeholder="e.g., endpoint, execution, powershell")
                        tags_list = [t.strip() for t in tags_input.split(",")] if tags_input else []
                    
                    col_submit, col_cancel = st.columns(2)
                    with col_submit:
                        submit = st.form_submit_button("Save Changes", type="primary")
                    with col_cancel:
                        cancel = st.form_submit_button("Cancel")
                    
                    if cancel:
                        st.session_state["edit_rule_id"] = None
                        st.session_state["show_edit_form"] = False
                        persist_session_state()
                        st.rerun()
                    
                    if submit:
                        if not rule_name or not rule_text or not platform:
                            st.error("Rule name, query, and platform are required")
                        else:
                            try:
                                # Store previous state for audit log
                                previous_state = RuleChangeLogRepository._rule_to_dict(rule)
                                
                                # Compute new hash
                                rule_hash = compute_rule_hash(rule_text, platform, rule_format)
                                
                                # Update rule
                                updated_rule = RuleRepository.update(
                                    db,
                                    rule.id,
                                    platform=platform,
                                    rule_name=rule_name,
                                    rule_text=rule_text,
                                    rule_format=rule_format,
                                    rule_hash=rule_hash,
                                    tags=tags_list if tags_list else None,
                                    mitre_technique_id=mitre_technique if mitre_technique else None
                                )
                                
                                # Log to audit trail
                                if updated_rule:
                                    RuleChangeLogRepository.log_update(
                                        db, updated_rule, previous_state, username,
                                        reason="Edited from Rules page"
                                    )
                                
                                st.success(f"Rule '{rule_name}' updated successfully!")
                                st.session_state["edit_rule_id"] = None
                                st.session_state["show_edit_form"] = False
                                persist_session_state()
                                st.rerun()
                            except Exception as e:
                                st.error(f"Error updating rule: {e}")
                st.divider()
            else:
                # Normal rule display
                col_check, col_content, col_actions = st.columns([0.5, 4, 2])
                
                with col_check:
                    rule_selected = st.checkbox(
                        "Select",
                        key=f"select_{rule.id}",
                        value=rule.id in st.session_state.selected_rules,
                        label_visibility="hidden"
                    )
                    if rule_selected and rule.id not in st.session_state.selected_rules:
                        st.session_state.selected_rules.append(rule.id)
                    elif not rule_selected and rule.id in st.session_state.selected_rules:
                        st.session_state.selected_rules.remove(rule.id)
                
                with col_content:
                    # Rule header with key info
                    col_name, col_meta = st.columns([2, 1])
                    with col_name:
                        rule_title = rule.rule_name
                        # Add disabled indicator to title if disabled
                        if hasattr(rule, 'enabled') and rule.enabled is not None and not rule.enabled:
                            rule_title = f"~~{rule_title}~~ ⚠️ (Disabled)"
                        st.markdown(f"### {rule_title}")
                    with col_meta:
                        st.caption(f"📅 {rule.created_at.strftime('%Y-%m-%d')}")
                    
                    # Tags and metadata
                    rule_tags = []
                    # Handle tags in different formats
                    if rule.tags:
                        if isinstance(rule.tags, list):
                            rule_tags.extend(rule.tags)
                        elif isinstance(rule.tags, str):
                            try:
                                import json
                                rule_tags.extend(json.loads(rule.tags))
                            except:
                                rule_tags.append(rule.tags)
                    rule_tags.append(rule.platform)
                    if rule.rule_format:
                        rule_tags.append(rule.rule_format)
                    if rule_tags:
                        tags_str = " ".join([f"`{tag}`" for tag in set(rule_tags)])
                        st.markdown(tags_str)
                    
                    # MITRE technique badge (show all techniques if multi-mapping)
                    mitre_display = []
                    if rule.mitre_technique_ids and isinstance(rule.mitre_technique_ids, list):
                        mitre_display = rule.mitre_technique_ids
                    elif rule.mitre_technique_id:
                        mitre_display = [rule.mitre_technique_id]
                    
                    if mitre_display:
                        st.markdown(f"**MITRE:** `{', '.join(mitre_display)}`")
                    
                    # Show audit results if rule has 'to_improve' tag
                    # Handle tags in different formats
                    rule_tags_list = rule.tags if rule.tags else []
                    if isinstance(rule_tags_list, str):
                        try:
                            import json
                            rule_tags_list = json.loads(rule_tags_list)
                        except:
                            rule_tags_list = [rule_tags_list]
                    elif not isinstance(rule_tags_list, list):
                        rule_tags_list = []
                    
                    if rule_tags_list and 'to_improve' in rule_tags_list and rule.last_audit_results:
                        audit_data = rule.last_audit_results
                        if isinstance(audit_data, dict):
                            with st.expander("🔧 Improvement Recommendations", expanded=False):
                                if audit_data.get('gap_analysis') and audit_data.get('gap_analysis') != 'N/A':
                                    st.markdown("**📊 Gap Analysis:**")
                                    st.info(audit_data.get('gap_analysis', ''))
                                
                                if audit_data.get('improvement_suggestion') and audit_data.get('improvement_suggestion') != 'N/A':
                                    st.markdown("**💡 Improvement Suggestions:**")
                                    st.success(audit_data.get('improvement_suggestion', ''))
                                
                                if audit_data.get('pseudo_code_recommendation') and audit_data.get('pseudo_code_recommendation') != 'N/A':
                                    st.markdown("**💻 Recommended Detection Query:**")
                                    st.code(audit_data.get('pseudo_code_recommendation', ''), language="sql")
                                
                    # Get current mappings
                    current_mappings = []
                    if rule.mitre_technique_ids and isinstance(rule.mitre_technique_ids, list):
                        current_mappings = rule.mitre_technique_ids
                    elif rule.mitre_technique_id:
                        current_mappings = [rule.mitre_technique_id]
                    
                    # Auto-tag rules that need mapping review
                    # Only auto-tag if rule doesn't already have the tag (to avoid re-tagging after removal)
                    needs_mapping_review = False
                    has_tag_already = rule_tags_list and 'to_update_mapping' in rule_tags_list
                    
                    # Only check if rule needs review if it doesn't already have the tag
                    if not has_tag_already:
                        if len(current_mappings) == 0:
                            # Rule has no mapping - needs review
                            needs_mapping_review = True
                        else:
                            # Rule has mapping - check if it matches recommendations
                            mapping_analysis = rule.last_mapping_analysis if rule.last_mapping_analysis else None
                            if mapping_analysis and isinstance(mapping_analysis, dict):
                                accuracy = mapping_analysis.get("current_mapping_accuracy", "")
                                
                                # Check if current mapping matches recommendations
                                primary = mapping_analysis.get("primary_technique")
                                multi_mapping = mapping_analysis.get("multi_mapping", [])
                                
                                # If accuracy is incorrect/partially correct, needs review
                                if accuracy in ["Incorrect", "Partially Correct"]:
                                    needs_mapping_review = True
                                # If multi-mapping is recommended, check if it matches
                                elif multi_mapping and len(multi_mapping) > 0:
                                    recommended_tech_ids = set([tech.get("technique_id") for tech in multi_mapping if tech.get("technique_id")])
                                    current_tech_ids = set(current_mappings)
                                    # Only tag if mapping doesn't match recommendations
                                    if recommended_tech_ids != current_tech_ids:
                                        needs_mapping_review = True
                                # If primary is recommended, check if it's in current mappings
                                elif primary and primary.get("technique_id"):
                                    # Only tag if primary is not in current mappings
                                    if primary.get("technique_id") not in current_mappings:
                                        needs_mapping_review = True
                                # If accuracy is "Correct", don't tag (mapping is good)
                                elif accuracy == "Correct":
                                    needs_mapping_review = False
                    
                    # Auto-tag if needed (only if not already tagged)
                    if needs_mapping_review and not has_tag_already:
                        if not rule.tags:
                            rule.tags = []
                        elif not isinstance(rule.tags, list):
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
                            flag_modified(rule, "tags")
                            db.commit()
                            db.refresh(rule)  # Refresh to get updated tags
                            rule_tags_list = rule.tags  # Update local list
                    
                    # Show mapping review info if rule has mapping analysis or review history
                    # Only expand if rule is tagged for review
                    has_mapping_info = False
                    from db.models import MappingReview
                    latest_mapping_review = db.query(MappingReview).filter(
                        MappingReview.rule_id == rule.id
                    ).order_by(MappingReview.reviewed_at.desc()).first()
                    
                    mapping_analysis = rule.last_mapping_analysis if rule.last_mapping_analysis else None
                    
                    if mapping_analysis or latest_mapping_review:
                        has_mapping_info = True
                    
                    # Show mapping review section if there's mapping info
                    # Expand only if rule is tagged for review (closed by default)
                    is_tagged_for_review = rule_tags_list and 'to_update_mapping' in rule_tags_list
                    
                    if has_mapping_info:
                        from src.mitre_engine import MitreEngine
                        from services.mitre_coverage import get_mitre_engine
                        from services.auth import get_current_user
                        from datetime import datetime
                        
                        # Section is closed by default, only open if tagged for review
                        with st.expander("🎯 Mapping Review", expanded=is_tagged_for_review):
                            st.warning("⚠️ This rule needs MITRE mapping review.")
                            
                            # Show current mapping (use already computed current_mappings)
                            if current_mappings:
                                st.markdown(f"**Current Mapping:** {', '.join(current_mappings)}")
                            else:
                                st.markdown("**Current Mapping:** Not mapped")
                            
                            # Show analysis results and actions if available
                            if mapping_analysis and isinstance(mapping_analysis, dict):
                                primary = mapping_analysis.get("primary_technique")
                                alternative = mapping_analysis.get("alternative_technique")
                                multi_mapping = mapping_analysis.get("multi_mapping", [])
                                recommendation = mapping_analysis.get("recommendation", "")
                                
                                if recommendation:
                                    st.info(f"**💡 Recommendation:** {recommendation}")
                                
                                # Action buttons
                                action_col1, action_col2, action_col3 = st.columns(3)
                                
                                with action_col1:
                                    # Apply primary technique
                                    if primary and primary.get("technique_id"):
                                        current_user = get_current_user() or "system"
                                        mitre_engine = get_mitre_engine()
                                        can_modify_mapping = has_permission("update")
                                        
                                        if st.button(f"✅ Apply: {primary.get('technique_id')}", key=f"apply_primary_usecase_{rule.id}", width='stretch', disabled=not can_modify_mapping):
                                            # Store previous state for audit log
                                            previous_state = RuleChangeLogRepository._rule_to_dict(rule)
                                            
                                            # Get previous mapping
                                            previous_tech_id = rule.mitre_technique_id
                                            previous_tech_name = None
                                            if previous_tech_id:
                                                prev_details = mitre_engine.get_technique_details(previous_tech_id)
                                                previous_tech_name = prev_details.get('name', 'Unknown') if prev_details else 'Unknown'
                                            
                                            action_type = "add" if not previous_tech_id else "replace"
                                            
                                            # Update rule
                                            rule.mitre_technique_ids = [primary.get("technique_id")]
                                            rule.mitre_technique_id = primary.get("technique_id")
                                            
                                            # Remove tag
                                            if not rule.tags:
                                                rule.tags = []
                                            elif not isinstance(rule.tags, list):
                                                if isinstance(rule.tags, str):
                                                    try:
                                                        import json
                                                        rule.tags = json.loads(rule.tags)
                                                    except:
                                                        rule.tags = [rule.tags] if rule.tags else []
                                                else:
                                                    rule.tags = list(rule.tags) if rule.tags else []
                                            
                                            if 'to_update_mapping' in rule.tags:
                                                rule.tags.remove('to_update_mapping')
                                            
                                            # Update mapping analysis to reflect that mapping is now correct
                                            if rule.last_mapping_analysis and isinstance(rule.last_mapping_analysis, dict):
                                                rule.last_mapping_analysis["current_mapping_accuracy"] = "Correct"
                                                flag_modified(rule, "last_mapping_analysis")
                                            
                                            rule.updated_at = datetime.now()
                                            flag_modified(rule, "tags")
                                            flag_modified(rule, "mitre_technique_ids")
                                            
                                            # Create review history
                                            review = MappingReview(
                                                rule_id=rule.id,
                                                reviewed_by=current_user,
                                                previous_technique_id=previous_tech_id,
                                                previous_technique_name=previous_tech_name,
                                                action_type=action_type,
                                                new_technique_id=primary.get("technique_id"),
                                                new_technique_name=primary.get("technique_name", "Unknown"),
                                                ai_analysis=mapping_analysis,
                                                recommendation=recommendation
                                            )
                                            db.add(review)
                                            db.commit()
                                            db.refresh(rule)  # Refresh rule from database
                                            
                                            # Log to audit trail
                                            RuleChangeLogRepository.log_update(
                                                db, rule, previous_state, current_user,
                                                reason=f"Mapping {action_type}: {primary.get('technique_id')}"
                                            )
                                            
                                            st.success(f"✅ Mapping updated to {primary.get('technique_id')}")
                                            st.rerun()
                                
                                with action_col2:
                                    # Apply multi-mapping
                                    if multi_mapping and len(multi_mapping) > 0:
                                        multi_tech_ids = [tech.get("technique_id") for tech in multi_mapping if tech.get("technique_id")]
                                        can_modify_mapping = has_permission("update")
                                        if st.button(f"🔗 Multi-Map ({len(multi_tech_ids)})", key=f"apply_multi_usecase_{rule.id}", width='stretch', disabled=not can_modify_mapping):
                                            current_user = get_current_user() or "system"
                                            mitre_engine = get_mitre_engine()
                                            
                                            # Store previous state for audit log
                                            previous_state = RuleChangeLogRepository._rule_to_dict(rule)
                                            
                                            # Get previous mapping
                                            previous_tech_id = rule.mitre_technique_id
                                            previous_tech_name = None
                                            if previous_tech_id:
                                                prev_details = mitre_engine.get_technique_details(previous_tech_id)
                                                previous_tech_name = prev_details.get('name', 'Unknown') if prev_details else 'Unknown'
                                            
                                            # Update rule
                                            rule.mitre_technique_ids = multi_tech_ids
                                            rule.mitre_technique_id = multi_tech_ids[0] if multi_tech_ids else None
                                            
                                            # Remove tag (ensure tags is a list)
                                            if not rule.tags:
                                                rule.tags = []
                                            elif not isinstance(rule.tags, list):
                                                if isinstance(rule.tags, str):
                                                    try:
                                                        import json
                                                        rule.tags = json.loads(rule.tags)
                                                    except:
                                                        rule.tags = [rule.tags] if rule.tags else []
                                                else:
                                                    rule.tags = list(rule.tags) if rule.tags else []
                                            
                                            if 'to_update_mapping' in rule.tags:
                                                rule.tags.remove('to_update_mapping')
                                            
                                            # Update mapping analysis to reflect that mapping is now correct
                                            if rule.last_mapping_analysis and isinstance(rule.last_mapping_analysis, dict):
                                                rule.last_mapping_analysis["current_mapping_accuracy"] = "Correct"
                                                flag_modified(rule, "last_mapping_analysis")
                                            
                                            rule.updated_at = datetime.now()
                                            flag_modified(rule, "tags")
                                            flag_modified(rule, "mitre_technique_ids")
                                            
                                            # Create review history
                                            review = MappingReview(
                                                rule_id=rule.id,
                                                reviewed_by=current_user,
                                                previous_technique_id=previous_tech_id,
                                                previous_technique_name=previous_tech_name,
                                                action_type="multi-mapping",
                                                new_technique_id=multi_tech_ids[0] if multi_tech_ids else None,
                                                new_technique_name=multi_mapping[0].get("technique_name", "Unknown") if multi_mapping else "Unknown",
                                                additional_techniques=[{"technique_id": tech.get("technique_id"), "technique_name": tech.get("technique_name")} for tech in multi_mapping[1:] if tech.get("technique_id")],
                                                ai_analysis=mapping_analysis,
                                                recommendation=recommendation
                                            )
                                            db.add(review)
                                            db.commit()
                                            db.refresh(rule)  # Refresh rule from database
                                            
                                            # Log to audit trail
                                            RuleChangeLogRepository.log_update(
                                                db, rule, previous_state, current_user,
                                                reason=f"Multi-mapping: {', '.join(multi_tech_ids)}"
                                            )
                                            
                                            st.success(f"✅ Multi-mapping applied: {', '.join(multi_tech_ids)}")
                                            st.rerun()
                                
                                with action_col3:
                                    # Link to Mapping page for detailed analysis
                                    st.page_link("pages/3_Mapping.py", label="🎯 Go to Mapping Page", icon="🎯")
                            else:
                                # No analysis yet - show link to analyze
                                st.info("💡 **Action:** Go to the Mapping page to analyze and update the mapping.")
                                st.page_link("pages/3_Mapping.py", label="🎯 Analyze in Mapping Page", icon="🎯")
                            
                            # Show review history if available
                            if latest_mapping_review:
                                st.caption(f"📅 Last reviewed by {latest_mapping_review.reviewed_by} on {latest_mapping_review.reviewed_at.strftime('%Y-%m-%d %H:%M')}")
                            
                            # Show mapping analysis date if available
                            if mapping_analysis and isinstance(mapping_analysis, dict):
                                analyzed_at = mapping_analysis.get('analyzed_at')
                                if analyzed_at:
                                    try:
                                        if isinstance(analyzed_at, str):
                                            dt = datetime.fromisoformat(analyzed_at.replace('Z', '+00:00'))
                                            st.caption(f"📅 Mapping analyzed on: {dt.strftime('%Y-%m-%d %H:%M')}")
                                        else:
                                            st.caption(f"📅 Mapping analyzed: {analyzed_at}")
                                    except:
                                        st.caption(f"📅 Mapping analyzed: {analyzed_at}")
                    
                    # Preview of query
                    with st.expander("View Detection Query", expanded=False):
                        st.code(rule.rule_text, language="sql")
                
                with col_actions:
                    # Show enabled/disabled status
                    if hasattr(rule, 'enabled') and rule.enabled is not None and not rule.enabled:
                        st.warning("⚠️ Disabled")
                    
                    # Check if rule has to_improve tag to show "Mark as Improved" button
                    has_to_improve = rule_tags_list and 'to_improve' in rule_tags_list
                    
                    # Create compact icon-only buttons layout - all buttons on one line
                    num_cols = 4 if has_to_improve else 3
                    if has_permission("delete"):
                        num_cols += 1
                    if has_permission("update"):
                        num_cols += 1
                    
                    # Create columns dynamically with small gaps
                    cols = st.columns(num_cols, gap="small")
                    col_idx = 0
                    
                    # Edit button - icon only
                    if has_permission("update"):
                        with cols[col_idx]:
                            if st.button("✏️", key=f"edit_{rule.id}", type="secondary", width="content", help="Edit rule"):
                                # Set edit mode
                                st.session_state["edit_rule_id"] = rule.id
                                st.session_state["show_edit_form"] = True
                                # Clear create mode if active
                                st.session_state["create_rule"] = False
                                persist_session_state()
                                st.rerun()
                        col_idx += 1
                    
                    # Audit button - icon only
                    with cols[col_idx]:
                        if st.button("🛡️", key=f"audit_{rule.id}", type="secondary", width="content", help="Audit rule"):
                            # Add rule to audit session state
                            if 'manual_rules' not in st.session_state:
                                st.session_state.manual_rules = []
                            
                            # Convert rule to audit format
                            # Get MITRE technique ID, handling None, empty string, and whitespace
                            mitre_id = rule.mitre_technique_id
                            if mitre_id:
                                mitre_id = str(mitre_id).strip()
                            else:
                                mitre_id = ''
                            
                            audit_rule = {
                                'Rule_Name': rule.rule_name,
                                'Query': rule.rule_text,
                                'Platform': rule.platform,
                                'Technique_ID': mitre_id,
                                'Tactic': '',
                                'Format': rule.rule_format or 'unknown'
                            }
                            
                            # Add to manual rules for audit
                            st.session_state.manual_rules.append(audit_rule)
                            st.session_state["audit_rule_added"] = True
                            persist_session_state()
                            st.switch_page("pages/2_Audit.py")
                    col_idx += 1
                    
                    # Mark as Improved button - icon only (only if rule has to_improve tag)
                    if has_to_improve and has_permission("update"):
                        with cols[col_idx]:
                            if st.button("✅", key=f"mark_improved_{rule.id}", type="secondary", width="content", help="Mark as improved"):
                                try:
                                    # Store previous state for audit log
                                    previous_state = RuleChangeLogRepository._rule_to_dict(rule)
                                    
                                    # Ensure tags is a list
                                    if not rule.tags:
                                        rule.tags = []
                                    elif not isinstance(rule.tags, list):
                                        if isinstance(rule.tags, str):
                                            try:
                                                import json
                                                rule.tags = json.loads(rule.tags)
                                            except:
                                                rule.tags = [rule.tags] if rule.tags else []
                                        else:
                                            rule.tags = list(rule.tags) if rule.tags else []
                                    
                                    # Remove to_improve tag
                                    if 'to_improve' in rule.tags:
                                        rule.tags.remove('to_improve')
                                    
                                    # Update audit results status to indicate improvement is done
                                    if rule.last_audit_results and isinstance(rule.last_audit_results, dict):
                                        rule.last_audit_results['improvement_status'] = 'completed'
                                        rule.last_audit_results['improved_at'] = datetime.now().isoformat()
                                        flag_modified(rule, "last_audit_results")
                                    
                                    rule.updated_at = datetime.now()
                                    flag_modified(rule, "tags")
                                    db.commit()
                                    db.refresh(rule)
                                    
                                    # Log to audit trail
                                    RuleChangeLogRepository.log_update(
                                        db, rule, previous_state, username,
                                        reason="Marked as improved - tag 'to_improve' removed"
                                    )
                                    
                                    st.success(f"✅ Rule '{rule.rule_name}' marked as improved! Tag 'to_improve' removed.")
                                    st.rerun()
                                except Exception as e:
                                    st.error(f"❌ Error marking rule as improved: {e}")
                        col_idx += 1
                    
                    # Toggle Enable/Disable button - icon only
                    if has_permission("update"):
                        with cols[col_idx]:
                            rule_enabled = getattr(rule, 'enabled', True)
                            if rule_enabled is None:
                                rule_enabled = True
                            
                            toggle_icon = "🔴" if rule_enabled else "🟢"
                            toggle_help = "Disable rule" if rule_enabled else "Enable rule"
                            if st.button(toggle_icon, key=f"toggle_{rule.id}", type="secondary", width="content", help=toggle_help):
                                try:
                                    # Log to audit trail first (before the change)
                                    RuleChangeLogRepository.log_enable_disable(
                                        db, rule, username, not rule_enabled,
                                        reason=f"{'Disabled' if rule_enabled else 'Enabled'} from Rules page"
                                    )
                                    
                                    RuleRepository.update(db, rule.id, enabled=not rule_enabled)
                                    st.success(f"Rule {'disabled' if rule_enabled else 'enabled'} successfully!")
                                    persist_session_state()
                                    st.rerun()
                                except Exception as e:
                                    st.error(f"Error toggling rule: {e}")
                        col_idx += 1
                    
                    # Delete button - icon only
                    if has_permission("delete"):
                        with cols[col_idx]:
                            if st.button("🗑️", key=f"delete_{rule.id}", type="secondary", width="content", help="Delete rule"):
                                try:
                                    # Log to audit trail first (before deletion, so we have the full state)
                                    RuleChangeLogRepository.log_delete(
                                        db, rule, username,
                                        reason="Deleted from Rules page"
                                    )
                                    
                                    if RuleRepository.delete(db, rule.id):
                                        st.success(f"Rule '{rule.rule_name}' deleted successfully!")
                                        persist_session_state()
                                        st.rerun()
                                    else:
                                        st.error("Failed to delete rule")
                                except Exception as e:
                                    st.error(f"Error deleting rule: {e}")
                
                # Reduced spacing - use a thin line instead of divider
                st.markdown("---")
finally:
    db.close()

# Add admin link at bottom of sidebar
st.sidebar.divider()
if st.sidebar.button("⚙️ Admin", width='stretch'):
    st.switch_page("pages/8_Admin.py")


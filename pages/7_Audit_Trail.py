"""Audit Trail - View and rollback rule changes."""
import streamlit as st
import difflib
from datetime import datetime, timedelta, timezone
from db.session import SessionLocal
from db.models import RuleChangeLog, RuleImplementation
from db.repo import RuleChangeLogRepository, RuleRepository
from services.auth import get_current_user, has_permission, login


def generate_colored_diff(old_text: str, new_text: str) -> str:
    """Generate HTML diff with colored highlighting for changes."""
    if not old_text:
        old_text = ""
    if not new_text:
        new_text = ""
    
    old_lines = old_text.splitlines(keepends=True)
    new_lines = new_text.splitlines(keepends=True)
    
    diff = difflib.unified_diff(old_lines, new_lines, lineterm='')
    
    html_parts = []
    html_parts.append("""
    <style>
        .diff-container {
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 13px;
            background: #1e1e1e;
            border-radius: 8px;
            padding: 12px;
            overflow-x: auto;
            line-height: 1.5;
        }
        .diff-line {
            padding: 2px 8px;
            margin: 1px 0;
            border-radius: 3px;
            white-space: pre-wrap;
            word-break: break-all;
        }
        .diff-added {
            background-color: #1c4428;
            color: #7ee787;
            border-left: 3px solid #3fb950;
        }
        .diff-removed {
            background-color: #4c1d1d;
            color: #f85149;
            border-left: 3px solid #f85149;
        }
        .diff-context {
            color: #8b949e;
        }
        .diff-header {
            color: #58a6ff;
            font-weight: bold;
            margin-bottom: 8px;
        }
    </style>
    <div class="diff-container">
    """)
    
    has_changes = False
    for line in diff:
        if line.startswith('+++') or line.startswith('---'):
            continue
        elif line.startswith('@@'):
            html_parts.append(f'<div class="diff-line diff-header">{_escape_html(line.strip())}</div>')
            has_changes = True
        elif line.startswith('+'):
            html_parts.append(f'<div class="diff-line diff-added">+ {_escape_html(line[1:].rstrip())}</div>')
            has_changes = True
        elif line.startswith('-'):
            html_parts.append(f'<div class="diff-line diff-removed">- {_escape_html(line[1:].rstrip())}</div>')
            has_changes = True
        else:
            html_parts.append(f'<div class="diff-line diff-context">  {_escape_html(line.rstrip())}</div>')
    
    html_parts.append('</div>')
    
    if not has_changes:
        return None
    
    return ''.join(html_parts)


def generate_side_by_side_diff(old_text: str, new_text: str) -> str:
    """Generate HTML side-by-side diff with word-level highlighting."""
    if not old_text:
        old_text = ""
    if not new_text:
        new_text = ""
    
    old_lines = old_text.splitlines()
    new_lines = new_text.splitlines()
    
    # Use SequenceMatcher for line matching
    matcher = difflib.SequenceMatcher(None, old_lines, new_lines)
    
    html_parts = []
    html_parts.append("""
    <style>
        .side-diff-container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 12px;
        }
        .side-diff-panel {
            background: #1e1e1e;
            border-radius: 8px;
            padding: 12px;
            overflow-x: auto;
        }
        .side-diff-title {
            font-weight: bold;
            margin-bottom: 10px;
            padding-bottom: 8px;
            border-bottom: 1px solid #333;
        }
        .side-diff-title-old { color: #f85149; }
        .side-diff-title-new { color: #7ee787; }
        .side-line {
            padding: 2px 6px;
            margin: 1px 0;
            border-radius: 3px;
            white-space: pre-wrap;
            word-break: break-all;
            line-height: 1.4;
        }
        .side-added {
            background-color: #1c4428;
            color: #7ee787;
        }
        .side-removed {
            background-color: #4c1d1d;
            color: #f85149;
        }
        .side-unchanged {
            color: #8b949e;
        }
        .highlight-add {
            background-color: #2ea043;
            color: white;
            padding: 1px 3px;
            border-radius: 2px;
        }
        .highlight-remove {
            background-color: #da3633;
            color: white;
            padding: 1px 3px;
            border-radius: 2px;
        }
    </style>
    <div class="side-diff-container">
        <div class="side-diff-panel">
            <div class="side-diff-title side-diff-title-old">❌ BEFORE</div>
    """)
    
    # Process old lines
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == 'equal':
            for line in old_lines[i1:i2]:
                html_parts.append(f'<div class="side-line side-unchanged">{_escape_html(line)}</div>')
        elif tag == 'delete' or tag == 'replace':
            for line in old_lines[i1:i2]:
                html_parts.append(f'<div class="side-line side-removed">{_escape_html(line)}</div>')
        # Insert doesn't show in old panel
    
    html_parts.append("""
        </div>
        <div class="side-diff-panel">
            <div class="side-diff-title side-diff-title-new">✅ AFTER</div>
    """)
    
    # Process new lines
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == 'equal':
            for line in new_lines[j1:j2]:
                html_parts.append(f'<div class="side-line side-unchanged">{_escape_html(line)}</div>')
        elif tag == 'insert' or tag == 'replace':
            for line in new_lines[j1:j2]:
                html_parts.append(f'<div class="side-line side-added">{_escape_html(line)}</div>')
        # Delete doesn't show in new panel
    
    html_parts.append("""
        </div>
    </div>
    """)
    
    return ''.join(html_parts)


def _escape_html(text: str) -> str:
    """Escape HTML special characters."""
    return (text
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#39;'))

st.set_page_config(
    page_title="Audit Trail",
    page_icon="📜",
    layout="wide"
)

st.title("📜 Audit Trail")
st.markdown("""
**Complete History of Detection Rule Changes**

This page allows you to:
- View all modifications made to detection rules
- Filter by action type, user, or date
- Perform rollback (restore a previous version)
""")

# Authentication check
username = get_current_user()
if not username:
    st.warning("Please login to access Audit Trail")
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
                    st.error("Invalid username.")
            else:
                st.error("Please enter a username")
    
    st.info("💡 **Demo users:** admin, reviewer1, contributor1, reader1")
    st.stop()

# Permission check - admin can do everything, reviewer can view
can_view = has_permission("read")
can_rollback = has_permission("admin")

if not can_view:
    st.error("🔒 You don't have permission to view the audit trail.")
    st.stop()

# Filters sidebar
st.sidebar.header("🔍 Filters")

# Action filter
action_filter = st.sidebar.selectbox(
    "Action Type",
    ["All", "create", "update", "delete", "enable", "disable"],
    index=0
)

# User filter
db = SessionLocal()
try:
    # Get list of users who made changes
    all_changes_for_users = db.query(RuleChangeLog.changed_by).distinct().all()
    users_list = ["All"] + sorted(list(set([c[0] for c in all_changes_for_users if c[0]])))
    user_filter = st.sidebar.selectbox("User", users_list, index=0)
    
    # Date filter
    date_range = st.sidebar.selectbox(
        "Time Period",
        ["Last 24 hours", "Last 7 days", "Last 30 days", "All history"],
        index=1
    )
    
    # Calculate date range
    now = datetime.now(timezone.utc)
    if date_range == "Last 24 hours":
        from_date = now - timedelta(days=1)
    elif date_range == "Last 7 days":
        from_date = now - timedelta(days=7)
    elif date_range == "Last 30 days":
        from_date = now - timedelta(days=30)
    else:
        from_date = None
    
    # Build query parameters
    query_params = {
        "skip": 0,
        "limit": 100
    }
    
    if action_filter != "All":
        query_params["action"] = action_filter
    if user_filter != "All":
        query_params["changed_by"] = user_filter
    if from_date:
        query_params["from_date"] = from_date
    
    # Get changes
    changes = RuleChangeLogRepository.get_all_changes(db, **query_params)
    
    # Display metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("📊 Total Changes", len(changes))
    with col2:
        creates = len([c for c in changes if c.action == "create"])
        st.metric("➕ Creates", creates)
    with col3:
        updates = len([c for c in changes if c.action == "update"])
        st.metric("✏️ Updates", updates)
    with col4:
        deletes = len([c for c in changes if c.action == "delete"])
        st.metric("🗑️ Deletes", deletes)
    
    st.divider()
    
    if not changes:
        st.info("📭 No changes found for selected filters.")
    else:
        st.subheader(f"📋 Change History ({len(changes)} entries)")
        
        for change in changes:
            # Determine icon and color based on action
            action_icons = {
                "create": "➕",
                "update": "✏️",
                "delete": "🗑️",
                "enable": "🟢",
                "disable": "🔴"
            }
            action_icon = action_icons.get(change.action, "❓")
            
            # Format timestamp
            timestamp = change.changed_at.strftime("%Y-%m-%d %H:%M:%S")
            
            # Get rule name from state
            rule_name = "Unknown Rule"
            rule_id = change.rule_id
            
            if change.new_state and isinstance(change.new_state, dict):
                rule_name = change.new_state.get("rule_name", rule_name)
            elif change.previous_state and isinstance(change.previous_state, dict):
                rule_name = change.previous_state.get("rule_name", rule_name)
            
            # Check if this is a rollback
            rollback_badge = " 🔄 (Rollback)" if change.is_rollback else ""
            
            # Display change entry
            with st.expander(
                f"{action_icon} [{timestamp}] **{rule_name}** (ID: {rule_id}) - {change.action.upper()} by {change.changed_by}{rollback_badge}",
                expanded=False
            ):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**📝 Change Details:**")
                    st.write(f"- **Action:** {change.action}")
                    st.write(f"- **By:** {change.changed_by}")
                    st.write(f"- **Date:** {timestamp}")
                    if change.reason:
                        st.write(f"- **Reason:** {change.reason}")
                    
                    if change.is_rollback:
                        st.info(f"🔄 This is a rollback of change #{change.rollback_of_id}")
                
                with col2:
                    # Show changed fields
                    if change.changed_fields and isinstance(change.changed_fields, dict):
                        st.markdown("**🔀 Changed Fields:**")
                        query_changed = False
                        old_query = None
                        new_query = None
                        
                        for field, values in change.changed_fields.items():
                            if isinstance(values, dict):
                                old_val = values.get("old", "N/A")
                                new_val = values.get("new", "N/A")
                                
                                # Special handling for rule_text (query) - store for detailed display
                                if field == "rule_text":
                                    query_changed = True
                                    old_query = old_val
                                    new_query = new_val
                                    st.write(f"- **{field}:** Query modified (see details below)")
                                else:
                                    # Truncate long values for other fields
                                    if isinstance(old_val, str) and len(old_val) > 100:
                                        old_val = old_val[:100] + "..."
                                    if isinstance(new_val, str) and len(new_val) > 100:
                                        new_val = new_val[:100] + "..."
                                    st.write(f"- **{field}:** `{old_val}` → `{new_val}`")
                
                # Show query diff if rule_text was changed
                if change.changed_fields and isinstance(change.changed_fields, dict):
                    rule_text_change = change.changed_fields.get("rule_text")
                    if rule_text_change and isinstance(rule_text_change, dict):
                        st.divider()
                        st.markdown("**📝 Query Change Details:**")
                        
                        old_query = rule_text_change.get("old", "") or ""
                        new_query = rule_text_change.get("new", "") or ""
                        
                        # Display mode selector
                        view_mode = st.radio(
                            "View mode:",
                            ["Colored Diff", "Side by Side", "Raw"],
                            horizontal=True,
                            key=f"view_mode_{change.id}"
                        )
                        
                        if view_mode == "Colored Diff":
                            diff_html = generate_colored_diff(old_query, new_query)
                            if diff_html:
                                st.markdown(diff_html, unsafe_allow_html=True)
                            else:
                                st.info("No differences detected")
                        
                        elif view_mode == "Side by Side":
                            side_diff_html = generate_side_by_side_diff(old_query, new_query)
                            st.markdown(side_diff_html, unsafe_allow_html=True)
                        
                        else:  # Raw
                            query_col1, query_col2 = st.columns(2)
                            
                            with query_col1:
                                st.markdown("**Before:**")
                                if old_query:
                                    st.code(old_query, language="yaml")
                                else:
                                    st.info("No previous query")
                            
                            with query_col2:
                                st.markdown("**After:**")
                                if new_query:
                                    st.code(new_query, language="yaml")
                                else:
                                    st.info("Query removed")
                
                # State comparison
                if change.previous_state or change.new_state:
                    st.divider()
                    st.markdown("**📸 States:**")
                    
                    state_col1, state_col2 = st.columns(2)
                    
                    with state_col1:
                        st.markdown("**Before:**")
                        if change.previous_state:
                            # Display key fields
                            prev = change.previous_state
                            st.json({
                                "rule_name": prev.get("rule_name"),
                                "platform": prev.get("platform"),
                                "mitre_technique_id": prev.get("mitre_technique_id"),
                                "tags": prev.get("tags"),
                                "enabled": prev.get("enabled")
                            })
                        else:
                            st.info("No previous state (creation)")
                    
                    with state_col2:
                        st.markdown("**After:**")
                        if change.new_state:
                            # Display key fields
                            new = change.new_state
                            st.json({
                                "rule_name": new.get("rule_name"),
                                "platform": new.get("platform"),
                                "mitre_technique_id": new.get("mitre_technique_id"),
                                "tags": new.get("tags"),
                                "enabled": new.get("enabled")
                            })
                        else:
                            st.info("No after state (deletion)")
                
                # Rollback button (only for non-create actions and if user has permission)
                st.divider()
                if can_rollback:
                    if change.action in ["update", "delete", "enable", "disable"]:
                        if st.button(f"🔄 Rollback this change", key=f"rollback_{change.id}", type="primary"):
                            try:
                                rollback_reason = f"Rollback requested by {username}"
                                restored_rule = RuleChangeLogRepository.rollback_change(
                                    db, change.id, username, reason=rollback_reason
                                )
                                
                                if restored_rule:
                                    st.success(f"✅ Rollback successful! Rule restored: {restored_rule.rule_name}")
                                    st.rerun()
                                else:
                                    st.error("❌ Unable to perform rollback")
                            except Exception as e:
                                st.error(f"❌ Error during rollback: {e}")
                    elif change.action == "create":
                        st.info("💡 To undo a creation, use the Delete button in the Rules page.")
                else:
                    st.warning("🔒 You don't have permission to perform rollbacks ('admin' permission required)")
        
        # Pagination hint
        if len(changes) >= 100:
            st.info("📌 Display limited to the last 100 changes. Refine filters to see more details.")
    
    # Rule history section
    st.divider()
    st.subheader("📖 History for a Specific Rule")
    
    # Get all rules for selection
    all_rules = db.query(RuleImplementation).order_by(RuleImplementation.rule_name).all()
    
    if all_rules:
        rule_options = {f"{r.id}: {r.rule_name} ({r.platform})": r.id for r in all_rules}
        selected_rule_label = st.selectbox(
            "Select a rule",
            options=["-- Select --"] + list(rule_options.keys()),
            key="rule_history_select"
        )
        
        if selected_rule_label != "-- Select --":
            selected_rule_id = rule_options[selected_rule_label]
            
            rule_history = RuleChangeLogRepository.get_rule_history(db, selected_rule_id, limit=50)
            
            if rule_history:
                st.markdown(f"**📚 {len(rule_history)} change(s) for this rule:**")
                
                for change in rule_history:
                    action_icons = {
                        "create": "➕",
                        "update": "✏️",
                        "delete": "🗑️",
                        "enable": "🟢",
                        "disable": "🔴"
                    }
                    action_icon = action_icons.get(change.action, "❓")
                    timestamp = change.changed_at.strftime("%Y-%m-%d %H:%M:%S")
                    rollback_badge = " 🔄" if change.is_rollback else ""
                    
                    with st.expander(f"{action_icon} {timestamp} - {change.action.upper()} by {change.changed_by}{rollback_badge}"):
                        st.write(f"**Reason:** {change.reason or 'Not specified'}")
                        
                        if change.changed_fields and isinstance(change.changed_fields, dict):
                            st.markdown("**Changed Fields:**")
                            has_rule_text = False
                            for field, values in change.changed_fields.items():
                                if isinstance(values, dict):
                                    if field == "rule_text":
                                        has_rule_text = True
                                        st.write(f"- **{field}:** Query modified (see diff below)")
                                    else:
                                        old_val = values.get('old', 'N/A')
                                        new_val = values.get('new', 'N/A')
                                        # Truncate long values
                                        if isinstance(old_val, str) and len(old_val) > 80:
                                            old_val = old_val[:80] + "..."
                                        if isinstance(new_val, str) and len(new_val) > 80:
                                            new_val = new_val[:80] + "..."
                                        st.write(f"- **{field}:** `{old_val}` → `{new_val}`")
                            
                            # Show colored diff for rule_text
                            if has_rule_text:
                                rule_text_change = change.changed_fields.get("rule_text", {})
                                old_q = rule_text_change.get("old", "") or ""
                                new_q = rule_text_change.get("new", "") or ""
                                
                                st.markdown("**Query Diff:**")
                                diff_html = generate_colored_diff(old_q, new_q)
                                if diff_html:
                                    st.markdown(diff_html, unsafe_allow_html=True)
                                else:
                                    st.info("No differences detected")
                        
                        if can_rollback and change.action in ["update", "enable", "disable"]:
                            if st.button(f"🔄 Rollback", key=f"rollback_rule_{change.id}"):
                                try:
                                    restored_rule = RuleChangeLogRepository.rollback_change(
                                        db, change.id, username,
                                        reason=f"Rollback requested by {username}"
                                    )
                                    if restored_rule:
                                        st.success("✅ Rollback successful!")
                                        st.rerun()
                                except Exception as e:
                                    st.error(f"❌ Error: {e}")
            else:
                st.info("No history found for this rule.")
    else:
        st.info("No rules in catalogue.")

finally:
    db.close()

# Sidebar admin link
st.sidebar.divider()
if st.sidebar.button("⚙️ Admin", width='stretch'):
    st.switch_page("pages/8_Admin.py")

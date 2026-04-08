"""Admin page."""
import streamlit as st
from sqlalchemy import func, and_
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
from db.session import SessionLocal
from db.models import (
    RuleImplementation, RuleChangeLog, UseCase, 
    AiAuditResult, OfflineAuditResult, MappingReview
)
from services.auth import get_current_user, has_permission, load_rbac_config, require_sign_in
from services.feature_flags import load_feature_flags, save_feature_flags
from services.mitre_coverage import get_mitre_engine
from services.quota import set_quota_limit
from db.repo import QuotaRepository
from utils.time import get_current_period

st.set_page_config(page_title="Admin", page_icon="⚙️", layout="wide")

require_sign_in("the Admin page")
username = get_current_user()

st.title("⚙️ Administration")

if not has_permission("admin"):
    st.error("Admin access required")
    st.stop()

db = SessionLocal()
try:
    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        [
            "📊 System Statistics",
            "📈 Rule Quality Metrics",
            "🔒 RBAC",
            "🎛️ Platform",
            "📝 README Editor",
        ]
    )

    with tab1:
        col_header, col_refresh = st.columns([3, 1])
        with col_header:
            st.subheader("📊 System Statistics")
        with col_refresh:
            if st.button("🔄 Refresh", key="refresh_stats", help="Refresh statistics data"):
                st.rerun()
        
        # Overall metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            total_rules = db.query(RuleImplementation).count()
            enabled_rules = db.query(RuleImplementation).filter(RuleImplementation.enabled == True).count()
            st.metric("Total Rules", total_rules, delta=f"{enabled_rules} enabled")
        
        with col2:
            total_use_cases = db.query(UseCase).count()
            approved_use_cases = db.query(UseCase).filter(UseCase.status == "approved").count()
            st.metric("Use Cases", total_use_cases, delta=f"{approved_use_cases} approved")
        
        with col3:
            total_changes = db.query(RuleChangeLog).count()
            recent_changes = db.query(RuleChangeLog).filter(
                RuleChangeLog.changed_at >= datetime.now(timezone.utc) - timedelta(days=7)
            ).count()
            st.metric("Total Changes", total_changes, delta=f"{recent_changes} (7d)")
        
        with col4:
            total_users = len(load_rbac_config().get("users", {}))
            st.metric("Users", total_users)
        
        st.divider()
        
        # Rules by platform
        st.subheader("Rules by Platform")
        platform_stats = db.query(
            RuleImplementation.platform,
            func.count(RuleImplementation.id).label('count')
        ).group_by(RuleImplementation.platform).all()
        
        if platform_stats:
            col1, col2 = st.columns(2)
            with col1:
                platform_data = {p: c for p, c in platform_stats}
                st.bar_chart(platform_data)
            with col2:
                for platform, count in sorted(platform_stats, key=lambda x: x[1], reverse=True):
                    st.write(f"**{platform}**: {count} rules")
        
        # Rules by format
        st.subheader("Rules by Format")
        format_stats = db.query(
            RuleImplementation.rule_format,
            func.count(RuleImplementation.id).label('count')
        ).group_by(RuleImplementation.rule_format).all()
        
        if format_stats:
            col1, col2 = st.columns(2)
            with col1:
                format_data = {f or "Unknown": c for f, c in format_stats}
                st.bar_chart(format_data)
            with col2:
                for rule_format, count in sorted(format_stats, key=lambda x: x[1], reverse=True):
                    st.write(f"**{rule_format or 'Unknown'}**: {count} rules")
        
        # Recent activity
        st.divider()
        st.subheader("Recent Activity (Last 7 Days)")
        
        recent_changes_list = db.query(RuleChangeLog).filter(
            RuleChangeLog.changed_at >= datetime.now(timezone.utc) - timedelta(days=7)
        ).order_by(RuleChangeLog.changed_at.desc()).limit(10).all()
        
        if recent_changes_list:
            for change in recent_changes_list:
                action_icons = {
                    "create": "➕",
                    "update": "✏️",
                    "delete": "🗑️",
                    "enable": "🟢",
                    "disable": "🔴"
                }
                icon = action_icons.get(change.action, "❓")
                timestamp = change.changed_at.strftime("%Y-%m-%d %H:%M:%S")
                rule_name = "Unknown"
                if change.new_state and isinstance(change.new_state, dict):
                    rule_name = change.new_state.get("rule_name", rule_name)
                elif change.previous_state and isinstance(change.previous_state, dict):
                    rule_name = change.previous_state.get("rule_name", rule_name)
                
                st.write(f"{icon} **{change.action.upper()}** - {rule_name} by {change.changed_by} at {timestamp}")
        else:
            st.info("No recent activity")
        
        # AI Usage
        st.divider()
        st.subheader("AI Usage Statistics")
        
        total_ai_audits = db.query(AiAuditResult).count()
        recent_ai_audits = db.query(AiAuditResult).filter(
            AiAuditResult.run_at >= datetime.now(timezone.utc) - timedelta(days=30)
        ).count()
        
        if total_ai_audits > 0:
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total AI Audits", total_ai_audits)
            with col2:
                st.metric("Last 30 Days", recent_ai_audits)
            with col3:
                total_cost = db.query(func.sum(AiAuditResult.cost_estimate)).scalar() or 0
                st.metric("Total Cost (Est.)", f"${total_cost:.2f}")
        else:
            st.info("No AI audits performed yet")

    with tab2:
        col_header, col_refresh = st.columns([3, 1])
        with col_header:
            st.subheader("📈 Rule Quality Metrics")
        with col_refresh:
            if st.button("🔄 Refresh", key="refresh_metrics", help="Refresh metrics data"):
                st.rerun()
        
        # Load all rules once for consistent calculations
        all_rules = db.query(RuleImplementation).all()
        
        # Calculate metrics
        rules_to_improve = 0
        rules_to_update_mapping = 0
        rules_no_mapping = 0
        rules_with_mapping = 0
        multi_mapping_rules = 0
        unique_techniques = set()
        
        for rule in all_rules:
            # Check tags (tags is JSON, can be None, list, or empty list)
            tags = rule.tags or []
            if isinstance(tags, list):
                if "to_improve" in tags:
                    rules_to_improve += 1
                if "to_update_mapping" in tags:
                    rules_to_update_mapping += 1
            
            # Check MITRE mapping
            has_mapping = False
            if rule.mitre_technique_id:
                has_mapping = True
                unique_techniques.add(rule.mitre_technique_id)
            
            if rule.mitre_technique_ids:
                if isinstance(rule.mitre_technique_ids, list) and len(rule.mitre_technique_ids) > 0:
                    has_mapping = True
                    unique_techniques.update(rule.mitre_technique_ids)
                    if len(rule.mitre_technique_ids) > 1:
                        multi_mapping_rules += 1
            
            if has_mapping:
                rules_with_mapping += 1
            else:
                rules_no_mapping += 1
        
        total_rules = len(all_rules)
        mapping_coverage = (rules_with_mapping / total_rules * 100) if total_rules > 0 else 0
        disabled_rules = sum(1 for r in all_rules if not r.enabled)
        
        # Rules needing attention
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### Rules Requiring Attention")
            st.metric("🔧 To Improve", rules_to_improve)
            st.metric("🎯 To Update Mapping", rules_to_update_mapping)
            st.metric("❌ No MITRE Mapping", rules_no_mapping)
            st.metric("🔴 Disabled Rules", disabled_rules)
        
        with col2:
            st.markdown("### MITRE Coverage")
            
            # Calculate real MITRE framework coverage
            try:
                mitre_engine = get_mitre_engine()
                all_mitre_techniques = mitre_engine.mitre_attack_data.get_techniques(
                    include_subtechniques=True, 
                    remove_revoked_deprecated=True
                )
                total_mitre_techniques = len(all_mitre_techniques)
                mitre_framework_coverage = (len(unique_techniques) / total_mitre_techniques * 100) if total_mitre_techniques > 0 else 0
                
                st.metric(
                    "MITRE Framework Coverage", 
                    f"{mitre_framework_coverage:.1f}%", 
                    delta=f"{len(unique_techniques)}/{total_mitre_techniques} techniques"
                )
            except Exception as e:
                st.warning(f"Could not load MITRE data: {e}")
                st.metric("MITRE Framework Coverage", "N/A")
            
            st.metric("Rules with Mapping", f"{mapping_coverage:.1f}%", delta=f"{rules_with_mapping}/{total_rules} rules")
            st.metric("Multi-Mapping Rules", multi_mapping_rules)
            st.metric("Unique Techniques Covered", len(unique_techniques))
        
        st.divider()
        
        # Detailed lists
        st.subheader("Rules Needing Improvement")
        rules_to_improve_list = [r for r in all_rules if r.tags and isinstance(r.tags, list) and "to_improve" in r.tags][:10]
        
        if rules_to_improve_list:
            for rule in rules_to_improve_list:
                st.write(f"- **{rule.rule_name}** (ID: {rule.id}, Platform: {rule.platform})")
        else:
            st.success("✅ No rules need improvement!")
        
        st.subheader("Rules Without MITRE Mapping")
        rules_no_mapping_list = [r for r in all_rules if not r.mitre_technique_id and (not r.mitre_technique_ids or (isinstance(r.mitre_technique_ids, list) and len(r.mitre_technique_ids) == 0))][:10]
        
        if rules_no_mapping_list:
            for rule in rules_no_mapping_list:
                st.write(f"- **{rule.rule_name}** (ID: {rule.id}, Platform: {rule.platform})")
        else:
            st.success("✅ All rules have MITRE mappings!")

    with tab3:
        st.subheader("🔒 RBAC Configuration")
        st.info("RBAC is configured via config/rbac.yaml file. Edit the file to change user roles.")
        
        # Display current config
        config = load_rbac_config()
        
        st.json(config)
        
        # User summary
        st.divider()
        st.subheader("User Summary")
        
        users = config.get("users", {})
        if users:
            # Group by role
            role_counts = {}
            for username, user_data in users.items():
                role = user_data.get("role", "unknown")
                role_counts[role] = role_counts.get(role, 0) + 1
            
            col1, col2 = st.columns(2)
            with col1:
                st.bar_chart(role_counts)
            with col2:
                for role, count in sorted(role_counts.items(), key=lambda x: x[1], reverse=True):
                    st.write(f"**{role.title()}**: {count} user(s)")
            
            # User list
            st.markdown("### User List")
            user_data_list = []
            for username, user_data in users.items():
                user_data_list.append({
                    "Username": username,
                    "Role": user_data.get("role", "N/A"),
                    "Team": user_data.get("team", "N/A")
                })
            
            if user_data_list:
                import pandas as pd
                df = pd.DataFrame(user_data_list)
                st.dataframe(df, width='stretch', hide_index=True)

    with tab4:
        st.subheader("🎛️ Platform")
        st.caption("Operational switches and per-team AI run quotas for the current month.")

        flags = load_feature_flags()
        with st.form("feature_flags_form"):
            maint = st.text_area(
                "Maintenance banner (empty = off)",
                value=str(flags.get("maintenance_message") or ""),
                help="Shown on the home page and sidebar when non-empty.",
            )
            disable_ai = st.checkbox(
                "Disable AI globally",
                value=bool(flags.get("disable_ai_globally")),
                help="New AIEngine instances will raise; turn off for maintenance or policy.",
            )
            if st.form_submit_button("Save platform settings", type="primary"):
                save_feature_flags(
                    {
                        "maintenance_message": maint.strip(),
                        "disable_ai_globally": disable_ai,
                    }
                )
                st.success("Platform settings saved to `config/feature_flags.yaml`.")
                st.rerun()

        st.divider()
        st.subheader("AI quota by team (current period)")
        period = get_current_period()
        st.caption(f"Period: **{period}** (YYYY-MM, UTC)")

        teams = sorted(
            {
                (u.get("team") or "").strip()
                for u in load_rbac_config().get("users", {}).values()
                if isinstance(u, dict) and (u.get("team") or "").strip()
            }
        )
        if not teams:
            teams = ["security", "soc"]

        for team in teams:
            q = QuotaRepository.get_or_create(db, period, team)
            c1, c2, c3 = st.columns([2, 1, 1])
            with c1:
                st.write(f"**{team}** — used **{q.runs_used}** / limit **{q.runs_limit}**")
            with c2:
                new_lim = st.number_input(
                    f"Limit ({team})",
                    min_value=0,
                    max_value=1_000_000,
                    value=int(q.runs_limit),
                    key=f"quota_lim_{team}",
                )
            with c3:
                if st.button("Apply", key=f"quota_apply_{team}"):
                    set_quota_limit(db, team, int(new_lim))
                    st.success(f"Updated limit for {team}")
                    st.rerun()

    with tab5:
        st.subheader("📝 README Editor")
        st.info("Edit the README.md file directly from this interface. Changes are saved immediately.")
        
        readme_path = "README.md"
        
        # Load current README content
        try:
            with open(readme_path, 'r', encoding='utf-8') as f:
                current_content = f.read()
        except FileNotFoundError:
            st.error(f"README.md file not found at {readme_path}")
            current_content = ""
        except Exception as e:
            st.error(f"Error reading README.md: {e}")
            current_content = ""
        
        # Editor
        st.markdown("### Edit README.md")
        
        # Store in session state to detect changes
        if "readme_content" not in st.session_state:
            st.session_state["readme_content"] = current_content
        
        edited_content = st.text_area(
            "README Content",
            value=st.session_state["readme_content"],
            height=600,
            help="Edit the README.md content. Use Markdown syntax.",
            key="readme_editor"
        )
        
        col1, col2, col3 = st.columns([1, 1, 2])
        
        with col1:
            if st.button("💾 Save Changes", type="primary"):
                try:
                    with open(readme_path, 'w', encoding='utf-8') as f:
                        f.write(edited_content)
                    
                    st.session_state["readme_content"] = edited_content
                    st.success(f"✅ README.md saved successfully!")
                    
                    # Log the change
                    st.info(f"📝 File updated by {username} at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}")
                except Exception as e:
                    st.error(f"❌ Error saving README.md: {e}")
        
        with col2:
            if st.button("🔄 Reload from File"):
                try:
                    with open(readme_path, 'r', encoding='utf-8') as f:
                        reloaded_content = f.read()
                    st.session_state["readme_content"] = reloaded_content
                    st.success("✅ Content reloaded from file")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ Error reloading: {e}")
        
        with col3:
            if st.button("↩️ Reset to Original"):
                st.session_state["readme_content"] = current_content
                st.info("Content reset to original. Click 'Reload from File' to apply.")
                st.rerun()
        
        # Show file info
        st.divider()
        st.markdown("### File Information")
        try:
            import os
            file_stats = os.stat(readme_path)
            file_size = file_stats.st_size
            modified_time = datetime.fromtimestamp(file_stats.st_mtime, tz=timezone.utc)
            
            col_info1, col_info2, col_info3 = st.columns(3)
            with col_info1:
                st.metric("File Size", f"{file_size:,} bytes")
            with col_info2:
                st.metric("Last Modified", modified_time.strftime("%Y-%m-%d %H:%M:%S"))
            with col_info3:
                lines_count = len(edited_content.splitlines())
                st.metric("Lines", lines_count)
        except Exception as e:
            st.warning(f"Could not retrieve file stats: {e}")
        
        # Preview section
        st.divider()
        with st.expander("📄 Preview README (Markdown)", expanded=False):
            st.markdown(edited_content)
finally:
    db.close()

# Add admin link at bottom of sidebar (already on admin page, but keep for consistency)
st.sidebar.divider()
st.sidebar.caption("⚙️ Administration Page")

"""Detection engineering: playbook, dry-run, export pack, near-duplicate finder."""
import json
from datetime import datetime

import pandas as pd
import streamlit as st

from db.models import RuleImplementation, UseCase
from db.repo import RuleRepository, RuleChangeLogRepository
from db.session import SessionLocal
from services.auth import get_current_user, has_permission, require_sign_in
from utils.app_navigation import render_app_sidebar
from services.rule_dry_run import dry_run_event
from services.rule_export_pack import build_rules_export_zip
from services.rule_playbook import format_playbook_for_diff, normalize_playbook, playbook_from_form
from services.rule_similarity import find_similar_rules
from utils.session_persistence import restore_session_state

restore_session_state()

st.set_page_config(
    page_title="Detection engineering",
    page_icon="🧪",
    layout="wide",
)

require_sign_in("Detection engineering")
username = get_current_user()
render_app_sidebar(username)

if not has_permission("read"):
    st.error("Read permission required.")
    st.stop()

st.title("🧪 Detection engineering")
st.caption(
    "Per-rule playbook (FP, validation, escalation, contacts), JSON dry-run heuristic, "
    "packaged export (Sigma / Splunk / KQL + manifest), and text similarity for near-duplicates."
)

db = SessionLocal()
try:
    rules = db.query(RuleImplementation).order_by(RuleImplementation.rule_name).all()
    use_cases = {u.id: u for u in db.query(UseCase).all()}
    uc_titles = {uid: u.name for uid, u in use_cases.items()}

    tab_pb, tab_dry, tab_exp, tab_sim = st.tabs(
        ["Playbook", "Dry-run sample", "Export pack", "Near-duplicates"]
    )

    rule_labels = {f"{r.id} — {r.rule_name}": r.id for r in rules}
    rule_by_id = {r.id: r for r in rules}

    with tab_pb:
        st.subheader("Playbook per rule")
        if not rules:
            st.info("No rules yet — create rules in the catalogue.")
        else:
            pick = st.selectbox("Rule", options=list(rule_labels.keys()), key="pb_rule")
            rid = rule_labels[pick]
            rule = rule_by_id[rid]
            pb = normalize_playbook(getattr(rule, "playbook", None))
            can_write = has_permission("update")

            fp = st.text_area("False positive handling", value=pb["false_positive"], height=100, key="pb_fp")
            val = st.text_area("Validation steps", value=pb["validation"], height=100, key="pb_val")
            esc = st.text_area("Escalation", value=pb["escalation"], height=80, key="pb_esc")
            contacts_raw = st.text_area(
                "Contacts (JSON array)",
                value=json.dumps(pb["contacts"], indent=2) if pb["contacts"] else "[]",
                height=120,
                help='[{"name":"SOC L2","role":"On-call","channel":"#soc-l2"}]',
                key="pb_ct",
            )

            if can_write and st.button("Save playbook", type="primary", key="pb_save"):
                merged = playbook_from_form(fp, val, esc, contacts_raw)
                prev = RuleChangeLogRepository._rule_to_dict(rule)
                RuleRepository.update(db, rule.id, playbook=merged)
                rule = RuleRepository.get_by_id(db, rule.id)
                if rule:
                    RuleChangeLogRepository.log_update(
                        db,
                        rule,
                        prev,
                        username or "user",
                        reason="Playbook updated (Detection engineering)",
                    )
                st.success("Playbook saved.")
                st.rerun()
            elif not can_write:
                st.caption("Read-only — need **update** permission to save.")

            st.markdown("**Saved playbook (diff-friendly)**")
            rule_live = RuleRepository.get_by_id(db, rid)
            st.code(
                format_playbook_for_diff(
                    normalize_playbook(getattr(rule_live, "playbook", None) if rule_live else None)
                ),
                language="yaml",
            )

    with tab_dry:
        st.subheader("Dry-run vs sample event (heuristic)")
        st.caption(
            "Compares tokens extracted from the rule text with a JSON sample. "
            "Not a full query engine — use for quick triage only."
        )
        if not rules:
            st.info("No rules.")
        else:
            pick_d = st.selectbox("Rule", options=list(rule_labels.keys()), key="dry_rule")
            rid_d = rule_labels[pick_d]
            r_d = rule_by_id[rid_d]
            sample = st.text_area(
                "Sample event (JSON object)",
                value='{\n  "EventID": 4688,\n  "CommandLine": "powershell.exe -enc ABC"\n}',
                height=220,
                key="dry_json",
            )
            if st.button("Run dry-run", type="primary", key="dry_go"):
                try:
                    ev = json.loads(sample)
                except json.JSONDecodeError as e:
                    st.error(f"Invalid JSON: {e}")
                else:
                    res = dry_run_event(r_d.rule_text, r_d.rule_format, ev)
                    st.metric("Token overlap ratio", f"{res['match_ratio']:.0%}")
                    st.write(res.get("note", ""))
                    c1, c2 = st.columns(2)
                    with c1:
                        st.caption("Matched tokens (in sample)")
                        st.json(res.get("matched", []))
                    with c2:
                        st.caption("Sample of unmatched rule tokens")
                        st.json(res.get("unmatched_sample", []))

    with tab_exp:
        st.subheader("Export packaged rules")
        scope = st.radio(
            "Scope",
            ["All rules", "Selected formats only"],
            horizontal=True,
            key="exp_scope",
        )
        fmt_filter = None
        if scope == "Selected formats only":
            fmt_filter = st.multiselect(
                "Formats",
                ["sigma", "splunk", "kql", "yara", "snort", "other"],
                default=["sigma", "splunk", "kql"],
                key="exp_fmt",
            )
        to_export = list(rules)
        if fmt_filter:
            fl = [f.lower() for f in fmt_filter]
            to_export = [r for r in rules if (r.rule_format or "other").lower() in fl]

        st.caption(f"{len(to_export)} rule(s) in this export.")
        if to_export:
            data = build_rules_export_zip(to_export, uc_titles)
            st.download_button(
                label="Download rules_export.zip",
                data=data,
                file_name=f"detection_rules_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.zip",
                mime="application/zip",
                key="exp_dl",
            )

    with tab_sim:
        st.subheader("Near-duplicate rules (text similarity)")
        st.caption("Uses normalized string similarity — tune threshold; not semantic embeddings.")
        if len(rules) < 2:
            st.info("Need at least two rules.")
        else:
            pick_s = st.selectbox("Reference rule", options=list(rule_labels.keys()), key="sim_rule")
            rid_s = rule_labels[pick_s]
            r_s = rule_by_id[rid_s]
            thr = st.slider("Minimum similarity", 0.5, 1.0, 0.72, 0.01, key="sim_thr")
            if st.button("Find similar", type="primary", key="sim_go"):
                cand = [(x.id, x.rule_name, x.rule_text) for x in rules]
                found = find_similar_rules(r_s.rule_text, rid_s, cand, min_ratio=thr)
                if not found:
                    st.info("No other rules above the threshold.")
                else:
                    st.dataframe(pd.DataFrame(found), width="stretch", hide_index=True)

finally:
    db.close()

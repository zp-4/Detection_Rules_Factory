"""MITRE coverage: custom scopes, CTI campaigns, gaps, Navigator export."""
import json
from datetime import datetime

import pandas as pd
import streamlit as st
import yaml

from db.session import SessionLocal
from db.models import RuleImplementation
from services.auth import get_current_user, has_permission, require_sign_in
from utils.app_navigation import render_app_sidebar
from services.mitre_coverage import get_mitre_engine
from services.mitre_catalog import collect_covered_technique_ids
from services.mitre_coverage_config import (
    CONFIG_PATH,
    load_config,
    save_config,
    scope_technique_ids,
    campaign_by_id,
)
from utils.session_persistence import restore_session_state

restore_session_state()

st.set_page_config(
    page_title="MITRE coverage hub",
    page_icon="🎯",
    layout="wide",
)

require_sign_in("MITRE coverage hub")
render_app_sidebar(get_current_user() or "")
if not has_permission("read"):
    st.error("Read permission required.")
    st.stop()

st.title("🎯 MITRE coverage hub")
st.caption(
    "Define **scopes** (technique subsets) and **CTI campaigns** (named technique bundles), "
    "then measure catalogue coverage, gaps, and export Navigator layers."
)

db = SessionLocal()
try:
    all_rules = db.query(RuleImplementation).all()
    covered = collect_covered_technique_ids(all_rules)

    try:
        mitre_engine = get_mitre_engine()
        mad = mitre_engine.mitre_attack_data
        all_ent = mad.get_techniques(
            include_subtechniques=True, remove_revoked_deprecated=True
        )
        enterprise_ids = set()
        for obj in all_ent:
            for r in getattr(obj, "external_references", []) or []:
                if getattr(r, "source_name", None) == "mitre-attack" and getattr(
                    r, "external_id", None
                ):
                    enterprise_ids.add(r.external_id)
                    break
    except Exception as e:
        st.error(f"MITRE engine: {e}")
        st.stop()

    cfg = load_config()

    tab_cfg, tab_cov, tab_road, tab_nav = st.tabs(
        ["Scopes & campaigns", "Coverage vs bundle", "Roadmap (gaps)", "Navigator export"]
    )

    with tab_cfg:
        st.subheader("Configuration file")
        st.caption(f"Path: `{CONFIG_PATH}`")
        _cfg_dump = yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False)
        raw_yaml = st.text_area(
            "YAML",
            value=_cfg_dump,
            height=420,
        )
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Validate & save", type="primary"):
                try:
                    parsed = yaml.safe_load(raw_yaml)
                    if not isinstance(parsed, dict):
                        raise ValueError("Root must be a mapping")
                    if "scopes" not in parsed or "campaigns" not in parsed:
                        raise ValueError("Need `scopes` and `campaigns` keys")
                    save_config(parsed)
                    st.success("Saved.")
                    st.rerun()
                except Exception as ex:
                    st.error(str(ex))
        with c2:
            st.markdown(
                "**Scopes:** keys under `scopes` → `technique_ids` list (empty = full enterprise). "
                "**Campaigns:** list of `{id, name, technique_ids: [T...]}`."
            )

    def target_set(mode: str, key: str) -> set:
        if mode == "Full enterprise":
            return set(enterprise_ids)
        if mode == "Scope":
            ids = scope_technique_ids(cfg, key)
            return set(ids) if ids else set(enterprise_ids)
        if mode == "Campaign":
            c = campaign_by_id(cfg, key)
            if not c:
                return set()
            t = c.get("technique_ids") or []
            return {str(x).strip() for x in t if str(x).strip()}
        return set()

    scope_keys = list((cfg.get("scopes") or {}).keys())
    camp_list = cfg.get("campaigns") or []
    camp_ids = [str(c.get("id")) for c in camp_list if isinstance(c, dict) and c.get("id")]

    with tab_cov:
        st.subheader("Coverage vs selected universe")
        mode = st.radio(
            "Universe",
            ["Full enterprise", "Scope", "Campaign"],
            horizontal=True,
        )
        sel = ""
        if mode == "Scope":
            sel = st.selectbox("Scope", options=scope_keys or ["enterprise_full"])
        elif mode == "Campaign":
            if not camp_ids:
                st.warning("Define at least one campaign in the **Scopes & campaigns** tab.")
                sel = ""
            else:
                sel = st.selectbox("Campaign", options=camp_ids)
        tgt = target_set(mode, sel)
        if not tgt:
            st.warning("Empty target set. Check configuration.")
        else:
            hit = covered & tgt
            pct = 100.0 * len(hit) / len(tgt) if tgt else 0.0
            m1, m2, m3 = st.columns(3)
            m1.metric("Target techniques", len(tgt))
            m2.metric("Covered by rules", len(hit))
            m3.metric("Coverage", f"{pct:.1f}%")
            gap = sorted(tgt - hit)
            st.write(f"**Gap count:** {len(gap)}")
            if gap[:40]:
                st.dataframe(pd.DataFrame({"technique_id": gap[:200]}), hide_index=True)

    with tab_road:
        st.subheader("Roadmap — gap prioritization")
        st.caption(
            "Lists uncovered techniques in the selected universe. "
            "Sort is by technique ID; refine priority in your PM tool."
        )
        mode_r = st.radio(
            "Universe",
            ["Full enterprise", "Scope", "Campaign"],
            horizontal=True,
            key="road_mode",
        )
        sel_r = ""
        if mode_r == "Scope":
            sel_r = st.selectbox(
                "Scope", options=scope_keys or ["enterprise_full"], key="road_scope"
            )
        elif mode_r == "Campaign":
            if not camp_ids:
                st.warning("Add a campaign in the configuration tab.")
                sel_r = ""
            else:
                sel_r = st.selectbox("Campaign", options=camp_ids, key="road_camp")
        tgt_r = target_set(mode_r, sel_r)
        gap_r = sorted(tgt_r - covered) if tgt_r else []
        rows = []
        for tid in gap_r[:500]:
            det = mitre_engine.get_technique_details(tid)
            rows.append(
                {
                    "technique_id": tid,
                    "name": det.get("name") or "—",
                    "platforms": ", ".join((det.get("platforms") or [])[:4]),
                }
            )
        if rows:
            st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
            st.download_button(
                "Download gaps CSV",
                pd.DataFrame(rows).to_csv(index=False).encode("utf-8"),
                f"mitre_gaps_{datetime.utcnow().strftime('%Y%m%d')}.csv",
                "text/csv",
            )
        else:
            st.success("No gaps in this universe (or empty selection).")

    with tab_nav:
        st.subheader("Navigator layer (subset)")
        st.caption(
            "Layer includes techniques from the selected universe that are covered by at least one rule."
        )
        mode_n = st.radio(
            "Universe",
            ["Full enterprise", "Scope", "Campaign"],
            horizontal=True,
            key="nav_mode",
        )
        sel_n = ""
        if mode_n == "Scope":
            sel_n = st.selectbox(
                "Scope", options=scope_keys or ["enterprise_full"], key="nav_scope"
            )
        elif mode_n == "Campaign":
            if not camp_ids:
                st.warning("Add a campaign in the configuration tab.")
                sel_n = ""
            else:
                sel_n = st.selectbox("Campaign", options=camp_ids, key="nav_camp")
        tgt_n = target_set(mode_n, sel_n)
        vis = sorted((covered & tgt_n) if tgt_n else covered)
        techniques_list = []
        for tech_id in vis:
            techniques_list.append(
                {
                    "techniqueID": tech_id,
                    "score": 1,
                    "enabled": True,
                    "comment": "Covered by Detection Rules Factory catalogue",
                }
            )
        if techniques_list:
            layer = {
                "name": f"DRF coverage {datetime.utcnow().strftime('%Y-%m-%d')}",
                "versions": {"attack": "18", "navigator": "4.9.0", "layer": "4.4"},
                "domain": "enterprise-attack",
                "description": f"{len(techniques_list)} techniques",
                "techniques": techniques_list,
                "gradient": {
                    "colors": ["#ff6666", "#ffe766", "#8ec843"],
                    "minValue": 0,
                    "maxValue": 1,
                },
                "showTacticRowBackground": False,
                "selectTechniquesAcrossTactics": True,
                "selectSubtechniquesWithParent": True,
            }
            st.download_button(
                "Download Navigator JSON",
                json.dumps(layer, indent=2).encode("utf-8"),
                f"mitre_layer_subset_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json",
                "application/json",
            )
        else:
            st.info("No techniques to export for this selection.")

finally:
    db.close()

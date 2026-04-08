"""CTI library, rule↔source traceability, local IOC parsing."""
import pandas as pd
import streamlit as st

from db.models import RuleImplementation
from db.repo import CtiLibraryRepository, RuleChangeLogRepository, RuleRepository
from db.session import SessionLocal
from services.auth import get_current_user, has_permission, require_sign_in
from services.cti_ioc import parse_iocs_from_text
from services.cti_refs import build_cti_refs_from_entry_ids, normalize_cti_refs
from utils.session_persistence import restore_session_state

restore_session_state()

st.set_page_config(page_title="CTI library", page_icon="📚", layout="wide")

require_sign_in("CTI library")
username = get_current_user() or ""

if not has_permission("read"):
    st.error("Read permission required.")
    st.stop()

st.title("📚 CTI library & traceability")
st.caption(
    "Reusable CTI sources (metadata + excerpt), link catalogue rules to sources, "
    "and parse IOCs locally (no external enrichment APIs)."
)

db = SessionLocal()
try:
    tab_lib, tab_trace, tab_ioc = st.tabs(["Library", "Rule links", "IOC parse (local)"])

    with tab_lib:
        st.subheader("Reusable sources")
        can_write = has_permission("create") or has_permission("update")
        rows = CtiLibraryRepository.list_all(db, limit=400)
        if rows:
            df = pd.DataFrame(
                [
                    {
                        "id": r.id,
                        "title": r.title,
                        "kind": r.source_kind,
                        "url": (r.url or "")[:80],
                        "tags": ", ".join(r.tags) if r.tags else "",
                        "updated": r.updated_at,
                    }
                    for r in rows
                ]
            )
            st.dataframe(df, width="stretch", hide_index=True)
        else:
            st.info("No entries yet — add one below or from the CTI Detection page.")

        if can_write:
            with st.expander("Add entry", expanded=not rows):
                t_title = st.text_input("Title", key="cti_new_title")
                t_kind = st.selectbox("Source kind", ["paste", "url", "file_excerpt"], key="cti_new_kind")
                t_url = st.text_input("URL (optional)", key="cti_new_url")
                t_ex = st.text_area("Excerpt / content", height=180, key="cti_new_ex")
                t_tags = st.text_input("Tags (comma-separated)", key="cti_new_tags")
                t_vendor = st.text_input("Vendor / report (metadata)", key="cti_new_vendor")
                if st.button("Save entry", type="primary", key="cti_new_save"):
                    if not t_title.strip() or not t_ex.strip():
                        st.error("Title and excerpt are required.")
                    else:
                        tags = [x.strip() for x in t_tags.split(",") if x.strip()]
                        meta = {}
                        if t_vendor.strip():
                            meta["vendor"] = t_vendor.strip()
                        CtiLibraryRepository.create(
                            db,
                            title=t_title.strip()[:500],
                            source_kind=t_kind,
                            url=t_url.strip() or None,
                            excerpt_text=t_ex[:200000],
                            source_metadata=meta or None,
                            tags=tags or None,
                            created_by=username or None,
                        )
                        st.success("Saved.")
                        st.rerun()
        else:
            st.caption("Need **create** or **update** permission to add entries.")

    with tab_trace:
        st.subheader("Link rules to CTI sources")
        all_rules = db.query(RuleImplementation).order_by(RuleImplementation.rule_name).all()
        entries = CtiLibraryRepository.list_all(db, limit=400)
        if not all_rules:
            st.info("No rules in catalogue.")
        elif not entries:
            st.info("Add CTI library entries first.")
        else:
            r_labels = {f"{r.id} — {r.rule_name}": r.id for r in all_rules}
            e_labels = {f"{e.id} — {e.title}": e.id for e in entries}
            pick_r = st.selectbox("Rule", options=list(r_labels.keys()), key="tr_rule")
            rid = r_labels[pick_r]
            rule = RuleRepository.get_by_id(db, rid)
            cur = normalize_cti_refs(getattr(rule, "cti_refs", None))
            pre = [f"{x['cti_entry_id']} — {next((e.title for e in entries if e.id == x['cti_entry_id']), '?')}" for x in cur]
            st.caption("Current links: " + (", ".join(pre) if pre else "none"))
            sel = st.multiselect(
                "CTI sources to attach",
                options=list(e_labels.keys()),
                default=[k for k in e_labels if e_labels[k] in {x["cti_entry_id"] for x in cur}],
                key="tr_sel",
            )
            note = st.text_input("Note for new links", key="tr_note")
            if has_permission("update") and st.button("Save links", type="primary", key="tr_save"):
                ids = [e_labels[k] for k in sel if k in e_labels]
                new_refs = build_cti_refs_from_entry_ids(ids, note)
                prev = RuleChangeLogRepository._rule_to_dict(rule)
                RuleRepository.update(db, rid, cti_refs=new_refs)
                rule2 = RuleRepository.get_by_id(db, rid)
                if rule2:
                    RuleChangeLogRepository.log_update(
                        db,
                        rule2,
                        prev,
                        username,
                        reason="CTI traceability updated",
                    )
                st.success("Updated.")
                st.rerun()

    with tab_ioc:
        st.subheader("IOC extraction (local heuristics)")
        st.warning(
            "**Internal use only.** No live lookups — parsing and IP classification use the standard library only."
        )
        raw = st.text_area("Paste indicators (one per line or free text)", height=220, key="ioc_raw")
        if st.button("Parse", type="primary", key="ioc_go"):
            found = parse_iocs_from_text(raw)
            if not found:
                st.info("No IOC-like tokens detected.")
            else:
                st.dataframe(pd.DataFrame(found), width="stretch", hide_index=True)

finally:
    db.close()

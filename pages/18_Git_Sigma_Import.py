"""Import Sigma rules from a public Git repository (shallow clone)."""
import streamlit as st

from db.session import SessionLocal
from db.repo import UseCaseRepository
from services.auth import get_current_user, has_permission, require_sign_in
from utils.app_navigation import render_app_sidebar
from services.sigma_git_import import import_sigma_from_git
from utils.session_persistence import restore_session_state

restore_session_state()

st.set_page_config(
    page_title="Git Sigma import",
    page_icon="📥",
    layout="wide",
)

require_sign_in("Git Sigma import")
render_app_sidebar(get_current_user() or "")

if not has_permission("create"):
    st.error("**create** permission is required to import rules.")
    st.stop()

st.title("📥 Import Sigma rules from Git")
st.caption(
    "Shallow-clones a repository (``git clone --depth 1``), scans ``*.yml`` / ``*.yaml`` under an optional "
    "subdirectory, and creates catalogue rules. Existing identical rules (same hash) are skipped."
)

db = SessionLocal()
try:
    use_cases = UseCaseRepository.list_all(db, limit=500)
    uc_labels = ["(none)"] + [f"{u.id} — {u.name}" for u in use_cases]
    uc_choice = st.selectbox("Attach to use case (optional)", uc_labels)
    use_case_id = None
    if uc_choice != "(none)":
        use_case_id = int(uc_choice.split("—")[0].strip())

    repo_url = st.text_input(
        "Repository URL (HTTPS)",
        placeholder="https://github.com/SigmaHQ/sigma",
        help="Public repo; machine must have ``git`` and network access.",
    )
    branch = st.text_input("Branch", value="master")
    subdir = st.text_input(
        "Subdirectory (optional)",
        value="rules/windows/process_creation",
        help="Path inside the repo to scan; leave empty to scan the whole tree.",
    )

    if st.button("Run import", type="primary"):
        if not (repo_url or "").strip():
            st.error("Repository URL is required.")
        else:
            with st.spinner("Cloning and importing…"):
                stats, err = import_sigma_from_git(
                    db,
                    repo_url.strip(),
                    branch.strip() or "master",
                    subdirectory=subdir.strip(),
                    use_case_id=use_case_id,
                )
            if err:
                st.error(err)
            elif stats.created == 0 and stats.skipped_duplicate == 0 and stats.skipped_invalid == 0 and not stats.errors:
                st.warning("Nothing imported. Check branch and subdirectory, or repo has no Sigma YAML in that path.")
            else:
                st.success(
                    f"Created **{stats.created}** rule(s); skipped **{stats.skipped_duplicate}** duplicate(s); "
                    f"skipped **{stats.skipped_invalid}** non-Sigma file(s)."
                )
                if stats.errors:
                    st.error("Errors:\n" + "\n".join(stats.errors[:20]))
finally:
    db.close()

# Link back
st.divider()
if st.button("← Back to home"):
    st.switch_page("app.py")

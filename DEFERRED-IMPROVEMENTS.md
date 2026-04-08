# Deferred improvements

Items identified but **not** implemented unless explicitly requested (see `.cursor/rules/scope-discipline.mdc`).

| Area | Item | Notes |
|------|------|--------|
| Dependencies | Pin exact versions in `requirements.txt` | Required by secure-dev policy |
| Testing | Unit tests for `services/user_workspace.py` | Needs DB fixtures or in-memory SQLite |
| Versioning | Immutable version table (append-only history rows) | Currently derived from `RuleChangeLog` |
| DB | Postgres migration for cycle-de-vie columns | `migrate_add_cycle_de_vie.py` is SQLite-only |
| Testing | Integration tests for Streamlit pages | Heavy; prefer extracted service logic |
| Auth | SSO / OIDC | Out of scope for local RBAC MVP |
| Security | Rate limiting on login attempts | Not implemented on sign-in portal |
| Docs | Per-feature runbooks | Add when features are finalized |
| MITRE | Coverage config in DB + API | YAML file is sufficient for current scope; migrate if multi-tenant |
| MITRE | Tactic filters on `pages/3_Mapping.py` | Catalogue + hub covered; mapping page stretch |
| Detection | Full Sigma/Splunk/KQL evaluators for dry-run | Heuristic token overlap only |
| Detection | Near-duplicates via embeddings / fuzzy hashing | Text `SequenceMatcher` only |
| DB | Postgres migration for `playbook` column | SQLite migration script provided |
| CTI | Binary PDF storage + VirusTotal-style enrichment | Excerpt + metadata only; local IOC parse only |
| DB | Postgres migration for `cti_library_entries` / `cti_refs` | SQLite migration script provided |
| Collaboration | Email / Slack for @mentions | In-app notifications only |
| Governance | PPTX export, scheduled archival jobs | PDF one-pager + manual archive only |
| DB | Postgres migration for `archived_at` / `archived_by` | SQLite migration script provided |
| DB | Postgres migration for `user_notifications` / `comments.mentions` | SQLite migration script provided |
| DB | Postgres migration for `config_audit_logs` | SQLite migration script provided |
| Integrations | Webhook retries, signing (HMAC), delivery log | Fire-and-forget POST only |
| Integrations | REST API writes (create/update rules) | Read-only MVP |
| Integrations | Private Git / SSH remotes, scheduled sync, update-on-pull | MVP: public HTTPS + shallow clone only |

## How to use this file

When a change is out of the **current** user request, do not implement it: add a row here instead.

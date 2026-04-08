# 🏭 Detection Rules Factory

A **Streamlit** application for managing SOC detection rules, analysing **MITRE ATT&CK** coverage, and connecting threat intelligence to detection content—with **RBAC**, optional **AI** providers (OpenAI, Gemini, local OpenAI-compatible APIs), and a **SQLite** database by default.

---

## Features

- **📋 Detection rules catalogue** — Search, filters (tags, platforms, MITRE tactics/sub-techniques, formats), mapping review, operational status, playbooks, archival.
- **🛡️ MITRE audit** — CSV/manual/catalogue inputs; coverage analysis; optional AI recommendations.
- **🎯 Mapping analysis** — AI-assisted verification, multi-mapping (several techniques per rule), mapping history.
- **📊 Coverage dashboard** — SOC-style metrics, gaps, Navigator export.
- **🎯 MITRE Coverage Hub** — Configurable scopes, CTI technique bundles, gap lists, CSV/Navigator layers.
- **👥 Group coverage** — Coverage vs MITRE threat groups.
- **🔍 CTI** — Detection opportunities from text/PDF/Excel/URL; **CTI library** for reusable sources; local IOC parsing.
- **🔄 Lifecycle** — Use case workflow, review queue (priority, SLA, assignee), rule version diff, ticket references.
- **🧪 Detection engineering** — Dry-run heuristics, packaged export (Sigma/Splunk/KQL + manifest), near-duplicate detection.
- **💬 Collaboration** — Comments, `@mentions`, in-app notifications.
- **📦 Governance** — Retention hints, executive PDF, archival.
- **⚙️ Administration** — Statistics, quality metrics, RBAC view, platform flags, quotas, config audit log, business tags.
- **🔒 RBAC** — Roles (`reader` → `admin`) enforced across pages; optional password hashing (PBKDF2).
- **🤖 AI** — Audits, mapping, CTI extraction; quotas per team; session-friendly locking and duplicate reuse.
- **🔌 Integrations** — Optional outbound **webhooks** (use case approved, mapping changed, offline audit completed) via `config/webhooks.yaml`; optional **read-only REST API** (`rest_api.py`) with bearer tokens in `config/rest_api.yaml`; **Sigma import from Git** (shallow clone + YAML scan, page **Git Sigma import**).

For **step-by-step workflows**, RBAC tables, configuration, and data model details, see **[USAGE.md](USAGE.md)**.

---

## Use cases

| Scenario | What you can do |
|----------|-----------------|
| **SOC / content owners** | Maintain a single catalogue of rules, MITRE mappings, and statuses; route use cases through review; track changes and roll back if needed. |
| **Detection engineering** | Compare rule versions, attach playbooks, dry-run sample events, export rule packs for SIEM teams. |
| **CTI / threat intel** | Ingest reports or URLs, propose rules, link rules to a CTI library and IOC snippets—without depending on external enrichment APIs. |
| **Coverage & leadership** | Use dashboards and the MITRE hub to show gaps, scopes, and executive summaries (including PDF). |
| **Multi-team setups** | Separate teams in RBAC, AI quotas, and optional per-team AI restrictions via platform settings. |

---

## Contribution

Work [zp-4](https://github.com/zp-4) added to this repository:

- **Identity & workspace** — Sign-in, profile, personal workspace, PBKDF2 passwords with YAML RBAC.
- **Platform controls** — Feature flags, maintenance banner, global and per-team AI disable, quotas, business tags, config audit log.
- **Lifecycle** — Use case workflow, decision log, review queue (priority, SLA, assignee, dates), rule versioning and diff, ticket refs, operational status, migrations.
- **MITRE & coverage** — Coverage hub (scopes, CTI bundles, gaps, CSV, Navigator), catalogue filters by tactic/sub-technique.
- **Detection engineering** — Playbooks, dry-run, ZIP export with manifest, near-duplicate detection.
- **CTI** — Library entries, rule↔CTI traceability, local IOC parsing.
- **Collaboration** — Comments, `@mentions`, notifications inbox.
- **Governance** — Soft archive, retention hints, executive PDF on the dashboard path.
- **Tests** — Unit tests for the services above.
- **Integrations** — Webhooks service + optional FastAPI REST (`uvicorn rest_api:app`) + Sigma rules import from a shallow Git clone (`services/sigma_git_import.py`, `pages/18_Git_Sigma_Import.py`).

---

## Architecture

- **UI:** Streamlit multi-page app (`app.py` + `pages/`).
- **Logic:** `services/` (audit, MITRE, auth, quotas, webhooks, …).
- **Persistence:** `db/` (SQLAlchemy models, repositories); default SQLite file `usecase_factory.db`.
- **Engines:** `src/` (AI client abstraction, MITRE engine, ingestion).
- **Optional API:** `rest_api.py` (FastAPI) — separate process from Streamlit; same SQLite DB.

Simplified layout:

```
Detection_Rules_Factory/
├── app.py
├── pages/              # Streamlit pages (login, catalogue, audit, mapping, dashboards, CTI, workflow, …)
├── services/
├── db/
├── src/
├── config/             # rbac.yaml, feature_flags.yaml, mitre_coverage_config.yaml, …
├── tests/
├── init_db.py
├── requirements.txt
├── rest_api.py         # Optional FastAPI (uvicorn)
├── README.md
└── USAGE.md            # User guide (workflows, RBAC, config, integrations)
```

---

## Quick start

**Requirements:** Python 3.8+, pip.

```bash
python -m venv venv
# Windows (PowerShell): .\venv\Scripts\Activate.ps1
# Windows (cmd): venv\Scripts\activate.bat
source venv/bin/activate   # Linux / macOS

pip install -r requirements.txt
python init_db.py          # creates tables + demo seed data
streamlit run app.py       # http://localhost:8501
```

Optional: configure an AI provider in the app sidebar (OpenAI, Gemini, or a local OpenAI-compatible URL). Details and examples are in **[USAGE.md](USAGE.md#configuration)**.

---

## Documentation

| Document | Content |
|----------|---------|
| **[USAGE.md](USAGE.md)** | Per-feature usage, RBAC matrix, AI behaviour, DB/config, data model, migrations, admin capabilities, **webhooks & REST** |
| [LICENSE](LICENSE) | Apache 2.0 |
| [NOTICE](NOTICE) | Attribution |

---

## Testing

```bash
pytest tests/
```

---

## License

This project is licensed under the **Apache License, Version 2.0**.

- See [`LICENSE`](LICENSE) for the full license text.
- See [`NOTICE`](NOTICE) for copyright and attribution when redistributing.

SPDX-License-Identifier: `Apache-2.0`

---

## Contributing

Issues and pull requests are welcome. By contributing, you agree your contributions are licensed under the same terms as this project (Apache 2.0).

---

## Contributors

- **[zp-4](https://github.com/zp-4)** — author of the [Contribution](#contribution) section in this repository.

The upstream project credits Ibrahim Talbi; see git history and `NOTICE` for original authorship.

---

## Trademark notice

[MITRE ATT&CK](https://attack.mitre.org/)® is a registered trademark of [The MITRE Corporation](https://www.mitre.org/). This project is independent and is not affiliated with, endorsed by, or sponsored by MITRE.

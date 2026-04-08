# Detection Rules Factory — User guide

This document is the **operator and user manual**: workflows per screen, RBAC, configuration, and development notes. For a short project overview and installation, see [README.md](README.md).

---

## Table of contents

1. [Detailed usage](#detailed-usage)
2. [More pages in the app](#more-pages-in-the-app)
3. [RBAC](#rbac-role-based-access-control)
4. [AI analysis infrastructure](#ai-analysis-infrastructure)
5. [Optional AI providers (sidebar)](#optional-ai-providers-sidebar)
6. [Database](#database)
7. [Testing](#testing)
8. [Configuration](#configuration)
9. [Data model](#data-model)
10. [Development](#development)
11. [Integrations](#integrations)
12. [Administration](#administration)

---

## Detailed usage

### Detection Rules Catalogue

1. Navigate to **Detection Rules** page (sidebar or main page)
2. Use search and filters to find rules:
   - **Search**: Search in rule name, query text, or MITRE technique ID
   - **Platform**: Filter by platform (Windows, Linux, AWS, SaaS, etc.)
   - **Tags**: Multi-select filter by tags (including `to_improve`, `to_update_mapping`)
   - **Format**: Filter by rule format (Splunk, Sigma, YARA, etc.)
   - **MITRE Technique**: Filter by specific MITRE technique ID
3. **Actions**:
   - **Edit**: Edit rule details (requires permissions)
   - **Run Audit**: Add rule directly to audit queue
   - **Multi-select**: Select multiple rules and add them to audit
4. **Mapping Review**:
   - Rules with mapping issues are automatically tagged with `to_update_mapping`
   - **Mapping Review** section shows AI recommendations directly in the catalogue
   - Apply mapping changes (primary, alternative, or multi-mapping) without leaving the page
   - Section is closed by default, opens automatically for tagged rules

### MITRE Audit

The Audit page provides a **unified interface** with three input methods:

1. **📁 Upload CSV/Excel File**: Upload a file with detection rules
   - Required columns: `Rule_Name`, `Query` (or `Logic_Query`), `Platform`
   - Optional columns: `Technique_ID`, `Tactic`, `Format`

2. **✏️ Add Rule Manually**: Enter rules one by one
   - Multi-select platforms supported
   - Automatic platform mapping (e.g., Okta → SaaS)

3. **📋 Load from Detection Rules Catalogue**: Select existing rules from the catalogue
   - Prevents duplicate rules automatically
   - Explicit "Load" button required (no automatic loading)

After adding rules, click **"Run Coverage Analysis"** to:

- Analyze platform coverage against MITRE ATT&CK
- Run AI analysis (if enabled and quota available)
- Generate detailed recommendations
- Automatically tag rules needing improvement (`to_improve`)
- Save audit results to database for tracking

**Results**:

- Rules with gaps are automatically tagged with `to_improve`
- Audit results are saved and visible in the Rules Catalogue
- Rules can be updated directly from audit results

### AI Analysis

AI analysis provides:

- **Detailed recommendations** (4-6 sentences with examples)
- **Platform mapping** suggestions (e.g., Okta → SaaS)
- **Rule examples** for improvements
- **Duplicate detection** (reuses results within 30 days)

### Smart Tagging System

The system automatically tags rules for review:

- **`to_improve`**: Rules that haven't been audited in 3+ months or have gaps identified
- **`to_update_mapping`**: Rules with incorrect or missing MITRE technique mappings

Tags are visible in:

- Detection Rules Catalogue (filterable)
- Mapping Review section (auto-opens for tagged rules)
- Mapping Analysis page (filterable)

Tags are automatically removed when:

- Mapping is corrected and matches recommendations
- Audit is completed and gaps are addressed

### Mapping Review Workflow

1. **Automatic Detection**: Rules are automatically tagged with `to_update_mapping` if:
   - No MITRE mapping exists
   - Current mapping is incorrect or partially correct (based on AI analysis)
   - Recommended mapping doesn't match current mapping

2. **Review in Catalogue**:
   - Tagged rules show "🎯 Mapping Review" section (auto-opened for tagged rules)
   - View AI recommendations directly in the catalogue
   - Apply mapping changes (primary, alternative, or multi-mapping) with one click
   - Section is closed by default for non-tagged rules

3. **Detailed Analysis** (Mapping Page):
   - Analyze multiple rules at once (all selected by default)
   - View detailed AI analysis with confidence scores and reasoning
   - Apply primary, alternative, or multi-mapping recommendations
   - Review complete mapping history for each rule

4. **Multi-Mapping Support**:
   - Rules can map to 2-3 MITRE techniques simultaneously
   - Useful for rules detecting multiple distinct attack patterns
   - Stored in `mitre_technique_ids` (JSON array)
   - Primary technique also stored in `mitre_technique_id` for backward compatibility

5. **History Tracking**:
   - All mapping changes are recorded in `MappingReview` table
   - Includes previous mapping, new mapping, action type (add/replace/multi-mapping)
   - Stores reviewer username and timestamp
   - Complete AI analysis preserved for audit trail

### MITRE Mapping Analysis

1. Navigate to **Mapping** page
2. **Select Rules**: All rules are selected by default (filterable by mapping status, platform, format)
3. **Configure AI**: Select AI provider (OpenAI, Gemini, or Llama) and enter credentials
4. **Analyze**: Click "Analyze Selected Rules" to verify MITRE mappings
5. **Review Results**:
   - **Primary Technique**: Recommended primary MITRE technique
   - **Alternative Technique**: Alternative if current mapping is incorrect
   - **Multi-Mapping**: If rule detects multiple attack patterns (2-3 techniques)
   - **Mapping Accuracy**: Current mapping status (Correct/Incorrect/Partially Correct)
6. **Actions**:
   - **➕ Add**: Add primary technique to existing mapping
   - **🔄 Replace**: Replace current mapping with recommended technique
   - **🔗 Multi-Map**: Apply 2-3 techniques simultaneously
   - **🏷️ Tag for Review**: Mark rule for manual review
7. **Mapping History**: View complete history of all mapping changes with reviewer and timestamp

**Features**:

- Analysis persists in database (survives page navigation)
- Automatic tagging of rules needing mapping review
- Multi-mapping support (rules can map to multiple techniques)
- Complete audit trail of all mapping changes

### Coverage Dashboard

1. Navigate to **Dashboard** page
2. **Executive Summary**: Key metrics (Use Cases, Rules, Techniques Covered, Active Rules, Rules to Improve)
3. **Coverage Analysis**:
   - Rules distribution by platform (interactive pie chart)
   - Overall coverage gauge (0-100%)
4. **Detailed Statistics** (4 tabs):
   - **Techniques**: Complete list with details, top 10 most covered
   - **Rules**: Filterable table by platform, status, format
   - **Tags**: Most used tags analysis
   - **Timeline**: Rules activity over time
5. **Gap Analysis**: Identifies uncovered MITRE techniques
6. **Export Navigator JSON**: Download MITRE ATT&CK Navigator compatible JSON (version 18)

### CTI Detection

1. Navigate to **CTI Detection Opportunity** page
2. **Input Methods**:
   - **📄 Text Input**: Paste threat intelligence content directly
   - **📁 File Upload**: Upload PDF or Excel files containing CTI
   - **🔗 URL**: Provide a URL to extract content from (web pages, reports)
3. **AI Analysis**:
   - Select AI provider (OpenAI, Gemini, or Llama)
   - Configure API credentials
   - AI analyzes the CTI content and identifies detection opportunities
4. **Results**:
   - Proposed detection rules with MITRE technique mappings
   - Rule names, queries, platforms, and confidence scores
   - Tags and reasoning for each proposed rule
5. **Actions**:
   - **Add to Catalogue**: Add proposed rules directly to your detection rules catalogue (requires `create` permission)
   - Review and modify rules before adding

**Features**:

- Supports multiple input formats (text, PDF, Excel, URLs)
- AI-powered rule extraction from unstructured threat intelligence
- Automatic MITRE technique mapping suggestions
- Direct integration with detection rules catalogue

### Group Coverage

1. Navigate to **Group Coverage** page
2. **Select Threat Actor Group**: Choose from MITRE ATT&CK threat actor groups
3. **Coverage Analysis**:
   - View which MITRE techniques are used by the selected group
   - See which techniques are covered by your detection rules
   - Identify gaps in coverage for specific threat actors
4. **Visualizations**:
   - Interactive coverage matrix
   - Technique-by-technique coverage status
   - Gap analysis for the selected group
5. **Use Cases**:
   - Prioritize rule development based on active threat actors
   - Assess detection coverage against specific APT groups
   - Identify missing detections for high-priority threats

### Audit Trail

1. Navigate to **Audit Trail** page
2. **Filter Options**:
   - **Action Type**: All, create, update, delete, enable, disable
   - **User**: Filter by who made the change
   - **Time Period**: Last 24 hours, 7 days, 30 days, or all history
3. **View Changes**:
   - See all modifications with before/after states
   - View changed fields with old and new values
   - Check reason for each change
4. **Rollback** (Admin only):
   - Restore a rule to its previous state
   - Rollbacks are themselves tracked in the audit trail
5. **Rule History**:
   - Select a specific rule to see its complete change history

**Features**:

- Complete snapshot of rule state before and after each change
- All actions tracked: create, update, delete, enable, disable
- MITRE mapping changes tracked separately in MappingReview table
- Rollback capability for updates, deletes, and enable/disable actions

---

## More pages in the app

After sign-in, the sidebar lists additional areas (exact labels may vary by version):

| Theme | Examples |
|--------|----------|
| Identity | Login, My Profile |
| Work | My Workspace, Use case workflow |
| MITRE | MITRE Coverage Hub (scopes, bundles, gaps, exports) |
| Rules | Rule version diff, Detection engineering (playbooks, dry-run, export) |
| CTI | CTI Library |
| Collaboration | Comments, @mentions, notifications |
| Governance | Archival, retention, executive PDF |
| Admin | Statistics, metrics, RBAC view, Platform (flags, quotas, config audit), Business tags, README editor |

---

## RBAC (Role-Based Access Control)

### Roles and Permissions

| Role | read | create | update | delete | review | trigger_ai | admin | rollback |
|------|------|--------|--------|--------|--------|------------|-------|----------|
| reader | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| contributor | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| reviewer | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ |
| admin | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

### Permission Enforcement

RBAC is enforced across all pages:

- **Detection Rules**: Create/Edit/Delete require appropriate permissions
- **MITRE Mapping**: Modifying mappings requires `update` permission
- **CTI Detection**: Adding rules requires `create` permission
- **Audit Page**: Modifying rules during audit requires `update`/`create` permissions
- **Audit Trail**: Rollback requires `admin` permission

### Default Users

Configured in `config/rbac.yaml`:

- **admin** — Full access including rollback
- **reviewer1** — Can review and trigger AI analysis
- **contributor1** — Can create and edit rules
- **reader1** — Read-only access (cannot modify anything)

---

## AI analysis infrastructure

### Duplicate Detection

- Rules are hashed (SHA256) based on query, platform, and format
- Recent AI results (within 30 days) are reused automatically
- Prevents redundant AI analysis calls

### Locking

- Prevents concurrent AI runs on same rule
- Locks expire after 30 minutes (auto-cleanup)
- Ensures consistent analysis results

---

## Optional AI providers (sidebar)

Configure one of the following when a page supports AI:

**OpenAI**

- Enter your OpenAI API key
- Uses GPT-4o (or chosen model) by default

**Gemini**

- Enter your Google AI (Gemini) API key

**Llama (custom / OpenAI-compatible)**

- **API Base URL**: e.g. `http://localhost:11434/v1` (Ollama)
- **Model Name**: as on your server (e.g. `llama3`)
- **API Key**: optional if the server does not require auth

| Server | Base URL | Notes |
|--------|----------|-------|
| Ollama | `http://localhost:11434/v1` | Common local setup |
| vLLM | `http://localhost:8000/v1` | High-throughput inference |
| text-generation-inference | `http://localhost:8080/v1` | HuggingFace TGI |
| LM Studio | `http://localhost:1234/v1` | Desktop LLM |

Platform settings (Admin) can disable AI globally or for selected teams; team AI quotas apply per calendar month.

---

## Database

### SQLite (Default)

Database file: `usecase_factory.db`

### PostgreSQL (Production)

Set environment variable:

```bash
export DATABASE_URL="postgresql://user:pass@localhost/dbname"
```

Use Alembic or your own migration strategy for production.

---

## Testing

```bash
pytest tests/
```

---

## Configuration

### RBAC

Edit `config/rbac.yaml`:

```yaml
users:
  username:
    role: admin|reviewer|contributor|reader
    team: security|soc|...
```

### Session Persistence

Session data is automatically saved to `.streamlit/session_cache.json` and restored on application restart. Cache expires after 24 hours.

Other YAML files under `config/` include feature flags, MITRE coverage scopes, business tags, and governance hints—see each file’s comments.

---

## Data model

Key entities:

- **RuleImplementation**: Detection rules with metadata (name, query, platform, format, tags, MITRE technique, multi-mapping support)
  - `mitre_technique_id`: Primary/legacy technique ID (backward compatibility)
  - `mitre_technique_ids`: JSON array for multi-mapping (2-3 techniques)
  - `last_mapping_analysis`: Stores AI mapping analysis results
  - `tags`: JSON array including `to_improve`, `to_update_mapping`
- **MappingReview**: Complete history of MITRE mapping changes
  - Tracks previous and new mappings
  - Records action type (add, replace, multi-mapping)
  - Stores AI analysis and recommendations
  - Includes reviewer and timestamp
- **RuleChangeLog**: Complete audit trail for all rule changes
  - Tracks all actions: create, update, delete, enable, disable
  - Stores full rule state snapshots (before and after)
  - Records changed fields with old/new values
  - Supports rollback to previous states
  - Tracks who made each change and when
- **OfflineAuditResult**: MITRE coverage audit results
- **AiAuditResult**: AI analysis results
- **CoverageSnapshot**: MITRE coverage snapshots

Additional tables support quotas, locks, CTI library, comments, notifications, governance fields, and configuration audit events—see `db/models.py`.

---

## Development

### Adding New Features

1. Add models in `db/models.py`
2. Add repositories in `db/repo.py`
3. Add services in `services/`
4. Create pages in `pages/`

### Database Migrations

For schema changes:

1. Update models in `db/models.py`
2. Run the relevant scripts under `db/migrate_*.py` (SQLite). Examples:

```bash
python db/migrate_add_tags.py
python db/migrate_add_mapping_reviews.py
python db/migrate_add_multi_mapping.py
python db/migrate_add_changelog.py
```

3. In production (PostgreSQL), use Alembic or an equivalent migration tool.

New databases can use `python init_db.py` to create the current schema. Older databases may need several migration scripts depending on age.

---

## Integrations

### Outbound webhooks

Configure `config/webhooks.yaml`. Set `enabled: true` and add one or more `endpoints` with an HTTPS `url` and an `events` list.

Emitted events:

| Event | When |
|-------|------|
| `use_case_approved` | A use case transitions to status `approved` (Use case workflow page). |
| `mapping_changed` | A `MappingReview` row is created from the catalogue or Mapping page. |
| `audit_completed` | An offline MITRE audit row is stored (`kind: offline` in payload). |

Each POST body is JSON:

```json
{
  "event": "mapping_changed",
  "occurred_at": "2026-04-08T12:00:00+00:00",
  "data": { "rule_id": 1, "rule_name": "...", "review_id": 42, ... }
}
```

Compatible with **Slack incoming webhooks** and any HTTPS endpoint that accepts `application/json`. Failures are logged only; the Streamlit UI is not blocked.

### Read-only REST API (optional)

1. Edit `config/rest_api.yaml`: set `enabled: true` and add at least one `tokens` entry (`name` + long random `token`).
2. Run a separate process (same working directory and `DATABASE_URL` as Streamlit):

```bash
uvicorn rest_api:app --host 127.0.0.1 --port 8080
```

3. Call with header `Authorization: Bearer <token>`:

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness (no auth). |
| GET | `/api/v1/rules` | Recent rules (query `limit`, max 500). |
| GET | `/api/v1/rules/{id}` | One rule. |
| GET | `/api/v1/use-cases` | Recent use cases. |

The API is **read-only** in this version—use Streamlit or future tooling for writes.

### Sigma rules from Git

Use **Git Sigma import** (`pages/18_Git_Sigma_Import.py`). Requires **`create`** permission, **`git`** on the server PATH, and network access to clone the URL (typically a **public** HTTPS repo).

- Performs `git clone --depth 1 --branch <branch> <url>` into a temporary directory.
- Recursively scans `*.yml` / `*.yaml` under an optional subdirectory (e.g. `rules/windows/process_creation`).
- Parses Sigma documents (must contain a `detection` block); derives platform from `logsource`, MITRE technique IDs from `tags` (`attack.tXXXX`), and skips rules whose hash already exists in the catalogue.

Private repositories or SSH remotes are not covered in this MVP—clone externally and use a local path import only if you extend the service.

---

## Administration

The **Admin** page provides:

1. **System Statistics**: Overall metrics (rules, use cases, changes, users), distribution by platform/format, recent activity, AI usage.
2. **Rule Quality Metrics**: Rules needing attention, MITRE framework coverage, multi-mapping counts, unique techniques.
3. **RBAC Configuration**: Read-only view of YAML and user summary.
4. **Platform**: Feature flags, maintenance banner, global or per-team AI disable, monthly AI quotas by team, **configuration audit log**.
5. **README Editor**: Edit `README.md` from the UI (this user guide is **`USAGE.md`** in the repo; edit it in your IDE or add a copy in Admin if you extend the editor).
6. **Business tags**: Governed tags for the rules catalogue.

---

*Return to [README.md](README.md) · SPDX-License-Identifier: Apache-2.0*

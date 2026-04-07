# 🏭 Detection Rules Factory

A comprehensive platform for managing SOC detection rules and MITRE ATT&CK coverage analysis.

## 🎯 Features

- **📋 Detection Rules Catalogue**: Manage and organize detection rules with advanced filtering (tags, platforms, MITRE techniques, formats)
- **🛡️ MITRE Audit**: Gap analysis against MITRE ATT&CK framework with unified input methods (CSV upload, manual entry, load from catalogue)
- **🎯 MITRE Mapping Analysis**: AI-powered mapping verification and improvement with multi-mapping support (2-3 techniques per rule)
- **📊 Coverage Dashboard**: Professional SOC-style dashboard with interactive visualizations and MITRE coverage metrics
- **⚙️ Administration**: System statistics, rule quality metrics, RBAC management, and README editor
- **🤖 AI Analysis**: AI-powered rule analysis with cost management, duplicate detection, and detailed recommendations
- **🔄 Session Persistence**: File-based session persistence to maintain data across browser sessions
- **🏷️ Smart Tagging**: Automatic tagging system (`to_improve`, `to_update_mapping`) for rules needing attention
- **📜 Mapping Review History**: Complete audit trail of all MITRE mapping changes with reviewer information
- **📜 Audit Trail**: Full changelog of all rule modifications with rollback capability
- **🔒 Enhanced RBAC**: Strict permission enforcement across all pages
- **🔍 CTI Detection**: AI-powered detection rule extraction from threat intelligence (text, PDF, Excel, URL)
- **👥 Group Coverage**: Analyze MITRE ATT&CK coverage by threat actor groups

## 🏗️ Architecture

The application is built with **Streamlit**:

```
mitre-attack/
├── LICENSE                   # Apache License 2.0 (full text)
├── NOTICE                    # Copyright and attribution (Apache 2.0)
├── app.py                    # Main landing page / Router
├── pages/                    # Streamlit multi-pages
│   ├── 1_Use_Cases.py       # Detection Rules Catalogue (with mapping review)
│   ├── 2_Audit.py           # MITRE Audit (unified input)
│   ├── 3_Mapping.py         # MITRE Mapping Analysis & Review
│   ├── 4_Dashboard_MITRE.py # MITRE Coverage Dashboard (SOC Edition)
│   ├── 5_Group_Coverage.py  # Group Coverage Analysis
│   ├── 6_CTI_Detection.py   # CTI Detection Opportunity
│   ├── 7_Audit_Trail.py     # Audit Trail & Rollback
│   └── 8_Admin.py           # Administration
├── services/                 # Business logic
│   ├── offline_audit.py     # Offline MITRE audit
│   ├── ai_audit.py          # AI audit with cost control
│   ├── mitre_coverage.py    # MITRE engine wrapper
│   └── auth.py              # RBAC authentication
├── db/                       # Database layer
│   ├── models.py            # SQLAlchemy models
│   ├── repo.py              # CRUD repositories
│   ├── session.py           # DB session management
│   └── migrations.py        # Migration scripts
├── src/                      # Core engines
│   ├── ai_engine.py         # AI analysis engine (OpenAI/Gemini/Llama)
│   ├── data_ingestion.py    # CSV/Excel data ingestion
│   └── mitre_engine.py      # MITRE ATT&CK engine
├── utils/                    # Utilities
│   ├── hashing.py           # Rule hashing for duplicates
│   ├── locking.py           # Locking mechanism
│   ├── platform_mapping.py  # Platform mapping (Okta → SaaS)
│   ├── session_persistence.py # Session state persistence
│   └── time.py              # Time utilities
├── config/                   # Configuration
│   └── rbac.yaml            # RBAC configuration
├── tests/                    # Unit tests
├── seeds/                    # Demo data seeding
├── requirements.txt          # Python dependencies
└── init_db.py               # Database initialization
```

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Installation

1. **Create a virtual environment**:

   ```powershell
   python -m venv venv
   ```

2. **Activate the virtual environment**:

   **On Windows (PowerShell):**
   ```powershell
   .\venv\Scripts\Activate.ps1
   ```

   **On Windows (CMD):**
   ```cmd
   venv\Scripts\activate.bat
   ```

   **On Linux/Mac:**
   ```bash
   source venv/bin/activate
   ```

3. **Install dependencies**:

   ```powershell
   pip install -r requirements.txt
   ```

4. **Initialize the database**:

   ```powershell
   python init_db.py
   ```

   This will:
   - Create all database tables (SQLite by default)
   - Seed demo data (3 use cases + 3 rules)

5. **Run the application**:

   ```powershell
   streamlit run app.py
   ```

   The application will automatically open in your browser at `http://localhost:8501`

### Optional: AI Provider Configuration

If you want to use AI analysis, configure one of the following providers in the sidebar:

**OpenAI**
- Enter your OpenAI API key
- Uses GPT-4o by default

**Gemini**
- Enter your Google AI (Gemini) API key
- Uses Gemini Pro model

**Llama (Custom LLM)**
- For self-hosted LLMs with OpenAI-compatible API
- Supports: Ollama, vLLM, text-generation-inference, LM Studio, etc.
- Configure:
  - **API Base URL**: Your LLM server endpoint (e.g., `http://localhost:11434/v1`)
  - **Model Name**: Model name as configured on your server (e.g., `llama3`, `mistral`, `codellama`)
  - **API Key**: Optional, only if your server requires authentication

Example configurations for Llama:
| Server | Base URL | Notes |
|--------|----------|-------|
| Ollama | `http://localhost:11434/v1` | Most common local setup |
| vLLM | `http://localhost:8000/v1` | High-performance inference |
| text-generation-inference | `http://localhost:8080/v1` | HuggingFace TGI |
| LM Studio | `http://localhost:1234/v1` | GUI-based local LLM |

## 📖 Usage Guide

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

## 🔐 RBAC (Role-Based Access Control)

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
- **admin** - Full access including rollback
- **reviewer1** - Can review and trigger AI analysis
- **contributor1** - Can create and edit rules
- **reader1** - Read-only access (cannot modify anything)

## 🔄 AI Analysis Features

### Duplicate Detection

- Rules are hashed (SHA256) based on query, platform, and format
- Recent AI results (within 30 days) are reused automatically
- Prevents redundant AI analysis calls

### Locking

- Prevents concurrent AI runs on same rule
- Locks expire after 30 minutes (auto-cleanup)
- Ensures consistent analysis results

## 🗄️ Database

### SQLite (Default)

Database file: `usecase_factory.db`

### PostgreSQL (Production)

Set environment variable:
```bash
export DATABASE_URL="postgresql://user:pass@localhost/dbname"
```

## 🧪 Testing

Run tests:
```bash
pytest tests/
```

## 📝 Configuration

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

## 📊 Data Model

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

## 🛠️ Development

### Adding New Features

1. Add models in `db/models.py`
2. Add repositories in `db/repo.py`
3. Add services in `services/`
4. Create pages in `pages/`

### Database Migrations

For schema changes:
1. Update models in `db/models.py`
2. Run migration scripts:
   ```powershell
   python db/migrate_add_tags.py          # Adds tags and mitre_technique_id
   python db/migrate_add_mapping_reviews.py  # Adds mapping_reviews table
   python db/migrate_add_multi_mapping.py    # Adds mitre_technique_ids and last_mapping_analysis
   python db/migrate_add_changelog.py        # Adds rule_change_logs table for audit trail
   ```
3. (In production, use Alembic for proper migrations)

**Recent Migrations**:
- `mapping_reviews`: Table for tracking MITRE mapping review history
- `mitre_technique_ids`: JSON field for multi-mapping support (2-3 techniques per rule)
- `last_mapping_analysis`: JSON field storing AI mapping analysis results
- `rule_change_logs`: Table for complete audit trail with rollback support

## 📚 Additional Features

### Administration Page

The Admin page provides comprehensive system management:

1. **System Statistics**:
   - Overall metrics (rules, use cases, changes, users)
   - Rules distribution by platform and format
   - Recent activity (last 7 days)
   - AI usage statistics

2. **Rule Quality Metrics**:
   - Rules requiring attention (to improve, to update mapping, no mapping, disabled)
   - MITRE framework coverage (techniques covered vs. total available)
   - Multi-mapping rules count
   - Unique techniques covered

3. **RBAC Configuration**:
   - View current RBAC configuration
   - User summary with role distribution
   - User list with roles and teams

4. **README Editor**:
   - Edit README.md directly from the interface
   - Preview markdown rendering
   - File information (size, last modified, line count)
   - Save, reload, and reset functionality

## 📄 License

This project is licensed under the **Apache License, Version 2.0**.

- See [`LICENSE`](LICENSE) for the full license text.
- See [`NOTICE`](NOTICE) for copyright and attribution notices required when redistributing (Apache 2.0 §4d).

SPDX-License-Identifier: `Apache-2.0`

## 🤝 Contributing

Contributions (issues, pull requests, documentation) are welcome. By contributing, you agree that your contributions will be licensed under the same terms as this project (Apache License 2.0).

### Contributors

| Name | Contact |
|------|---------|
| Ibrahim Talbi | [ibrahim89talbi@gmail.com](mailto:ibrahim89talbi@gmail.com) |

## ™️ Trademark notice

[MITRE ATT&CK](https://attack.mitre.org/)® is a registered trademark of [The MITRE Corporation](https://www.mitre.org/). This project is an independent tool and is not affiliated with, endorsed by, or sponsored by MITRE.

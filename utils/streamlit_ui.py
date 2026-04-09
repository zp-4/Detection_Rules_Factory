"""
Global Streamlit styling: fonts, layout, sidebar chrome, components.
Inject once per page (via render_app_sidebar or login).
"""

from __future__ import annotations

import streamlit as st

def apply_global_styles() -> None:
    """Inject shared CSS (main + sidebar). Call once at the top of each page run."""
    st.markdown(
        """
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,400;0,9..40,500;0,9..40,600;0,9..40,700;1,9..40,400&family=JetBrains+Mono:wght@400;500&display=swap');

:root {
  --drf-ink: #0f172a;
  --drf-muted: #64748b;
  --drf-line: #e2e8f0;
  --drf-accent: #0d9488;
  --drf-accent-dim: #ccfbf1;
  --drf-sidebar-bg0: #0b1220;
  --drf-sidebar-bg1: #111a2e;
  --drf-sidebar-text: #cbd5e1;
  --drf-sidebar-heading: #f8fafc;
}

html, body,
[class*="stApp"] {
  font-family: "DM Sans", system-ui, -apple-system, sans-serif !important;
}

code, pre, .stCodeBlock {
  font-family: "JetBrains Mono", ui-monospace, monospace !important;
}

/* Main column */
.main .block-container {
  padding-top: 0.85rem !important;
  padding-bottom: 1.1rem !important;
  padding-left: 1rem !important;
  padding-right: 1rem !important;
  max-width: min(1200px, 96vw) !important;
}

/* Top header bar */
header[data-testid="stHeader"] {
  background: rgba(248, 250, 252, 0.92) !important;
  backdrop-filter: blur(10px);
  border-bottom: 1px solid var(--drf-line) !important;
}

/* Main headings */
.main h1 {
  font-weight: 800 !important;
  letter-spacing: -0.035em !important;
  color: var(--drf-ink) !important;
  border-bottom: 2px solid var(--drf-line);
  padding-bottom: 0.4rem !important;
  margin-bottom: 0.75rem !important;
}
.main h2, .main h3 {
  font-weight: 700 !important;
  letter-spacing: -0.02em !important;
  color: var(--drf-ink) !important;
}

/* Primary buttons (main) — Streamlit uses data-testid on inner element */
.stMain [data-testid="baseButton-primary"],
section.main [data-testid="baseButton-primary"] {
  border-radius: 10px !important;
  font-weight: 600 !important;
  padding: 0.5rem 1rem !important;
  background: linear-gradient(145deg, #0d9488 0%, #0f766e 100%) !important;
  border: none !important;
  box-shadow: 0 2px 8px rgba(13, 148, 136, 0.35) !important;
}
.stMain [data-testid="baseButton-primary"]:hover,
section.main [data-testid="baseButton-primary"]:hover {
  box-shadow: 0 4px 14px rgba(13, 148, 136, 0.45) !important;
}

/* Secondary buttons */
.stMain [data-testid="baseButton-secondary"] {
  border-radius: 10px !important;
  font-weight: 500 !important;
  border: 1px solid var(--drf-line) !important;
}

/* Expanders — less dead space between stacked expanders */
.streamlit-expander {
  margin-bottom: 0.35rem !important;
}
.streamlit-expanderHeader {
  font-weight: 600 !important;
  border-radius: 10px !important;
  background: rgba(15, 23, 42, 0.04) !important;
  min-height: auto !important;
  padding-top: 0.45rem !important;
  padding-bottom: 0.45rem !important;
}
.streamlit-expanderContent {
  border-radius: 0 0 10px 10px !important;
  padding-top: 0.35rem !important;
}

/* Metrics / success blocks in main */
.main [data-testid="stMetricValue"] {
  font-weight: 700 !important;
}

/* ----- Sidebar (dark) ----- */
[data-testid="stSidebar"] {
  background: linear-gradient(195deg, var(--drf-sidebar-bg0) 0%, var(--drf-sidebar-bg1) 55%, #152036 100%) !important;
  border-right: 1px solid rgba(148, 163, 184, 0.12) !important;
  box-shadow: 4px 0 24px rgba(15, 23, 42, 0.12);
}

/* Sidebar headings — all sources (title(), markdown h3, etc.) */
[data-testid="stSidebar"] h1,
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3,
[data-testid="stSidebar"] [data-testid="stMarkdown"] h1,
[data-testid="stSidebar"] [data-testid="stMarkdown"] h2,
[data-testid="stSidebar"] [data-testid="stMarkdown"] h3 {
  color: #f8fafc !important;
  font-weight: 700 !important;
  letter-spacing: -0.02em !important;
  border: none !important;
}
[data-testid="stSidebar"] h1 {
  font-size: 1.15rem !important;
  margin: 0 0 0.35rem 0 !important;
  padding: 0 !important;
}
[data-testid="stSidebar"] h3 {
  margin: 0.25rem 0 0.2rem 0 !important;
  font-size: 0.95rem !important;
}

[data-testid="stSidebar"] [data-testid="stCaption"] {
  color: #94a3b8 !important;
  margin-top: 0 !important;
  margin-bottom: 0.15rem !important;
}

/* Sidebar: Streamlit adds large gaps between each widget — tighten */
[data-testid="stSidebar"] [class*="stElementContainer"],
[data-testid="stSidebar"] [class*="element-container"] {
  margin-bottom: 0.2rem !important;
}
[data-testid="stSidebar"] [data-testid="stVerticalBlock"] > div {
  gap: 0.2rem !important;
}
[data-testid="stSidebar"] hr {
  margin: 0.3rem 0 !important;
  border-color: rgba(148, 163, 184, 0.2) !important;
}

/* Sidebar alerts (success / warning) — compact session strip */
[data-testid="stSidebar"] [data-testid="stAlert"] {
  padding: 0.28rem 0.45rem !important;
  margin-bottom: 0.12rem !important;
}
[data-testid="stSidebar"] [data-testid="stAlert"] p {
  line-height: 1.35 !important;
  margin: 0 !important;
  font-size: 0.88rem !important;
}

/* Sidebar inner padding — use horizontal space, less vertical air */
[data-testid="stSidebar"] [data-testid="stSidebarContent"] {
  padding-top: 0.35rem !important;
  padding-bottom: 0.5rem !important;
  padding-left: 0.45rem !important;
  padding-right: 0.45rem !important;
}

/* Top home / brand page link — dark card, not pale blue */
[data-testid="stSidebar"] [data-testid^="stPageLink"] {
  background: rgba(255, 255, 255, 0.06) !important;
  border: 1px solid rgba(148, 163, 184, 0.18) !important;
  border-radius: 10px !important;
  padding: 0.4rem 0.5rem !important;
  margin-bottom: 0.15rem !important;
}
[data-testid="stSidebar"] [data-testid^="stPageLink"] p,
[data-testid="stSidebar"] [data-testid^="stPageLink"] span {
  color: #f1f5f9 !important;
  font-weight: 600 !important;
  font-size: 0.92rem !important;
}

/* Nav links inside expanders — same dark chrome, minimal stack gap */
[data-testid="stSidebar"] .streamlit-expander [data-testid^="stPageLink"] {
  margin-bottom: 0.12rem !important;
  padding: 0.32rem 0.45rem !important;
  font-size: 0.86rem !important;
}
[data-testid="stSidebar"] .streamlit-expander [data-testid^="stPageLink"] p,
[data-testid="stSidebar"] .streamlit-expander [data-testid^="stPageLink"] span {
  font-size: 0.86rem !important;
  font-weight: 500 !important;
}

/* Sidebar: expander groups (nav) — dark chrome, tight */
[data-testid="stSidebar"] .streamlit-expander {
  margin-bottom: 0.15rem !important;
  border: 1px solid rgba(148, 163, 184, 0.12) !important;
  border-radius: 10px !important;
  background: rgba(0, 0, 0, 0.12) !important;
}
[data-testid="stSidebar"] .streamlit-expanderHeader {
  background: transparent !important;
  color: #e2e8f0 !important;
  font-size: 0.85rem !important;
  padding-top: 0.3rem !important;
  padding-bottom: 0.3rem !important;
  min-height: 0 !important;
}
[data-testid="stSidebar"] .streamlit-expanderContent {
  padding-top: 0.15rem !important;
  padding-bottom: 0.25rem !important;
}

[data-testid="stSidebar"] [data-testid="baseButton-primary"],
[data-testid="stSidebar"] [data-testid="baseButton-secondary"] {
  border-radius: 10px !important;
  font-weight: 500 !important;
  background: rgba(255, 255, 255, 0.06) !important;
  border: 1px solid rgba(148, 163, 184, 0.2) !important;
  color: #e2e8f0 !important;
  transition: background 0.15s ease, border-color 0.15s ease !important;
  padding: 0.35rem 0.65rem !important;
  min-height: 0 !important;
}
[data-testid="stSidebar"] [data-testid="baseButton-primary"]:hover,
[data-testid="stSidebar"] [data-testid="baseButton-secondary"]:hover {
  background: rgba(45, 212, 191, 0.12) !important;
  border-color: rgba(45, 212, 191, 0.4) !important;
  color: #f8fafc !important;
}

[data-testid="stSidebar"] [data-baseweb="divider"] {
  background: rgba(148, 163, 184, 0.15) !important;
}

/* Alerts in sidebar — keep readable */
[data-testid="stSidebar"] .stAlert {
  border-radius: 10px !important;
  border: none !important;
}

[data-testid="stSidebar"] [data-testid="stSuccess"] {
  background: rgba(16, 185, 129, 0.15) !important;
}

/* Hero + cards (custom classes) */
.drf-hero {
  background: linear-gradient(135deg, #f0fdfa 0%, #ecfeff 40%, #f8fafc 100%);
  border: 1px solid #ccfbf1;
  border-radius: 16px;
  padding: 1.15rem 1.2rem 1.1rem 1.2rem;
  margin-bottom: 0.6rem;
  box-shadow: 0 8px 30px rgba(15, 23, 42, 0.06);
}
.drf-hero-kicker {
  margin: 0 0 0.35rem 0;
  font-size: 0.75rem;
  font-weight: 600;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: #0f766e;
}
.drf-hero-title {
  margin: 0 0 0.5rem 0;
  font-size: 1.75rem;
  font-weight: 800;
  letter-spacing: -0.04em;
  color: #0f172a;
  border: none !important;
  padding: 0 !important;
}
.drf-hero-lead {
  margin: 0;
  font-size: 1.05rem;
  color: #475569;
  line-height: 1.55;
  max-width: 52ch;
}

.drf-card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
  margin-top: 0.5rem;
}
.drf-stat-card {
  background: #fff;
  border: 1px solid var(--drf-line);
  border-radius: 12px;
  padding: 1rem 1.1rem;
  box-shadow: 0 2px 12px rgba(15, 23, 42, 0.04);
}
.drf-stat-card h4 {
  margin: 0 0 0.35rem 0;
  font-size: 0.7rem;
  font-weight: 700;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--drf-muted);
}
.drf-stat-card p {
  margin: 0;
  font-size: 1rem;
  font-weight: 600;
  color: var(--drf-ink);
}

.drf-login-shell {
  max-width: 420px;
  margin: 0 auto;
  padding: 2rem 1.5rem;
  background: linear-gradient(160deg, #ffffff 0%, #f8fafc 100%);
  border: 1px solid var(--drf-line);
  border-radius: 16px;
  box-shadow: 0 12px 40px rgba(15, 23, 42, 0.08);
}
.drf-login-shell h1 {
  border: none !important;
  font-size: 1.5rem !important;
  margin-bottom: 0.25rem !important;
}

/* Bordered containers (st.container(border=True)) */
.main [data-testid="stVerticalBlockBorderWrapper"] {
  border-radius: 12px !important;
  border-color: #e2e8f0 !important;
  background: #ffffff !important;
  box-shadow: 0 1px 8px rgba(15, 23, 42, 0.04) !important;
  padding: 0.5rem 0.65rem !important;
  margin-bottom: 0.35rem !important;
}
/* Quick access: caption under title — tight */
.main [data-testid="stVerticalBlockBorderWrapper"] [data-testid="stCaption"] {
  margin-top: -0.15rem !important;
  margin-bottom: 0.35rem !important;
}
</style>
        """,
        unsafe_allow_html=True,
    )


def apply_login_page_styles() -> None:
    """Tighter chrome + wide sign-in card (call after apply_global_styles on 0_Login only)."""
    st.markdown(
        """
<style>
/* Login: use full width of main area, minimal outer padding */
section.main div.block-container {
  padding-top: 0.35rem !important;
  padding-bottom: 0.5rem !important;
  padding-left: 0.75rem !important;
  padding-right: 0.75rem !important;
  max-width: 100% !important;
}
/* Wider bordered card on login */
section.main [data-testid="stVerticalBlockBorderWrapper"] {
  max-width: min(720px, 96vw) !important;
  margin-left: auto !important;
  margin-right: auto !important;
  padding: 0.85rem 1.25rem 1rem 1.25rem !important;
}
</style>
        """,
        unsafe_allow_html=True,
    )

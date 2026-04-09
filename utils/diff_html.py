"""HTML diff helpers for Streamlit (shared by Audit Trail and Rule Version Diff)."""
import difflib
from typing import Optional


def escape_html_diff(text: str) -> str:
    """Escape HTML special characters for safe embedding in diff output."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def generate_colored_diff(old_text: str, new_text: str) -> Optional[str]:
    """Generate HTML unified-diff style block with colored lines."""
    old_text = old_text or ""
    new_text = new_text or ""

    old_lines = old_text.splitlines(keepends=True)
    new_lines = new_text.splitlines(keepends=True)
    diff = difflib.unified_diff(old_lines, new_lines, lineterm="")

    html_parts = [
        """
    <style>
        .diff-container {
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 13px;
            background: #1e1e1e;
            border-radius: 8px;
            padding: 12px;
            overflow-x: auto;
            line-height: 1.5;
        }
        .diff-line {
            padding: 2px 8px;
            margin: 1px 0;
            border-radius: 3px;
            white-space: pre-wrap;
            word-break: break-all;
        }
        .diff-added {
            background-color: #1c4428;
            color: #7ee787;
            border-left: 3px solid #3fb950;
        }
        .diff-removed {
            background-color: #4c1d1d;
            color: #f85149;
            border-left: 3px solid #f85149;
        }
        .diff-context {
            color: #8b949e;
        }
        .diff-header {
            color: #58a6ff;
            font-weight: bold;
            margin-bottom: 8px;
        }
    </style>
    <div class="diff-container">
    """
    ]

    has_changes = False
    for line in diff:
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("@@"):
            html_parts.append(
                f'<div class="diff-line diff-header">{escape_html_diff(line.strip())}</div>'
            )
            has_changes = True
        elif line.startswith("+"):
            html_parts.append(
                f'<div class="diff-line diff-added">+ {escape_html_diff(line[1:].rstrip())}</div>'
            )
            has_changes = True
        elif line.startswith("-"):
            html_parts.append(
                f'<div class="diff-line diff-removed">- {escape_html_diff(line[1:].rstrip())}</div>'
            )
            has_changes = True
        else:
            html_parts.append(
                f'<div class="diff-line diff-context">  {escape_html_diff(line.rstrip())}</div>'
            )

    html_parts.append("</div>")

    if not has_changes:
        return None
    return "".join(html_parts)


def generate_side_by_side_diff(old_text: str, new_text: str) -> str:
    """Generate HTML side-by-side line diff."""
    old_lines = (old_text or "").splitlines()
    new_lines = (new_text or "").splitlines()
    matcher = difflib.SequenceMatcher(None, old_lines, new_lines)

    html_parts = [
        """
    <style>
        .side-diff-container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 12px;
        }
        .side-diff-panel {
            background: #1e1e1e;
            border-radius: 8px;
            padding: 12px;
            overflow-x: auto;
        }
        .side-diff-title {
            font-weight: bold;
            margin-bottom: 10px;
            padding-bottom: 8px;
            border-bottom: 1px solid #333;
        }
        .side-diff-title-old { color: #f85149; }
        .side-diff-title-new { color: #7ee787; }
        .side-line {
            padding: 2px 6px;
            margin: 1px 0;
            border-radius: 3px;
            white-space: pre-wrap;
            word-break: break-all;
            line-height: 1.4;
        }
        .side-added {
            background-color: #1c4428;
            color: #7ee787;
        }
        .side-removed {
            background-color: #4c1d1d;
            color: #f85149;
        }
        .side-unchanged {
            color: #8b949e;
        }
    </style>
    <div class="side-diff-container">
        <div class="side-diff-panel">
            <div class="side-diff-title side-diff-title-old">BEFORE</div>
    """
    ]

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for line in old_lines[i1:i2]:
                html_parts.append(f'<div class="side-line side-unchanged">{escape_html_diff(line)}</div>')
        elif tag in ("delete", "replace"):
            for line in old_lines[i1:i2]:
                html_parts.append(f'<div class="side-line side-removed">{escape_html_diff(line)}</div>')

    html_parts.append(
        """
        </div>
        <div class="side-diff-panel">
            <div class="side-diff-title side-diff-title-new">AFTER</div>
    """
    )

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for line in new_lines[j1:j2]:
                html_parts.append(f'<div class="side-line side-unchanged">{escape_html_diff(line)}</div>')
        elif tag in ("insert", "replace"):
            for line in new_lines[j1:j2]:
                html_parts.append(f'<div class="side-line side-added">{escape_html_diff(line)}</div>')

    html_parts.append(
        """
        </div>
    </div>
    """
    )
    return "".join(html_parts)

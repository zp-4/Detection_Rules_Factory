"""Add CTI library table and rule.cti_refs for traceability."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine, text
from db.session import DATABASE_URL


def _sqlite_columns(conn, table: str):
    r = conn.execute(text(f"PRAGMA table_info({table})"))
    return {row[1] for row in r}


def migrate():
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
    )

    if not DATABASE_URL.startswith("sqlite"):
        print("This script targets SQLite; use Alembic for Postgres.")
        return

    with engine.connect() as conn:
        tables = {r[0] for r in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))}
        if "rule_implementations" not in tables:
            print("Skipping: database not initialized (run init_db.py first).")
            return

        if "cti_library_entries" not in tables:
            conn.execute(
                text(
                    """
                    CREATE TABLE cti_library_entries (
                        id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                        title VARCHAR(512) NOT NULL,
                        source_kind VARCHAR(32) NOT NULL,
                        url VARCHAR(2048),
                        excerpt_text TEXT,
                        metadata TEXT,
                        tags TEXT,
                        created_by VARCHAR(100),
                        created_at DATETIME,
                        updated_at DATETIME
                    )
                    """
                )
            )
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_cti_lib_title ON cti_library_entries(title)"))
            conn.execute(
                text("CREATE INDEX IF NOT EXISTS idx_cti_lib_kind ON cti_library_entries(source_kind)")
            )
            conn.commit()
            print("[OK] cti_library_entries")

        rule_cols = _sqlite_columns(conn, "rule_implementations")
        if "cti_refs" not in rule_cols:
            conn.execute(text("ALTER TABLE rule_implementations ADD COLUMN cti_refs TEXT"))
            conn.commit()
            print("[OK] rule_implementations.cti_refs")

    print("\n[OK] migrate_add_cti_theme completed")


if __name__ == "__main__":
    migrate()

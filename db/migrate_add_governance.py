"""Add rule archival columns for governance (retention / catalogue hiding)."""
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

        cols = _sqlite_columns(conn, "rule_implementations")
        if "archived_at" not in cols:
            conn.execute(text("ALTER TABLE rule_implementations ADD COLUMN archived_at DATETIME"))
            conn.commit()
            print("[OK] rule_implementations.archived_at")
        if "archived_by" not in cols:
            conn.execute(text("ALTER TABLE rule_implementations ADD COLUMN archived_by VARCHAR(100)"))
            conn.commit()
            print("[OK] rule_implementations.archived_by")
        try:
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS idx_rule_archived_at ON rule_implementations(archived_at)"
                )
            )
            conn.commit()
        except Exception as e:
            print(f"  Note: index: {e}")

    print("\n[OK] migrate_add_governance completed")


if __name__ == "__main__":
    migrate()

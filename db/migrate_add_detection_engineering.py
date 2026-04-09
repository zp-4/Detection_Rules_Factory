"""Add detection_engineering.playbook JSON on rule_implementations."""
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
        print("This script targets SQLite PRAGMA; use Alembic for Postgres.")
        return

    with engine.connect() as conn:
        tables = {r[0] for r in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))}
        if "rule_implementations" not in tables:
            print("Skipping: database not initialized (run init_db.py first).")
            return

        rule_cols = _sqlite_columns(conn, "rule_implementations")
        if "playbook" not in rule_cols:
            conn.execute(text("ALTER TABLE rule_implementations ADD COLUMN playbook TEXT"))
            conn.commit()
            print("[OK] rule_implementations.playbook")

    print("\n[OK] migrate_add_detection_engineering completed")


if __name__ == "__main__":
    migrate()

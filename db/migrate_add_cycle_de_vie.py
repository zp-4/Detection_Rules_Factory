"""Add cycle-de-vie fields: review queue on use_cases, tickets + ops status on rules."""
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
        if "use_cases" not in tables or "rule_implementations" not in tables:
            print("Skipping: database not initialized (run init_db.py first).")
            return

        uc_cols = _sqlite_columns(conn, "use_cases")
        if "review_priority" not in uc_cols:
            conn.execute(
                text(
                    "ALTER TABLE use_cases ADD COLUMN review_priority INTEGER DEFAULT 3"
                )
            )
            conn.commit()
            print("[OK] use_cases.review_priority")
        if "review_sla_days" not in uc_cols:
            conn.execute(text("ALTER TABLE use_cases ADD COLUMN review_sla_days INTEGER"))
            conn.commit()
            print("[OK] use_cases.review_sla_days")
        if "review_assignee" not in uc_cols:
            conn.execute(
                text("ALTER TABLE use_cases ADD COLUMN review_assignee VARCHAR(100)")
            )
            conn.commit()
            print("[OK] use_cases.review_assignee")
        if "review_started_at" not in uc_cols:
            conn.execute(text("ALTER TABLE use_cases ADD COLUMN review_started_at DATETIME"))
            conn.commit()
            print("[OK] use_cases.review_started_at")
        if "review_due_at" not in uc_cols:
            conn.execute(text("ALTER TABLE use_cases ADD COLUMN review_due_at DATETIME"))
            conn.commit()
            print("[OK] use_cases.review_due_at")

        rule_cols = _sqlite_columns(conn, "rule_implementations")
        if "ticket_refs" not in rule_cols:
            conn.execute(text("ALTER TABLE rule_implementations ADD COLUMN ticket_refs TEXT"))
            conn.commit()
            print("[OK] rule_implementations.ticket_refs")
        if "operational_status" not in rule_cols:
            conn.execute(
                text(
                    "ALTER TABLE rule_implementations ADD COLUMN operational_status VARCHAR(32) DEFAULT 'production'"
                )
            )
            conn.commit()
            print("[OK] rule_implementations.operational_status")

        try:
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS idx_rule_operational_status ON rule_implementations(operational_status)"
                )
            )
            conn.commit()
            print("[OK] index operational_status")
        except Exception as e:
            print(f"  Note: index: {e}")

    print("\n[OK] migrate_add_cycle_de_vie completed")


if __name__ == "__main__":
    migrate()

"""Add config_audit_logs for admin platform / quota / YAML change tracking."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine, text
from db.session import DATABASE_URL


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
        if "quota_usage" not in tables:
            print("Skipping: database not initialized (run init_db.py first).")
            return

        if "config_audit_logs" not in tables:
            conn.execute(
                text(
                    """
                    CREATE TABLE config_audit_logs (
                        id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                        occurred_at DATETIME,
                        actor_username VARCHAR(100) NOT NULL,
                        category VARCHAR(64) NOT NULL,
                        action VARCHAR(128) NOT NULL,
                        detail TEXT
                    )
                    """
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_config_audit_logs_occurred_at ON config_audit_logs(occurred_at)"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_config_audit_logs_actor_username ON config_audit_logs(actor_username)"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_config_audit_logs_category ON config_audit_logs(category)"
                )
            )
            conn.commit()
            print("[OK] config_audit_logs")
        else:
            print("[OK] config_audit_logs already present")

    print("\n[OK] migrate_add_config_audit completed")


if __name__ == "__main__":
    migrate()

"""Add comment.mentions and user_notifications for collaboration theme."""
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
        if "comments" not in tables:
            print("Skipping: database not initialized (run init_db.py first).")
            return

        if "user_notifications" not in tables:
            conn.execute(
                text(
                    """
                    CREATE TABLE user_notifications (
                        id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                        username VARCHAR(100) NOT NULL,
                        message TEXT NOT NULL,
                        read_at DATETIME,
                        created_at DATETIME,
                        entity_type VARCHAR(50),
                        entity_id INTEGER,
                        comment_id INTEGER
                    )
                    """
                )
            )
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_user_notifications_username ON user_notifications(username)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_user_notifications_read_at ON user_notifications(read_at)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_user_notifications_created_at ON user_notifications(created_at)"))
            conn.commit()
            print("[OK] user_notifications")

        c_cols = _sqlite_columns(conn, "comments")
        if "mentions" not in c_cols:
            conn.execute(text("ALTER TABLE comments ADD COLUMN mentions TEXT"))
            conn.commit()
            print("[OK] comments.mentions")

    print("\n[OK] migrate_add_collaboration completed")


if __name__ == "__main__":
    migrate()

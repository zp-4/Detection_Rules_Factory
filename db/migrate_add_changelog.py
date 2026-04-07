"""Migration script to add RuleChangeLog table for comprehensive audit trail."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import inspect
from db.session import engine, SessionLocal
from db.models import Base, RuleChangeLog


def migrate():
    """Add RuleChangeLog table if it doesn't exist."""
    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()
    
    if "rule_change_logs" not in existing_tables:
        print("Creating rule_change_logs table...")
        RuleChangeLog.__table__.create(engine)
        print("[OK] rule_change_logs table created successfully!")
    else:
        print("[OK] rule_change_logs table already exists.")
    
    print("\nMigration complete!")


if __name__ == "__main__":
    migrate()


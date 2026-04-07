"""Migration script to add enabled column to rule_implementations."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine, text
from db.session import DATABASE_URL

def migrate():
    """Add enabled column to rule_implementations table."""
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
    
    with engine.connect() as conn:
        # Check if column already exists
        result = conn.execute(text("PRAGMA table_info(rule_implementations)"))
        columns = [row[1] for row in result]
        
        # Add enabled column if it doesn't exist
        if 'enabled' not in columns:
            print("Adding 'enabled' column...")
            conn.execute(text("ALTER TABLE rule_implementations ADD COLUMN enabled BOOLEAN DEFAULT 1"))
            conn.commit()
            print("[OK] Added 'enabled' column")
        else:
            print("[OK] 'enabled' column already exists")
        
        # Create index on enabled if it doesn't exist
        try:
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_rule_enabled ON rule_implementations(enabled)"))
            conn.commit()
            print("[OK] Created index on enabled")
        except Exception as e:
            print(f"  Note: Index may already exist: {e}")
        
        print("\n[OK] Migration completed!")

if __name__ == "__main__":
    migrate()


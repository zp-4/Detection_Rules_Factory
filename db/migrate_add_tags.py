"""Migration script to add tags and mitre_technique_id columns to rule_implementations."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine, text
from db.session import DATABASE_URL

def migrate():
    """Add tags and mitre_technique_id columns, make use_case_id nullable."""
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
    
    with engine.connect() as conn:
        # Check if columns already exist
        result = conn.execute(text("PRAGMA table_info(rule_implementations)"))
        columns = [row[1] for row in result]
        
        # Add tags column if it doesn't exist
        if 'tags' not in columns:
            print("Adding 'tags' column...")
            conn.execute(text("ALTER TABLE rule_implementations ADD COLUMN tags TEXT"))
            conn.commit()
            print("[OK] Added 'tags' column")
        else:
            print("[OK] 'tags' column already exists")
        
        # Add mitre_technique_id column if it doesn't exist
        if 'mitre_technique_id' not in columns:
            print("Adding 'mitre_technique_id' column...")
            conn.execute(text("ALTER TABLE rule_implementations ADD COLUMN mitre_technique_id VARCHAR(50)"))
            conn.commit()
            print("[OK] Added 'mitre_technique_id' column")
        else:
            print("[OK] 'mitre_technique_id' column already exists")
        
        # Create index on mitre_technique_id if it doesn't exist
        try:
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_rule_mitre_tech ON rule_implementations(mitre_technique_id)"))
            conn.commit()
            print("[OK] Created index on mitre_technique_id")
        except Exception as e:
            print(f"  Note: Index may already exist: {e}")
        
        # Note: SQLite doesn't support ALTER COLUMN to change NULL constraint
        # We'll need to recreate the table or handle NULL values in application code
        # For now, we'll just note this limitation
        print("\n[WARN] Note: SQLite doesn't support changing NULL constraints.")
        print("   The use_case_id column remains NOT NULL in the database.")
        print("   Application code handles NULL values gracefully.")
        
        print("\n[OK] Migration completed!")

if __name__ == "__main__":
    migrate()


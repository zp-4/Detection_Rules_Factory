"""Migration script to add mitre_technique_ids and last_mapping_analysis columns."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine, text
from db.session import DATABASE_URL

def migrate():
    """Add mitre_technique_ids and last_mapping_analysis columns."""
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
    
    with engine.connect() as conn:
        # Check if columns already exist
        result = conn.execute(text("PRAGMA table_info(rule_implementations)"))
        columns = [row[1] for row in result]
        
        # Add mitre_technique_ids column if it doesn't exist
        if 'mitre_technique_ids' not in columns:
            print("Adding 'mitre_technique_ids' column...")
            conn.execute(text("ALTER TABLE rule_implementations ADD COLUMN mitre_technique_ids TEXT"))
            conn.commit()
            print("[OK] Added 'mitre_technique_ids' column")
        else:
            print("[OK] 'mitre_technique_ids' column already exists")
        
        # Add last_mapping_analysis column if it doesn't exist
        if 'last_mapping_analysis' not in columns:
            print("Adding 'last_mapping_analysis' column...")
            conn.execute(text("ALTER TABLE rule_implementations ADD COLUMN last_mapping_analysis TEXT"))
            conn.commit()
            print("[OK] Added 'last_mapping_analysis' column")
        else:
            print("[OK] 'last_mapping_analysis' column already exists")
        
        print("\n[OK] Migration completed!")

if __name__ == "__main__":
    migrate()


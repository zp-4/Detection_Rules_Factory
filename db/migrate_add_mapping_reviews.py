"""Migration script to add mapping_reviews table."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine, text

# Import from session to get DATABASE_URL
from db.session import DATABASE_URL

def migrate():
    """Create mapping_reviews table if it doesn't exist."""
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
    
    with engine.connect() as conn:
        # Check if table exists
        if "sqlite" in DATABASE_URL:
            result = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='mapping_reviews'"))
        else:
            result = conn.execute(text("SELECT table_name FROM information_schema.tables WHERE table_name='mapping_reviews'"))
        
        table_exists = result.fetchone() is not None
        
        if not table_exists:
            print("Creating 'mapping_reviews' table...")
            
            # Create table
            conn.execute(text("""
                CREATE TABLE mapping_reviews (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id INTEGER NOT NULL,
                    reviewed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    reviewed_by VARCHAR(100) NOT NULL,
                    previous_technique_id VARCHAR(50),
                    previous_technique_name VARCHAR(255),
                    action_type VARCHAR(50) NOT NULL,
                    new_technique_id VARCHAR(50),
                    new_technique_name VARCHAR(255),
                    additional_techniques TEXT,
                    ai_analysis TEXT,
                    recommendation TEXT,
                    reviewer_notes TEXT,
                    FOREIGN KEY (rule_id) REFERENCES rule_implementations(id)
                )
            """))
            
            # Create indexes
            conn.execute(text("CREATE INDEX idx_mapping_rule_id ON mapping_reviews(rule_id)"))
            conn.execute(text("CREATE INDEX idx_mapping_reviewed_at ON mapping_reviews(reviewed_at)"))
            
            conn.commit()
            print("[OK] Created 'mapping_reviews' table with indexes")
        else:
            print("[OK] 'mapping_reviews' table already exists")
        
        print("\n[OK] Migration completed!")

if __name__ == "__main__":
    migrate()


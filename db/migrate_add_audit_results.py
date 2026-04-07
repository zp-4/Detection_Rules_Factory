"""Migration script to add last_audit_results column to rule_implementations table."""
import sys
import os
import sqlite3

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def migrate():
    """Add last_audit_results column to rule_implementations table."""
    db_path = "usecase_factory.db"
    
    if not os.path.exists(db_path):
        print(f"[ERROR] Database file {db_path} not found.")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if column already exists
        cursor.execute("PRAGMA table_info(rule_implementations)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'last_audit_results' in columns:
            print("[OK] Column 'last_audit_results' already exists.")
            conn.close()
            return True
        
        # Add the column
        print("Adding 'last_audit_results' column to rule_implementations table...")
        cursor.execute("""
            ALTER TABLE rule_implementations 
            ADD COLUMN last_audit_results TEXT
        """)
        
        conn.commit()
        conn.close()
        
        print("[OK] Column 'last_audit_results' added successfully.")
        return True
        
    except Exception as e:
        print(f"[ERROR] Error adding column: {e}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("Migration: Add last_audit_results to rule_implementations")
    print("=" * 60)
    print()
    
    success = migrate()
    
    if success:
        print()
        print("[OK] Migration completed successfully.")
    else:
        print()
        print("[ERROR] Migration failed.")
        sys.exit(1)


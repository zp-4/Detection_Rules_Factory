"""Initialize database and seed demo data."""
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from db.migrations import init_database
from seeds.demo_data import seed_demo_data


def main():
    """Initialize database and seed demo data."""
    print("=" * 60)
    print("Use Case Factory - Database Initialization")
    print("=" * 60)
    print()
    
    # Initialize database
    print("Step 1: Creating database tables...")
    try:
        init_database()
        print("[OK] Database tables created successfully")
    except Exception as e:
        print(f"[ERROR] Error creating tables: {e}")
        return
    
    print()
    
    # Seed demo data
    print("Step 2: Seeding demo data...")
    try:
        seed_demo_data()
        print("[OK] Demo data seeded successfully")
    except Exception as e:
        print(f"[WARN] Warning: Could not seed demo data: {e}")
        print("   Database is initialized but empty.")
    
    print()
    print("=" * 60)
    print("[OK] Initialization complete!")
    print("=" * 60)
    print()
    print("Next steps:")
    print("1. Run: streamlit run app.py")
    print("2. Login with username: admin")
    print("3. Explore the Use Cases catalogue")


if __name__ == "__main__":
    main()


"""Database migration and initialization script."""
from db.session import init_db, engine
from db.models import Base
from sqlalchemy import inspect


def check_tables_exist():
    """Check if tables exist."""
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    return len(tables) > 0


def init_database():
    """Initialize database - create all tables."""
    print("Initializing database...")
    init_db()
    print("Database initialized successfully!")
    
    # Verify tables
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    print(f"Created {len(tables)} tables: {', '.join(tables)}")


if __name__ == "__main__":
    init_database()


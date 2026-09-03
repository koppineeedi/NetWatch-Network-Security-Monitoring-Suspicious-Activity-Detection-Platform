import os
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, declarative_base

# PostgreSQL connection string with SQLite fallback for local development & standalone ease
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./netwatch.db")

if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL, connect_args={"check_same_thread": False}
    )
else:
    engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def apply_schema_migrations():
    """
    Ensures lightweight SQLite database schema is safely upgraded when new models/fields are added.
    """
    try:
        inspector = inspect(engine)
        tables = inspector.get_table_names()

        if "users" in tables:
            columns = [c["name"] for c in inspector.get_columns("users")]
            with engine.connect() as conn:
                if "username" not in columns:
                    conn.execute(text("ALTER TABLE users ADD COLUMN username VARCHAR"))
                if "email" not in columns:
                    conn.execute(text("ALTER TABLE users ADD COLUMN email VARCHAR"))
                if "password_hash" not in columns:
                    conn.execute(text("ALTER TABLE users ADD COLUMN password_hash VARCHAR"))
                if "role" not in columns:
                    conn.execute(text("ALTER TABLE users ADD COLUMN role VARCHAR DEFAULT 'ANALYST'"))
                if "is_active" not in columns:
                    conn.execute(text("ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT 1"))
                if "created_at" not in columns:
                    conn.execute(text("ALTER TABLE users ADD COLUMN created_at DATETIME"))
                if "updated_at" not in columns:
                    conn.execute(text("ALTER TABLE users ADD COLUMN updated_at DATETIME"))
                if "last_login_at" not in columns:
                    conn.execute(text("ALTER TABLE users ADD COLUMN last_login_at DATETIME"))
                conn.commit()

        if "alerts" in tables:
            columns = [c["name"] for c in inspector.get_columns("alerts")]
            with engine.connect() as conn:
                if "risk_score" not in columns:
                    conn.execute(text("ALTER TABLE alerts ADD COLUMN risk_score FLOAT DEFAULT 0.0"))
                if "updated_at" not in columns:
                    conn.execute(text("ALTER TABLE alerts ADD COLUMN updated_at DATETIME"))
                if "resolution" not in columns:
                    conn.execute(text("ALTER TABLE alerts ADD COLUMN resolution VARCHAR"))
                if "resolution_reason" not in columns:
                    conn.execute(text("ALTER TABLE alerts ADD COLUMN resolution_reason TEXT"))
                conn.commit()

        if "investigations" in tables:
            columns = [c["name"] for c in inspector.get_columns("investigations")]
            with engine.connect() as conn:
                if "verdict" not in columns:
                    conn.execute(text("ALTER TABLE investigations ADD COLUMN verdict VARCHAR"))
                if "verdict_reason" not in columns:
                    conn.execute(text("ALTER TABLE investigations ADD COLUMN verdict_reason TEXT"))
                if "closed_at" not in columns:
                    conn.execute(text("ALTER TABLE investigations ADD COLUMN closed_at DATETIME"))
                conn.commit()

        if "audit_logs" in tables:
            columns = [c["name"] for c in inspector.get_columns("audit_logs")]
            with engine.connect() as conn:
                if "resource_type" not in columns:
                    conn.execute(text("ALTER TABLE audit_logs ADD COLUMN resource_type VARCHAR"))
                if "resource_id" not in columns:
                    conn.execute(text("ALTER TABLE audit_logs ADD COLUMN resource_id VARCHAR"))
                if "details" not in columns:
                    conn.execute(text("ALTER TABLE audit_logs ADD COLUMN details TEXT"))
                conn.commit()
    except Exception:
        pass

apply_schema_migrations()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

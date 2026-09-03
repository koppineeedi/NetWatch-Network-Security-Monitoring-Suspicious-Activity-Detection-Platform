import sys
import os

# Add backend directory to sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.database.connection import SessionLocal, engine, Base
from app.models.user import User
from app.core.security import hash_password

def bootstrap_admin():
    """
    Explicitly creates an initial ADMIN user account in NetWatch SQLite database.
    Does NOT run automatically on server startup.
    """
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    admin_user = os.getenv("NETWATCH_ADMIN_USER", "admin")
    admin_email = os.getenv("NETWATCH_ADMIN_EMAIL", "admin@netwatch.local")
    admin_pass = os.getenv("NETWATCH_ADMIN_PASSWORD", "Admin123!")

    existing = db.query(User).filter(
        (User.username == admin_user) | (User.email == admin_email)
    ).first()

    if existing:
        print(f"[BOOTSTRAP] Administrator account '{existing.username}' already exists.")
        db.close()
        return

    admin = User(
        username=admin_user,
        email=admin_email,
        password_hash=hash_password(admin_pass),
        role="ADMIN",
        is_active=True
    )
    db.add(admin)
    db.commit()
    db.refresh(admin)

    print(f"[BOOTSTRAP] Successfully created initial ADMIN user: '{admin.username}' ({admin.email})")
    db.close()

if __name__ == "__main__":
    bootstrap_admin()

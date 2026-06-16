"""Database seeding — creates a default admin if no users exist.

SECURITY:
    - Only runs when the users table is completely empty (first boot).
    - Credentials are pulled from env vars; falls back to safe demo defaults.
    - Never overwrites existing users.
"""

import os
from sqlmodel import select
from backend.database import get_db_context
from backend.models import User, UserRole
from backend.security import get_password_hash


def seed_default_admin() -> None:
    """Create a default admin account if the database has zero users."""
    with get_db_context() as db:
        existing = db.exec(select(User)).first()
        if existing:
            return  # Already seeded — do nothing

        username = os.getenv("DEFAULT_ADMIN_USER", "admin")
        password = os.getenv("DEFAULT_ADMIN_PASS", "GuardianShield2024!")
        email = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@guardianshield.com")

        admin = User(
            username=username,
            email=email,
            full_name="System Administrator",
            hashed_password=get_password_hash(password),
            role=UserRole.ADMIN,
            is_active=True,
        )
        db.add(admin)
        db.commit()
        print(f"[SEED] Default admin created: {username} / {password}")
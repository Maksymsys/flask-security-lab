import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import NullPool

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def required(name):
    """Return an environment variable or stop with a clear message."""
    value = os.getenv(name)
    if not value:
        print(f"[!] Environment variable {name} is not set (check your .env file)")
        sys.exit(1)
    return value


def apply_schema():
    # Superuser connection is used only to create roles, tables and policies
    superuser_url = required("SUPERUSER_DB_URL")

    # The web_app_user password is taken from the app's own DATABASE_URL
    web_app_password = make_url(required("DATABASE_URL")).password
    if not web_app_password:
        print("[!] DATABASE_URL does not contain a password for web_app_user")
        sys.exit(1)

    # Role passwords are passed to the session as settings, so they are not
    # hardcoded in schema.sql (the SQL file can read them with current_setting())
    role_passwords = {
        "app.web_app_password": web_app_password,
        "app.migration_password": required("MIGRATION_DB_PASSWORD"),
        "app.analytics_password": required("ANALYTICS_DB_PASSWORD"),
    }
    schema_sql = (BASE_DIR / "schema.sql").read_text(encoding="utf-8")

    print("[*] Connecting to PostgreSQL and applying schema.sql...")
    engine = create_engine(
        superuser_url,
        isolation_level="AUTOCOMMIT",
        poolclass=NullPool,
        hide_parameters=True,  # keep passwords out of SQLAlchemy error messages
    )
    try:
        with engine.connect() as connection:
            for key, value in role_passwords.items():
                # is_local = false: the setting lasts for the whole session
                connection.execute(
                    text("SELECT set_config(:key, :value, false)"),
                    {"key": key, "value": value},
                )
            connection.exec_driver_sql(schema_sql)
    except SQLAlchemyError as error:
        print(f"[!] Database initialization failed: {getattr(error, 'orig', error)}")
        print("[i] Check that PostgreSQL is running and SUPERUSER_DB_URL is correct.")
        sys.exit(1)
    finally:
        engine.dispose()

    print("[+] Schema, roles, grants and RLS policies applied successfully.")


if __name__ == "__main__":
    apply_schema()

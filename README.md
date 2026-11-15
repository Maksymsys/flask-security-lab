# flask-security-lab

A small Flask + PostgreSQL lab where I practice **defensive web security**.
This is a learning project, not production code.

## What's inside

- **PostgreSQL least privilege**: three roles (`web_app_user`, `migration_user`,
  `read_only_analytics`) with separate permissions. The web app never connects as a superuser.
- **Row Level Security (RLS)** on `orders`: a user can only read their own rows.
  The user identity comes from the server-side session, not from the URL.
- **UUID primary keys** instead of sequential IDs.
- **Registration, login and logout**: password hashing (Werkzeug), HttpOnly + SameSite session cookie,
  the session is reset after login, and login errors do not reveal whether an email exists.
- **Honey-URLs**: requests to paths like `/.env`, `/wp-admin`, `/.git` get a normal 404,
  and the client IP is banned for 24 hours (Redis, with an in-memory fallback if Redis is down).
- **Honeypot field** in the registration form to catch simple bots.
- **Telegram alert** for each new ban (one alert per ban, no spam).
- The app refuses to start if it is configured to connect as the `postgres` superuser.

## Quick start

1. Install Python 3.12+, PostgreSQL and (optionally) Redis.
2. Create a virtual environment and install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Copy `.env.example` to `.env` and fill in your own values
   (generate `SECRET_KEY` with `python -c "import secrets; print(secrets.token_hex(32))"`).
4. Set the database passwords in `.env` (the password inside `DATABASE_URL`, plus
   `MIGRATION_DB_PASSWORD` and `ANALYTICS_DB_PASSWORD`), then create the schema.
   `init_db.py` passes the passwords to `schema.sql`, so they are never hardcoded in the SQL file:
   ```
   python init_db.py
   ```
   Optional: `python check_services.py` checks that Redis and the Telegram bot are reachable.
5. Run the app:
   ```
   python app.py
   ```

## Project layout

| File | Purpose |
|---|---|
| `app.py` | Flask app: ban middleware, honey-URLs, register/login/logout, orders endpoints |
| `init_db.py` | Applies `schema.sql` with a superuser connection |
| `check_services.py` | Manual check that Redis and the Telegram bot respond |
| `schema.sql` | Tables, roles, grants, RLS policies |
| `.env.example` | Template for environment variables (no real secrets) |

## Known limitations / TODO

- No rate limiting on `/login` yet.
- No CSRF tokens yet (cookies use `SameSite=Lax`).
- No security headers (CSP, X-Frame-Options, etc.) and no `Secure` flag on the session cookie yet (needed with HTTPS).
- RLS is enabled only on `orders`, not on `users`.
- The app uses the default `postgres` database; a real setup should use a dedicated one.
- Automated tests (pytest) are planned but not written yet.
- Honey-URL bans rely on `request.remote_addr`; behind a reverse proxy this needs extra care.

## Security notes

- Never commit `.env`, tokens or passwords. `.gitignore` already excludes `.env` and `venv/`.
- Only test on your own machine and your own systems.

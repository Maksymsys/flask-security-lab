SET password_encryption = 'scram-sha-256';

DO $$
DECLARE
    spec record;
BEGIN
    FOR spec IN
        SELECT * FROM (VALUES
            ('web_app_user', current_setting('app.web_app_password')),
            ('migration_user', current_setting('app.migration_password')),
            ('read_only_analytics', current_setting('app.analytics_password'))
        ) AS t(role_name, role_password)
    LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = spec.role_name) THEN
            EXECUTE 'ALTER ROLE ' || quote_ident(spec.role_name)
                || ' WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '
                || quote_literal(spec.role_password);
        ELSE
            EXECUTE 'CREATE ROLE ' || quote_ident(spec.role_name)
                || ' WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '
                || quote_literal(spec.role_password);
        END IF;
    END LOOP;
END
$$;

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS orders (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    amount NUMERIC(10, 2) NOT NULL CHECK (amount >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS orders_user_id_idx ON orders (user_id);

ALTER TABLE users OWNER TO migration_user;
ALTER TABLE orders OWNER TO migration_user;

DO $$
DECLARE
    db text := quote_ident(current_database());
BEGIN
    EXECUTE 'REVOKE ALL ON DATABASE ' || db || ' FROM PUBLIC';
    EXECUTE 'GRANT CONNECT ON DATABASE ' || db || ' TO web_app_user, migration_user, read_only_analytics';
END
$$;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO web_app_user, read_only_analytics;
GRANT ALL ON SCHEMA public TO migration_user;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC, web_app_user, read_only_analytics;
GRANT SELECT, INSERT, UPDATE ON users, orders TO web_app_user;
GRANT SELECT (id, email, created_at) ON users TO read_only_analytics;
GRANT SELECT ON orders TO read_only_analytics;

REVOKE ALL ON
    pg_catalog.pg_roles,
    pg_catalog.pg_user,
    pg_catalog.pg_group,
    pg_catalog.pg_database,
    pg_catalog.pg_settings,
    pg_catalog.pg_stat_activity
FROM PUBLIC;

ALTER TABLE orders ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS user_orders_isolation_policy ON orders;
DROP POLICY IF EXISTS analytics_read_policy ON orders;

CREATE POLICY user_orders_isolation_policy ON orders
    FOR ALL
    TO web_app_user
    USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid)
    WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid);

CREATE POLICY analytics_read_policy ON orders
    FOR SELECT
    TO read_only_analytics
    USING (true);
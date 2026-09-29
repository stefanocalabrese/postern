-- The two database roles Postern runs as. Superuser, once, BEFORE migrations.
--
-- WHAT THIS CLOSES. `audit_log` refuses UPDATE, DELETE and TRUNCATE through a
-- pair of triggers migration f1860c110112 installs, and a trigger is only as
-- strong as the privileges of whoever can turn it off. Two statements turn it
-- off: the table's OWNER runs `ALTER TABLE audit_log DISABLE TRIGGER`, and a
-- SUPERUSER runs `SET session_replication_role = replica`. Both are measured,
-- performed rather than described, in `tests/test_audit_append_only.py`. While
-- one role is simultaneously the owner, the migration runner and a superuser,
-- the append-only control protects the record against an attacker who can run
-- one statement and not against one who can run two.
--
-- So there are two roles and neither is the other:
--
--   postern_owner  owns every table, runs `alembic upgrade head`, and is the
--                  only role that can reach the triggers. Nothing serves a
--                  request as this role.
--   postern_app    owns nothing, is not a superuser, and holds exactly the
--                  privileges `sql/02-grants.sql` names. Both services connect
--                  as this one, through POSTERN_DATABASE_URL.
--
-- WHY THIS IS A SCRIPT AND NOT A MIGRATION. A role is cluster-wide and a
-- migration is per-database, so a second database on the same cluster running
-- the same chain would find the role already there; the revision that created
-- it has no honest downgrade; and, decisively, a `GRANT ... TO postern_app`
-- inside a revision makes the whole chain refuse to apply anywhere that role
-- does not exist -- every database an operator has today, and every disposable
-- container a test starts. Privileges are a deployment's shape, not the
-- schema's, and they are applied by a principal the schema never sees.
--
-- IDEMPOTENT, and re-running it is the supported way to repair a role whose
-- attributes drifted: the CREATE is guarded on `pg_roles` and the ALTER runs
-- unconditionally. An `ALTER ROLE` naming only these attributes leaves a
-- password already set on the role alone, which is what makes re-running safe
-- on a live deployment.
--
-- NO PASSWORD IS SET HERE, deliberately. A credential in a repository is a
-- credential in every clone of it. Both roles are created able to log in and
-- unable to authenticate; the operator supplies the secret out of band
-- (`ALTER ROLE postern_app PASSWORD ...` from a secrets manager, or an IAM /
-- peer authentication method that needs none). `docker-compose.yml` sets two
-- throwaway ones inline for local development, beside the throwaway superuser
-- password that is already there.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'postern_owner') THEN
        CREATE ROLE postern_owner;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'postern_app') THEN
        CREATE ROLE postern_app;
    END IF;
END
$$;

-- Spelled out rather than left to the CREATE ROLE defaults, which is more than
-- documentation: this is the line that repairs a role somebody granted
-- SUPERUSER to at three in the morning, and it is the reason re-running this
-- script is worth doing before believing the control holds.
ALTER ROLE postern_owner
    WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE postern_app
    WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

-- Per-database, and the reason this script is run once per database rather
-- than once per cluster. GRANT takes no parameter for the database name, so
-- `current_database()` reaches it through `format`, which also means this file
-- carries no database name to get wrong.
DO $$
BEGIN
    EXECUTE format(
        'GRANT CONNECT ON DATABASE %I TO postern_owner, postern_app',
        current_database()
    );
END
$$;

GRANT USAGE, CREATE ON SCHEMA public TO postern_owner;
GRANT USAGE ON SCHEMA public TO postern_app;

-- A role that owns nothing must not be able to start owning something. CREATE
-- on a schema is enough to build a table, copy rows into it, and have somewhere
-- to stage what an erasing statement could not reach. PostgreSQL 15 removed
-- PUBLIC's CREATE on `public` by default, so on 15 and above the first of these
-- is already true and is stated anyway -- an operator restoring an older dump,
-- or running this against 14, gets the same shape from the same file.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM postern_app;

-- Everything postern_app may do. Run as postern_owner, AFTER every migration.
--
-- WHY AFTER, AND WHY EVERY TIME. A grant names a table, so it cannot be issued
-- before `alembic upgrade head` creates one, and a migration that adds a table
-- leaves that table reachable by nobody until this runs again. Re-running is
-- free and is the intended operation: GRANT and REVOKE are idempotent, and the
-- REVOKE pair at the top makes this file AUTHORITATIVE rather than additive --
-- a privilege granted here by hand last month is removed by the next run
-- unless it is also written down here.
--
-- WHY postern_owner AND NOT A SUPERUSER. A superuser could run it and the
-- result would be identical. Running it as the owner proves the owner is
-- sufficient, which is the operator's real situation: the role that migrates is
-- the role that grants, and neither a deploy pipeline nor a CI job needs a
-- superuser credential to finish a release.
--
-- THE GRANT SET IS DERIVED FROM THE THREE MODULES THAT ISSUE STATEMENTS, not
-- from a summary. `tests/test_application_role.py`'s module docstring carries
-- the derivation and `EXPECTED_TABLE_PRIVILEGES` carries it as data, compared
-- against what PostgreSQL reports for this role, so an extra grant below fails
-- the build exactly as loudly as a missing one.
--
-- WHAT IS DELIBERATELY ABSENT:
--
--   UPDATE, DELETE, TRUNCATE on audit_log. This is the whole point. For this
--   role the append-only control is not a trigger that could be disabled, it
--   is a privilege that was never held, so PostgreSQL refuses at the ACL check
--   before the trigger is consulted.
--
--   DELETE on challenges. There is no delete helper in
--   `packages/postern-core/src/postern_core/store/challenges.py` and no caller
--   that wants one; an expired challenge is transitioned, not removed.
--
--   INSERT on consents, and USAGE on its sequence. Granting consent belongs to
--   a flow this repository has not built. Nothing in either service writes that
--   table, so nothing here lets them.
--
--   Everything on alembic_version. The schema version is the migration
--   runner's business and the migration runner is the owner. No module under
--   `services/` or `postern_core` reads it.

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM postern_app;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM postern_app;

GRANT SELECT, INSERT ON audit_log TO postern_app;
GRANT SELECT ON consents TO postern_app;
GRANT SELECT, INSERT, UPDATE ON challenges TO postern_app;

-- SELECT on audit_log is not redundant beside INSERT, and it is the one grant
-- here that reads as though it were. The ORM writes a row through
-- `session.add`, which for a server-generated primary key emits
-- `INSERT ... RETURNING id`, and RETURNING reads a column. Without SELECT the
-- append fails with `permission denied for table audit_log` on the INSERT --
-- and decision record 0006 makes a failed audit write a failed tool call, so
-- dropping this grant takes the whole read surface down.

-- Sequences are resolved through `pg_get_serial_sequence` rather than spelled
-- `audit_log_id_seq`, so a later migration that rebuilds either column cannot
-- leave this file granting on a name that no longer exists. It would raise
-- here instead, which is the direction worth having: a deploy that stops is
-- cheaper than a service that cannot insert.
DO $$
DECLARE
    target text;
    sequence_name text;
BEGIN
    FOREACH target IN ARRAY ARRAY['audit_log', 'challenges']
    LOOP
        sequence_name := pg_get_serial_sequence(target, 'id');
        IF sequence_name IS NULL THEN
            RAISE EXCEPTION
                'table %.id has no sequence to grant USAGE on; postern_app cannot INSERT',
                target;
        END IF;
        EXECUTE format('GRANT USAGE ON SEQUENCE %s TO postern_app', sequence_name);
    END LOOP;
END
$$;

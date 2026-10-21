-- On Postgres 14 and older, every role may create objects in schema public
-- by default. nfx_app could then plant a function or table there that a
-- SECURITY DEFINER function resolves before the real one. nfx_owner has its
-- own explicit grant (internal/db/db.go), so taking the default away from
-- everyone else changes nothing it relies on. On Postgres 15+ this is
-- already the default and the statement is a no-op.
--
-- Runs as the migrating admin, not nfx_owner: the schema isn't nfx_owner's.

REVOKE CREATE ON SCHEMA public FROM PUBLIC;

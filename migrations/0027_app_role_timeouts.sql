-- Timeouts for the application's database sessions (reliability review).
--
-- nfx_app had none, and lib/pq has no read deadline, so a statement stuck on
-- a lock, or a transaction left open, waited forever: a worker loop could
-- hang without logging anything while alerts went unprocessed. Now a lock
-- wait fails after 10s and a statement after 60s (both are retried as
-- transient errors), and a session idle inside a transaction for 5 minutes
-- is ended. Nothing the app does legitimately comes near these: network
-- calls happen outside transactions. Takes effect on new connections.
-- Migrations run as the admin role and aren't affected.

ALTER ROLE nfx_app SET lock_timeout = '10s';
ALTER ROLE nfx_app SET statement_timeout = '60s';
ALTER ROLE nfx_app SET idle_in_transaction_session_timeout = '5min';

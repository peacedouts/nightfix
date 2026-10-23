-- Audit rows are written only through nfx_audit (security review).
--
-- nfx_audit (SECURITY DEFINER) numbers each event and computes its link in
-- the hash chain. nfx_app could also INSERT into audit_events directly, and
-- the chain's hash is unkeyed, so anyone holding the application's database
-- credentials could append made-up events that still verify. The app only
-- ever writes through nfx_audit (db.Tx.Audit); it keeps SELECT.

SET LOCAL lock_timeout = '5s';
SET ROLE nfx_owner;

REVOKE INSERT ON audit_events FROM nfx_app;

RESET ROLE;

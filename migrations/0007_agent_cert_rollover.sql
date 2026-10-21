-- Certificate renewal no longer locks an agent out when the renewal
-- response is lost. Renewing used to replace the agent's serial at once, so
-- if the new certificate never arrived the agent's old one was rejected on
-- every call and it could never recover. The previous serial now stays
-- valid until the agent first authenticates with the new one, or until the
-- old certificate expires (at most 24h), whichever is first.

SET ROLE nfx_owner;

ALTER TABLE agents ADD COLUMN prev_cert_serial text UNIQUE;
ALTER TABLE agents ADD COLUMN prev_cert_expires_at timestamptz;

DROP FUNCTION nfx_route_agent(text);
CREATE FUNCTION nfx_route_agent(p_serial text)
RETURNS TABLE (org_id uuid, agent_id uuid, is_current boolean, has_prev boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  SELECT a.org_id, a.id, a.cert_serial = p_serial, a.prev_cert_serial IS NOT NULL
  FROM agents a
  WHERE a.revoked_at IS NULL
    AND (a.cert_serial = p_serial OR (a.prev_cert_serial = p_serial AND a.prev_cert_expires_at > now()))
$$;
GRANT EXECUTE ON FUNCTION nfx_route_agent(text) TO nfx_app;

RESET ROLE;

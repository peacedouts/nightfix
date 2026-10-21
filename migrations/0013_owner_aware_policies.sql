-- Finish the managed-Postgres change begun in 0002_z: admit nfx_owner in
-- every tenant policy created since (0003 onward, and the daily partitions
-- made before 0011). 0011 already creates new partitions with this policy.
--
-- New tenant tables must use this policy shape from the start:
--   USING (org_id = nfx_org() OR current_user = 'nfx_owner')
--   WITH CHECK (org_id = nfx_org() OR current_user = 'nfx_owner')
-- internal/db tests check every RLS table and partition.
--
-- Numbered after main's 0009–0012 (PR #12). An earlier draft of this file
-- was 0009 and also redefined nfx_ensure_partitions; 0011 supersedes that,
-- so this file only touches policies (idempotent: safe on any database).

SET ROLE nfx_owner;

DO $$
DECLARE r record; col text;
BEGIN
  FOR r IN SELECT tablename FROM pg_policies WHERE schemaname = 'public' AND policyname = 'tenant_isolation' LOOP
    col := CASE WHEN r.tablename = 'orgs' THEN 'id' ELSE 'org_id' END;
    EXECUTE format('ALTER POLICY tenant_isolation ON public.%I USING (%I = public.nfx_org() OR current_user = %L) WITH CHECK (%I = public.nfx_org() OR current_user = %L)',
                   r.tablename, col, 'nfx_owner', col, 'nfx_owner');
  END LOOP;
END $$;

RESET ROLE;

-- +goose Up

-- An account and an adopt key are made by the operator's commands
-- (dromas-server account, as the tables' owner), never by serve: serve
-- reads an account, takes a use of an adopt key and sweeps one past its
-- expiry, but inserts or updates no account and inserts no adopt key. So
-- no role but the owner may, whatever the default privileges granted it: a
-- role serve runs as, broken into, then cannot make an account or set
-- unmetered on one, nor make an adopt key, as Let's Encrypt grants each of
-- its components only the writes it makes, table by table (its
-- sa/db/02-users.sql, read 2026-11-08).
-- +goose StatementBegin
DO $$
DECLARE
	r record;
	g oid;
BEGIN
	FOR r IN SELECT * FROM (VALUES ('accounts', ARRAY['INSERT', 'UPDATE']), ('adopt_keys', ARRAY['INSERT'])) AS v (t, privileges) LOOP
		FOR g IN
			SELECT DISTINCT a.grantee
			FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
			WHERE c.oid = r.t::regclass AND a.grantee <> c.relowner AND a.privilege_type = ANY (r.privileges)
		LOOP
			EXECUTE format('REVOKE %s ON %I FROM ', array_to_string(r.privileges, ', '), r.t)
				|| CASE WHEN g = 0 THEN 'PUBLIC' ELSE g::regrole::text END;
		END LOOP;
	END LOOP;
END
$$;
-- +goose StatementEnd

-- +goose Up

-- A revocation is kept for good (PROTOCOL.md §11.15), and so is an
-- account: dromas-server deletes neither, so no role but the tables' owner
-- may, whatever the default privileges granted it. A role serve runs as,
-- broken into, then cannot take a revocation back, as Let's Encrypt's
-- storage authority may delete no certificate or revocation of one (its
-- sa/db/02-users.sql, read 2026-11-07).
-- +goose StatementBegin
DO $$
DECLARE
	t text;
	g oid;
BEGIN
	FOREACH t IN ARRAY ARRAY['revocations', 'accounts'] LOOP
		FOR g IN
			SELECT DISTINCT a.grantee
			FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
			WHERE c.oid = t::regclass AND a.grantee <> c.relowner AND a.privilege_type IN ('DELETE', 'TRUNCATE')
		LOOP
			EXECUTE format('REVOKE DELETE, TRUNCATE ON %I FROM ', t)
				|| CASE WHEN g = 0 THEN 'PUBLIC' ELSE g::regrole::text END;
		END LOOP;
	END LOOP;
END
$$;
-- +goose StatementEnd

-- And an update only adds to what the row revokes: the address's
-- revocation, once there, stays as it is; the revocation of certificates
-- only rises; the address and its identity never change. The trigger and
-- its function are the owner's, which no other role can drop or disable.
-- +goose StatementBegin
CREATE FUNCTION revocations_only_add() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	IF NEW.addr IS DISTINCT FROM OLD.addr OR NEW.identity IS DISTINCT FROM OLD.identity THEN
		RAISE EXCEPTION 'a revocation''s address and identity never change' USING ERRCODE = 'check_violation';
	END IF;
	IF OLD.revocation IS NOT NULL AND NEW.revocation IS DISTINCT FROM OLD.revocation THEN
		RAISE EXCEPTION 'a revocation of the address, once kept, never changes' USING ERRCODE = 'check_violation';
	END IF;
	IF OLD.through IS NOT NULL AND (NEW.through IS NULL OR NEW.through < OLD.through) THEN
		RAISE EXCEPTION 'a revocation of certificates is never lowered' USING ERRCODE = 'check_violation';
	END IF;
	RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER revocations_only_add BEFORE UPDATE ON revocations FOR EACH ROW EXECUTE FUNCTION revocations_only_add();

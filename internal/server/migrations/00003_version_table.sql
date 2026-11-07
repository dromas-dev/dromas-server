-- +goose Up

-- goose's table of versions, which the default privileges granted the
-- runtime role as they grant it every table: serve and account read it
-- (schemaReady) and write nothing to it, so the role keeps SELECT alone.
-- +goose StatementBegin
DO $$
DECLARE
	g oid;
BEGIN
	FOR g IN
		SELECT DISTINCT a.grantee
		FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
		WHERE c.oid = 'goose_db_version'::regclass AND a.grantee <> c.relowner AND a.privilege_type <> 'SELECT'
	LOOP
		EXECUTE 'REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON goose_db_version FROM '
			|| CASE WHEN g = 0 THEN 'PUBLIC' ELSE g::regrole::text END;
	END LOOP;
END
$$;
-- +goose StatementEnd

-- +goose Up

-- A revocation is kept for good (PROTOCOL.md §11.15), whatever a role's
-- grants: 00004 revokes DELETE and TRUNCATE from the roles it finds, and a
-- grant made since gives them back, so a row trigger refuses every DELETE and
-- a statement trigger every TRUNCATE, the owner's included, as
-- revocations_only_add refuses an update that takes anything away. Each is
-- the owner's, which no other role can drop or disable.
-- +goose StatementBegin
CREATE FUNCTION revocations_kept() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	RAISE EXCEPTION 'a revocation is kept for good' USING ERRCODE = 'check_violation';
END
$$;
-- +goose StatementEnd
CREATE TRIGGER revocations_kept BEFORE DELETE ON revocations FOR EACH ROW EXECUTE FUNCTION revocations_kept();
CREATE TRIGGER revocations_kept_whole BEFORE TRUNCATE ON revocations FOR EACH STATEMENT EXECUTE FUNCTION revocations_kept();

-- And a revocation of certificates is replaced only by one through a higher
-- serial: at the serial it holds, its document and signature stay as they
-- are, as dromas-server's own write keeps them (Revoke).
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION revocations_only_add() RETURNS trigger LANGUAGE plpgsql AS $$
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
	IF OLD.through IS NOT NULL AND NEW.through = OLD.through
		AND (NEW.revoked_certs IS DISTINCT FROM OLD.revoked_certs OR NEW.revoked_certs_sig IS DISTINCT FROM OLD.revoked_certs_sig) THEN
		RAISE EXCEPTION 'a revocation of certificates through a serial, once kept, never changes' USING ERRCODE = 'check_violation';
	END IF;
	RETURN NEW;
END
$$;
-- +goose StatementEnd

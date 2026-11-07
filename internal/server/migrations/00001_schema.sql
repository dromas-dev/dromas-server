-- +goose Up

-- Every time is ms since 1970, written by dromas-server's clock but the
-- sweep's, which reads the database's. Every key and hash is its bytes.

CREATE TABLE mailboxes (
	addr bytea PRIMARY KEY,
	identity bytea NOT NULL,
	created bigint NOT NULL,
	state text NOT NULL,
	statement bytea NOT NULL,
	statement_sig bytea NOT NULL,
	rank numeric(20) NOT NULL,
	signer bytea NOT NULL,
	senders text[] NOT NULL,
	retired jsonb NOT NULL,
	acl bytea,
	account text,
	expires_at bigint,
	rev bigint NOT NULL
);
CREATE INDEX mailboxes_account ON mailboxes (account) WHERE account IS NOT NULL;
CREATE INDEX mailboxes_expires_at ON mailboxes (expires_at) WHERE expires_at IS NOT NULL;
-- An update's change carries every column: a row passes 2 kB, and a
-- column stored out of line that the update left alone is otherwise sent
-- without its value.
ALTER TABLE mailboxes REPLICA IDENTITY FULL;

CREATE TABLE revocations (
	addr bytea PRIMARY KEY,
	identity bytea NOT NULL,
	revocation bytea,
	revoked_certs bytea,
	revoked_certs_sig bytea,
	through numeric(20)
);
ALTER TABLE revocations REPLICA IDENTITY FULL;

-- A queue: a row is inserted at a send and deleted at its ack, within
-- minutes, so its dead rows are vacuumed often.
CREATE TABLE messages (
	box bytea NOT NULL,
	id bytea NOT NULL,
	size integer NOT NULL,
	received_at bigint NOT NULL,
	expires_at bigint NOT NULL,
	PRIMARY KEY (box, id)
) WITH (autovacuum_vacuum_scale_factor = 0.01, autovacuum_vacuum_insert_scale_factor = 0.01);
CREATE INDEX messages_live ON messages (box, received_at, id) INCLUDE (size);
CREATE INDEX messages_expires_at ON messages (expires_at);

CREATE TABLE accounts (
	id text PRIMARY KEY,
	unmetered boolean NOT NULL,
	rev bigint NOT NULL
);

CREATE TABLE adopt_keys (
	account text NOT NULL,
	hash bytea NOT NULL,
	uses integer NOT NULL,
	expires_at bigint NOT NULL,
	PRIMARY KEY (account, hash)
);
CREATE INDEX adopt_keys_expires_at ON adopt_keys (expires_at);

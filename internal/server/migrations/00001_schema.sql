-- +goose Up

-- Every time but the sweep's is written by dromas-server's clock, to the
-- millisecond. Every key and hash is its bytes, of its one length.

CREATE TABLE accounts (
	id text PRIMARY KEY,
	unmetered boolean NOT NULL,
	rev bigint NOT NULL
);

CREATE TABLE mailboxes (
	addr bytea PRIMARY KEY CHECK (octet_length(addr) = 48),
	identity bytea NOT NULL,
	created timestamptz NOT NULL,
	statement bytea NOT NULL,
	statement_sig bytea NOT NULL,
	-- A certificate's serial, any uint64.
	rank numeric(20) NOT NULL CHECK (rank >= 0),
	signer bytea NOT NULL CHECK (octet_length(signer) = 32),
	senders text[] NOT NULL,
	retired jsonb NOT NULL,
	-- The ACL's document exactly as it was checked: json keeps its text.
	acl json,
	account text REFERENCES accounts (id) DEFERRABLE INITIALLY DEFERRED,
	expires_at timestamptz,
	rev bigint NOT NULL CHECK (rev >= 1)
);
CREATE INDEX mailboxes_account ON mailboxes (account) WHERE account IS NOT NULL;
CREATE INDEX mailboxes_expires_at ON mailboxes (expires_at) WHERE expires_at IS NOT NULL;
-- An update's change carries every column: a row passes 2 kB, and a
-- column stored out of line that the update left alone is otherwise sent
-- without its value.
ALTER TABLE mailboxes REPLICA IDENTITY FULL;

CREATE TABLE revocations (
	addr bytea PRIMARY KEY CHECK (octet_length(addr) = 48),
	identity bytea NOT NULL,
	revocation bytea,
	revoked_certs bytea,
	revoked_certs_sig bytea,
	through numeric(20) CHECK (through >= 1),
	CHECK ((through IS NULL) = (revoked_certs IS NULL) AND (through IS NULL) = (revoked_certs_sig IS NULL))
);
ALTER TABLE revocations REPLICA IDENTITY FULL;

-- A queue: a row is inserted at a send and deleted at its ack, within
-- minutes, so its dead rows are vacuumed often. A message expires
-- protocol.Retention after its received_at.
CREATE TABLE messages (
	box bytea NOT NULL CHECK (octet_length(box) = 48),
	id bytea NOT NULL CHECK (octet_length(id) = 32),
	size integer NOT NULL CHECK (size >= 0),
	received_at timestamptz NOT NULL,
	PRIMARY KEY (box, id)
) WITH (autovacuum_vacuum_scale_factor = 0.01, autovacuum_vacuum_insert_scale_factor = 0.01);
CREATE INDEX messages_live ON messages (box, received_at, id) INCLUDE (size);
CREATE INDEX messages_received_at ON messages (received_at);

CREATE TABLE adopt_keys (
	account text NOT NULL REFERENCES accounts (id) DEFERRABLE INITIALLY DEFERRED,
	hash bytea NOT NULL CHECK (octet_length(hash) = 32),
	uses integer NOT NULL CHECK (uses >= 0),
	expires_at timestamptz NOT NULL,
	PRIMARY KEY (account, hash)
);
CREATE INDEX adopt_keys_expires_at ON adopt_keys (expires_at);

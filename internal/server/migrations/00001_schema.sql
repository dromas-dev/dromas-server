-- +goose Up

-- Every time but the sweep's is written by dromas-server's clock, to the
-- millisecond. Every key and hash is its bytes, of its one length.

-- Text keys sort bytewise ("C"), so an index never depends on the
-- operating system's locale data.
CREATE TABLE accounts (
	id text COLLATE "C" PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9-]{0,31}$'),
	unmetered boolean NOT NULL,
	rev bigint NOT NULL
);

CREATE TABLE mailboxes (
	addr bytea PRIMARY KEY CHECK (octet_length(addr) = 48),
	identity bytea NOT NULL,
	created timestamptz NOT NULL,
	-- The address is the SHA-384 of the identity document.
	CHECK (addr = sha384(identity)),
	statement bytea NOT NULL,
	statement_sig bytea NOT NULL,
	-- A certificate's serial, any uint64.
	rank numeric(20) NOT NULL CHECK (rank BETWEEN 0 AND 18446744073709551615),
	signer bytea NOT NULL CHECK (octet_length(signer) = 32),
	senders text[] NOT NULL CHECK (array_position(senders, NULL) IS NULL),
	retired jsonb NOT NULL,
	-- The ACL's document exactly as it was checked: json keeps its text.
	acl json,
	-- Checked at commit: an adopt's transaction refuses a spent key before
	-- an account the key's row would have named is missing.
	account text COLLATE "C" REFERENCES accounts (id) DEFERRABLE INITIALLY DEFERRED,
	expires_at timestamptz,
	rev bigint NOT NULL CHECK (rev >= 1)
-- A record of a few kB stays in its row, so a read takes no out-of-line
-- fetch, and an update's old row, which REPLICA IDENTITY FULL logs, is
-- the row alone.
) WITH (toast_tuple_target = 8160);
CREATE INDEX mailboxes_account ON mailboxes (account) WHERE account IS NOT NULL;
CREATE INDEX mailboxes_expires_at ON mailboxes (expires_at) WHERE expires_at IS NOT NULL;
-- An update's change carries every column: a record with a large ACL is
-- stored partly out of line, and a column so stored that the update left
-- alone is otherwise sent without its value.
ALTER TABLE mailboxes REPLICA IDENTITY FULL;

CREATE TABLE revocations (
	addr bytea PRIMARY KEY CHECK (octet_length(addr) = 48),
	identity bytea NOT NULL,
	CHECK (addr = sha384(identity)),
	revocation bytea,
	revoked_certs bytea,
	revoked_certs_sig bytea,
	through numeric(20) CHECK (through BETWEEN 1 AND 18446744073709551615),
	CHECK ((through IS NULL) = (revoked_certs IS NULL) AND (through IS NULL) = (revoked_certs_sig IS NULL)),
	-- A row exists only holding a revocation.
	CHECK (revocation IS NOT NULL OR through IS NOT NULL)
);
ALTER TABLE revocations REPLICA IDENTITY FULL;

-- A queue: a row is inserted at a send and deleted at its ack, within
-- minutes, so its dead rows are vacuumed often. A message expires
-- protocol.Retention after its received_at.
CREATE TABLE messages (
	box bytea NOT NULL CHECK (octet_length(box) = 48),
	id bytea NOT NULL CHECK (octet_length(id) = 32),
	size integer NOT NULL CHECK (size BETWEEN 0 AND 16777216), -- protocol.MaxCiphertext
	received_at timestamptz NOT NULL,
	PRIMARY KEY (box, id)
) WITH (autovacuum_vacuum_scale_factor = 0.01, autovacuum_vacuum_insert_scale_factor = 0.01, autovacuum_vacuum_cost_delay = 0);
CREATE INDEX messages_live ON messages (box, received_at, id) INCLUDE (size);
CREATE INDEX messages_received_at ON messages (received_at);

CREATE TABLE adopt_keys (
	account text COLLATE "C" NOT NULL REFERENCES accounts (id) DEFERRABLE INITIALLY DEFERRED,
	hash bytea NOT NULL CHECK (octet_length(hash) = 32),
	uses integer NOT NULL CHECK (uses >= 0),
	expires_at timestamptz NOT NULL,
	PRIMARY KEY (account, hash)
);
CREATE INDEX adopt_keys_expires_at ON adopt_keys (expires_at);

-- The feed's publication, dromas_<schema>: the tables memory holds. A later
-- migration changes it with ALTER PUBLICATION.
-- +goose StatementBegin
DO $$
BEGIN
	EXECUTE format('CREATE PUBLICATION %I FOR TABLE mailboxes, revocations, messages, accounts', 'dromas_' || current_schema());
END
$$;
-- +goose StatementEnd

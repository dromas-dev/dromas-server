-- +goose Up

-- A record's version is its created beside its rev: a record made again at
-- its address once the sweep took the one before starts its rev over
-- (version, in store.go). The comment is psql's \d+ of the column.
COMMENT ON COLUMN mailboxes.rev IS 'The record''s revision, raised by each write and starting over in a record made again at its address: the feed applies a record by (created, rev)';

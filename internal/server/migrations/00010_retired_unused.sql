-- +goose Up

-- No build from this one on reads or writes mailboxes.retired: a new
-- prekey's key is the client's rule (PROTOCOL.md §12.4). The column gets a
-- constant default, a change of the catalog alone that rewrites nothing, so
-- an insert that does not name it still meets NOT NULL; the build before,
-- which names it, still runs. Expand, then contract (ARCHITECTURE.md
-- § Storage): a later migration drops it, once no running build names it.
ALTER TABLE mailboxes ALTER COLUMN retired SET DEFAULT '[]'::jsonb;
COMMENT ON COLUMN mailboxes.retired IS 'Read and written by nothing: a later migration drops it';

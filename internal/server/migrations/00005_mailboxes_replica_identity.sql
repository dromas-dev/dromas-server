-- +goose Up

-- A record's update logs its key alone as the old row (the primary key,
-- REPLICA IDENTITY DEFAULT), not the record whole: a renewal writes the
-- record anew, and the old record logged beside it measures about a third
-- of the WAL a renewal writes, decoded again by every feed. A column stored out
-- of line that an update leaves alone then comes without its value, and the
-- feed takes the row as one that does not read: memory forgets the address,
-- and its next use reads it (ARCHITECTURE.md § Following the feed). Every
-- column of a record is in line below toast_tuple_target but a large ACL,
-- and every update but an adopt's and a leave's writes the ACL anew.
ALTER TABLE mailboxes REPLICA IDENTITY DEFAULT;

-- +goose Up

-- mailboxes.retired, which no build from 00010 on reads or writes: the
-- contract step of 00010's expand (ARCHITECTURE.md § Storage), so the build
-- before, which does not name it, still runs on this schema while a deploy
-- rolls. Dropping a column changes the catalog alone and rewrites nothing.
-- squawk's ban-drop-column: no running build names the column (00010).
-- squawk-ignore ban-drop-column
ALTER TABLE mailboxes DROP COLUMN retired;

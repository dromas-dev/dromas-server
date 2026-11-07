-- +goose Up

-- The feed's publication, named for dromas-server as other tools name
-- theirs (Debezium's dbz_publication, Electric's
-- electric_publication_<stream id>; their docs, read 2026-11-07):
-- dromas_publication, and in a schema other than public,
-- dromas_publication_<schema>, so that schemas of one database keep
-- publications apart. 00001's dromas_<schema> stays for the build before
-- this one, which reads it while a deploy rolls; a later migration drops it.
-- +goose StatementBegin
DO $$
BEGIN
	EXECUTE format('CREATE PUBLICATION %I FOR TABLE mailboxes, revocations, messages, accounts',
		CASE current_schema() WHEN 'public' THEN 'dromas_publication' ELSE 'dromas_publication_' || current_schema() END);
END
$$;
-- +goose StatementEnd

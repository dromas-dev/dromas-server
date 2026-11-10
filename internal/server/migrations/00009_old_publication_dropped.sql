-- +goose Up

-- 00001's publication, dromas_<schema>, which no build reads: the feed reads
-- 00002's (publicationName, in migrate.go).
-- +goose StatementBegin
DO $$
BEGIN
	EXECUTE format('DROP PUBLICATION IF EXISTS %I', 'dromas_' || current_schema());
END
$$;
-- +goose StatementEnd

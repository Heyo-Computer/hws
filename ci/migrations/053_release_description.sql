-- Descriptive source metadata stays outside the immutable artifact manifest.
ALTER TABLE ci_release_build ADD COLUMN IF NOT EXISTS commit_message TEXT;

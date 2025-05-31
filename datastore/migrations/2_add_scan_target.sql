-- ALTER TABLE scan ADD COLUMN id text;
ALTER TABLE scan ADD COLUMN target_id text;

-- Recreate indexes with updated uniqueness constraint
DROP INDEX IF EXISTS idx_scan_folder;
CREATE UNIQUE INDEX idx_scan_folder_target ON scan(folder, target_id);

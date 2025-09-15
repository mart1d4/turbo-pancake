-- Up Migration
ALTER TABLE users ADD COLUMN banner_color_new INT NULL;
ALTER TABLE users ADD COLUMN accent_color_new INT NULL;
ALTER TABLE roles ADD COLUMN color_new INT NULL;


-- Populate the new integer columns by converting existing data
UPDATE users
SET banner_color_new = (
    CASE
        WHEN banner_color LIKE '#%' THEN ('x' || SUBSTRING(banner_color FROM 2))::bit(24)::int
        ELSE ('x' || banner_color)::bit(24)::int
    END
)
WHERE banner_color IS NOT NULL;

UPDATE users
SET accent_color_new = (
    CASE
        WHEN accent_color LIKE '#%' THEN ('x' || SUBSTRING(accent_color FROM 2))::bit(24)::int
        ELSE ('x' || accent_color)::bit(24)::int
    END
)
WHERE accent_color IS NOT NULL;

UPDATE roles
SET color_new = (
    CASE
        WHEN color LIKE '#%' THEN ('x' || SUBSTRING(color FROM 2))::bit(24)::int
        ELSE ('x' || color)::bit(24)::int
    END
)
WHERE color IS NOT NULL;


-- Drop the old VARCHAR columns
ALTER TABLE users DROP COLUMN banner_color;
ALTER TABLE users DROP COLUMN accent_color;
ALTER TABLE roles DROP COLUMN color;


-- Rename the new INT columns to the original names
ALTER TABLE users RENAME COLUMN banner_color_new TO banner_color;
ALTER TABLE users RENAME COLUMN accent_color_new TO accent_color;
ALTER TABLE roles RENAME COLUMN color_new TO color;


-- Re-add NOT NULL and DEFAULT constraints
ALTER TABLE users ALTER COLUMN banner_color SET NOT NULL;

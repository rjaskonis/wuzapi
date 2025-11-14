package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog/log"
)

type Migration struct {
	ID      int
	Name    string
	UpSQL   string
	DownSQL string
}

var migrations = []Migration{
	{
		ID:    1,
		Name:  "initial_schema",
		UpSQL: initialSchemaSQL,
	},
	{
		ID:   2,
		Name: "add_proxy_url",
		UpSQL: `
            -- PostgreSQL version
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_schema = current_schema()
                    AND table_name = 'users' AND column_name = 'proxy_url'
                ) THEN
                    ALTER TABLE users ADD COLUMN proxy_url TEXT DEFAULT '';
                END IF;
            END $$;
            
            -- SQLite version (handled in code)
            `,
	},
	{
		ID:    3,
		Name:  "change_id_to_string",
		UpSQL: changeIDToStringSQL,
	},
	{
		ID:    4,
		Name:  "add_s3_support",
		UpSQL: addS3SupportSQL,
	},
	{
		ID:    5,
		Name:  "add_message_history",
		UpSQL: addMessageHistorySQL,
	},
	{
		ID:    6,
		Name:  "add_quoted_message_id",
		UpSQL: addQuotedMessageIDSQL,
	},
	{
		ID:    7,
		Name:  "add_hmac_key",
		UpSQL: addHmacKeySQL,
	},
	{
		ID:    8,
		Name:  "add_data_json",
		UpSQL: addDataJsonSQL,
	},
	{
		ID:    9,
		Name:  "add_chatwoot_support",
		UpSQL: addChatwootSupportSQL,
	},
	{
		ID:    10,
		Name:  "add_chatwoot_inbox_id",
		UpSQL: addChatwootInboxIDSQL,
	},
	{
		ID:    11,
		Name:  "add_chatwoot_sign_message",
		UpSQL: addChatwootSignMessageSQL,
	},
	{
		ID:    12,
		Name:  "add_chatwoot_mark_read",
		UpSQL: addChatwootMarkReadSQL,
	},
	{
		ID:    13,
		Name:  "add_days_to_sync_history",
		UpSQL: addDaysToSyncHistorySQL,
	},
	{
		ID:    14,
		Name:  "add_ignore_groups",
		UpSQL: addIgnoreGroupsSQL,
	},
	{
		ID:    15,
		Name:  "add_chatwoot_import_database_uri",
		UpSQL: addChatwootImportDatabaseURISQL,
	},
	{
		ID:    16,
		Name:  "add_chatwoot_import_database_ssl",
		UpSQL: addChatwootImportDatabaseSSLSQL,
	},
	{
		ID:    17,
		Name:  "add_chatwoot_import_messages",
		UpSQL: addChatwootImportMessagesSQL,
	},
	{
		ID:    18,
		Name:  "add_push_name_to_message_history",
		UpSQL: addPushNameToMessageHistorySQL,
	},
	{
		ID:    19,
		Name:  "rename_push_name_to_sender_name",
		UpSQL: renamePushNameToSenderNameSQL,
	},
}

const changeIDToStringSQL = `
-- Migration to change ID from integer to random string
DO $$
BEGIN
    -- Only execute if the column is currently integer type
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema()
        AND table_name = 'users' AND column_name = 'id' AND data_type = 'integer'
    ) THEN
        -- For PostgreSQL
        ALTER TABLE users ADD COLUMN new_id TEXT;
		UPDATE users SET new_id = md5(random()::text || id::text || clock_timestamp()::text);
		ALTER TABLE users DROP CONSTRAINT users_pkey;
        ALTER TABLE users DROP COLUMN id CASCADE;
        ALTER TABLE users RENAME COLUMN new_id TO id;
        ALTER TABLE users ALTER COLUMN id SET NOT NULL;
        ALTER TABLE users ADD PRIMARY KEY (id);
    END IF;
END $$;
`

const initialSchemaSQL = `
-- PostgreSQL version
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables 
        WHERE table_schema = current_schema()
        AND table_name = 'users'
    ) THEN
        CREATE TABLE users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            token TEXT NOT NULL,
            webhook TEXT NOT NULL DEFAULT '',
            jid TEXT NOT NULL DEFAULT '',
            qrcode TEXT NOT NULL DEFAULT '',
            connected INTEGER,
            expiration INTEGER,
            events TEXT NOT NULL DEFAULT '',
            proxy_url TEXT DEFAULT ''
        );
    END IF;
END $$;

-- SQLite version (handled in code)
`

const addS3SupportSQL = `
-- PostgreSQL version
DO $$
BEGIN
    -- Add S3 configuration columns if they don't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 's3_enabled') THEN
        ALTER TABLE users ADD COLUMN s3_enabled BOOLEAN DEFAULT FALSE;
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 's3_endpoint') THEN
        ALTER TABLE users ADD COLUMN s3_endpoint TEXT DEFAULT '';
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 's3_region') THEN
        ALTER TABLE users ADD COLUMN s3_region TEXT DEFAULT '';
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 's3_bucket') THEN
        ALTER TABLE users ADD COLUMN s3_bucket TEXT DEFAULT '';
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 's3_access_key') THEN
        ALTER TABLE users ADD COLUMN s3_access_key TEXT DEFAULT '';
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 's3_secret_key') THEN
        ALTER TABLE users ADD COLUMN s3_secret_key TEXT DEFAULT '';
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 's3_path_style') THEN
        ALTER TABLE users ADD COLUMN s3_path_style BOOLEAN DEFAULT TRUE;
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 's3_public_url') THEN
        ALTER TABLE users ADD COLUMN s3_public_url TEXT DEFAULT '';
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 'media_delivery') THEN
        ALTER TABLE users ADD COLUMN media_delivery TEXT DEFAULT 'base64';
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 's3_retention_days') THEN
        ALTER TABLE users ADD COLUMN s3_retention_days INTEGER DEFAULT 30;
    END IF;
END $$;
`

const addMessageHistorySQL = `
-- PostgreSQL version
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = 'message_history') THEN
        CREATE TABLE message_history (
            id SERIAL PRIMARY KEY,
            user_id TEXT NOT NULL,
            chat_jid TEXT NOT NULL,
            sender_jid TEXT NOT NULL,
            message_id TEXT NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            message_type TEXT NOT NULL,
            text_content TEXT,
            media_link TEXT,
            UNIQUE(user_id, message_id)
        );
        CREATE INDEX idx_message_history_user_chat_timestamp ON message_history (user_id, chat_jid, timestamp DESC);
    END IF;
    
    -- Add history column to users table if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 'history') THEN
        ALTER TABLE users ADD COLUMN history INTEGER DEFAULT 0;
    END IF;
END $$;
`

const addQuotedMessageIDSQL = `
-- PostgreSQL version
DO $$
BEGIN
    -- Add quoted_message_id column to message_history table if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'message_history' AND column_name = 'quoted_message_id') THEN
        ALTER TABLE message_history ADD COLUMN quoted_message_id TEXT;
    END IF;
END $$;
`

const addDataJsonSQL = `
-- PostgreSQL version
DO $$
BEGIN
    -- Add dataJson column to message_history table if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'message_history' AND column_name = 'datajson') THEN
        ALTER TABLE message_history ADD COLUMN datajson TEXT;
    END IF;
END $$;

-- SQLite version (handled in code)
`

const addPushNameToMessageHistorySQL = `
-- PostgreSQL version
DO $$
BEGIN
    -- Add push_name column to message_history table if it doesn't exist
    -- Place it after sender_jid column (we can't control exact position in PostgreSQL, but it will be added)
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'message_history' AND column_name = 'push_name') THEN
        ALTER TABLE message_history ADD COLUMN push_name TEXT;
    END IF;
END $$;

-- SQLite version (handled in code)
`

const renamePushNameToSenderNameSQL = `
-- PostgreSQL version
DO $$
BEGIN
    -- Rename push_name column to sender_name if push_name exists and sender_name doesn't
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'message_history' AND column_name = 'push_name')
       AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'message_history' AND column_name = 'sender_name') THEN
        ALTER TABLE message_history RENAME COLUMN push_name TO sender_name;
    END IF;
END $$;

-- SQLite version (handled in code)
`

// GenerateRandomID creates a random string ID
func GenerateRandomID() (string, error) {
	bytes := make([]byte, 16) // 128 bits
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random ID: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// Initialize the database with migrations
func initializeSchema(db *sqlx.DB) error {
	// Create migrations table if it doesn't exist
	if err := createMigrationsTable(db); err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Get already applied migrations
	applied, err := getAppliedMigrations(db)
	if err != nil {
		return fmt.Errorf("failed to get applied migrations: %w", err)
	}

	// Verify migration 1: if marked as applied but users table doesn't exist, create it
	if _, ok := applied[1]; ok {
		usersTableExists, err := checkTableExists(db, "users")
		if err != nil {
			return fmt.Errorf("failed to verify users table existence: %w", err)
		}
		if !usersTableExists {
			// Migration 1 was marked as applied but table doesn't exist - create it without recording
			if err := applyMigrationSQLOnly(db, migrations[0]); err != nil {
				return fmt.Errorf("failed to create users table: %w", err)
			}
		} else {
			// Verify all required columns from migration 1 exist
			// If any are missing, add them all
			requiredColumns := map[string]string{
				"id":         "TEXT PRIMARY KEY",
				"name":       "TEXT NOT NULL",
				"token":      "TEXT NOT NULL",
				"webhook":    "TEXT NOT NULL DEFAULT ''",
				"jid":        "TEXT NOT NULL DEFAULT ''",
				"qrcode":     "TEXT NOT NULL DEFAULT ''",
				"connected":  "INTEGER",
				"expiration": "INTEGER",
				"events":     "TEXT NOT NULL DEFAULT ''",
				"proxy_url":  "TEXT DEFAULT ''",
			}
			
			missingColumns := make(map[string]string)
			for colName, colDef := range requiredColumns {
				exists, err := checkColumnExists(db, "users", colName)
				if err != nil {
					return fmt.Errorf("failed to verify column %s: %w", colName, err)
				}
				if !exists {
					missingColumns[colName] = colDef
				}
			}
			
			if len(missingColumns) > 0 {
				// Add all missing columns from migration 1
				if err := addMissingColumnsFromMigration1(db, missingColumns); err != nil {
					return fmt.Errorf("failed to add missing columns from migration 1: %w", err)
				}
			}
		}
	}

	// Verify and re-apply migrations if columns are missing
	// This handles cases where migrations were marked as applied but didn't complete
	if err := verifyAndFixMigrations(db, applied); err != nil {
		return fmt.Errorf("failed to verify migrations: %w", err)
	}

	// Apply missing migrations
	for _, migration := range migrations {
		if _, ok := applied[migration.ID]; !ok {
			if err := applyMigration(db, migration); err != nil {
				return fmt.Errorf("failed to apply migration %d: %w", migration.ID, err)
			}
		}
	}

	return nil
}

// checkTableExists verifies if a table exists in the current schema
func checkTableExists(db *sqlx.DB, tableName string) (bool, error) {
	var exists bool
	var err error

	switch db.DriverName() {
	case "postgres":
		err = db.Get(&exists, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.tables 
				WHERE table_schema = current_schema()
				AND table_name = $1
			)`, tableName)
	case "sqlite":
		err = db.Get(&exists, `
			SELECT EXISTS (
				SELECT 1 FROM sqlite_master 
				WHERE type='table' AND name=?
			)`, tableName)
	default:
		return false, fmt.Errorf("unsupported database driver: %s", db.DriverName())
	}

	if err != nil {
		return false, fmt.Errorf("failed to check table existence: %w", err)
	}

	return exists, nil
}

// checkColumnExists verifies if a column exists in a table
func checkColumnExists(db *sqlx.DB, tableName, columnName string) (bool, error) {
	var exists bool
	var err error

	switch db.DriverName() {
	case "postgres":
		err = db.Get(&exists, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.columns 
				WHERE table_schema = current_schema()
				AND table_name = $1 AND column_name = $2
			)`, tableName, columnName)
	case "sqlite":
		var count int
		err = db.Get(&count, `
			SELECT COUNT(*) FROM pragma_table_info(?)
			WHERE name = ?`, tableName, columnName)
		if err == nil {
			exists = count > 0
		}
	default:
		return false, fmt.Errorf("unsupported database driver: %s", db.DriverName())
	}

	if err != nil {
		return false, fmt.Errorf("failed to check column existence: %w", err)
	}

	return exists, nil
}

// addMissingColumnsFromMigration1 adds missing columns from migration 1 to the users table
// This handles cases where the table exists but was created with an old or incomplete schema
func addMissingColumnsFromMigration1(db *sqlx.DB, missingColumns map[string]string) error {
	tx, err := db.Beginx()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	if db.DriverName() == "sqlite" {
		// For SQLite, add each missing column
		for colName, colDef := range missingColumns {
			// Handle PRIMARY KEY constraint specially - can't add it after table creation
			if colName == "id" && strings.Contains(colDef, "PRIMARY KEY") {
				// Check if id column exists but without PRIMARY KEY
				var count int
				err = tx.Get(&count, `
					SELECT COUNT(*) FROM pragma_table_info(?)
					WHERE name = ?`, "users", "id")
				if err != nil {
					return fmt.Errorf("failed to check id column: %w", err)
				}
				if count == 0 {
					// Can't add PRIMARY KEY column after table creation in SQLite
					// This is a more serious issue - log it but continue with other columns
					log.Warn().Msg("Cannot add PRIMARY KEY id column to existing SQLite table. Table may need to be recreated.")
				}
				continue
			}
			
			// For NOT NULL columns without defaults, add with a default first
			colDefForSQLite := colDef
			if strings.Contains(colDef, "NOT NULL") && !strings.Contains(colDef, "DEFAULT") {
				// Add a default value for NOT NULL columns
				if colName == "name" || colName == "token" {
					colDefForSQLite = strings.Replace(colDef, "NOT NULL", "NOT NULL DEFAULT ''", 1)
				}
			}
			
			if err := addColumnIfNotExistsSQLite(tx, "users", colName, colDefForSQLite); err != nil {
				return fmt.Errorf("failed to add column %s: %w", colName, err)
			}
		}
	} else {
		// PostgreSQL: add each missing column
		for colName, colDef := range missingColumns {
			// Handle PRIMARY KEY constraint specially
			if colName == "id" && strings.Contains(colDef, "PRIMARY KEY") {
				// Check if id column exists but without PRIMARY KEY
				var exists bool
				err = tx.Get(&exists, `
					SELECT EXISTS (
						SELECT 1 FROM information_schema.columns 
						WHERE table_schema = current_schema()
						AND table_name = 'users' AND column_name = 'id'
					)`)
				if err != nil {
					return fmt.Errorf("failed to check id column: %w", err)
				}
				if !exists {
					// Can't add PRIMARY KEY column after table creation easily
					log.Warn().Msg("Cannot add PRIMARY KEY id column to existing PostgreSQL table. Table may need to be recreated.")
				}
				continue
			}
			
			// For NOT NULL columns without defaults, add with a default first
			// This is necessary when the table has existing rows
			colDefForPostgres := colDef
			if strings.Contains(colDef, "NOT NULL") && !strings.Contains(colDef, "DEFAULT") {
				// Add a default value for NOT NULL columns to allow adding to existing tables
				if colName == "name" || colName == "token" {
					colDefForPostgres = strings.Replace(colDef, "NOT NULL", "NOT NULL DEFAULT ''", 1)
				}
			}
			
			// Build the ALTER TABLE statement
			alterSQL := fmt.Sprintf(`
				DO $$
				BEGIN
					IF NOT EXISTS (
						SELECT 1 FROM information_schema.columns 
						WHERE table_schema = current_schema()
						AND table_name = 'users' AND column_name = '%s'
					) THEN
						ALTER TABLE users ADD COLUMN %s %s;
					END IF;
				END $$;
			`, colName, colName, strings.Replace(colDefForPostgres, "PRIMARY KEY", "", -1))
			
			_, err = tx.Exec(alterSQL)
			if err != nil {
				return fmt.Errorf("failed to add column %s: %w", colName, err)
			}
		}
	}

	if err != nil {
		return fmt.Errorf("failed to add missing columns: %w", err)
	}

	return tx.Commit()
}

// verifyAndFixMigrations checks if critical columns from applied migrations exist
// and re-applies migrations if columns are missing
func verifyAndFixMigrations(db *sqlx.DB, applied map[int]struct{}) error {
	// Check if users table exists first
	usersTableExists, err := checkTableExists(db, "users")
	if err != nil {
		return err
	}
	if !usersTableExists {
		return nil // Table doesn't exist, will be created by migration 1
	}

	// Verify migration 4 (S3 support) - check for s3_enabled column
	if _, ok := applied[4]; ok {
		hasS3Enabled, err := checkColumnExists(db, "users", "s3_enabled")
		if err != nil {
			return err
		}
		if !hasS3Enabled {
			// Re-apply migration 4
			if err := applyMigrationSQLOnly(db, migrations[3]); err != nil {
				return fmt.Errorf("failed to re-apply migration 4 (S3 support): %w", err)
			}
		}
	}

	// Verify migration 7 (HMAC key) - check for hmac_key column
	if _, ok := applied[7]; ok {
		hasHmacKey, err := checkColumnExists(db, "users", "hmac_key")
		if err != nil {
			return err
		}
		if !hasHmacKey {
			// Re-apply migration 7
			if err := applyMigrationSQLOnly(db, migrations[6]); err != nil {
				return fmt.Errorf("failed to re-apply migration 7 (HMAC key): %w", err)
			}
		}
	}

	// Verify migration 13 (days_to_sync_history) - check for days_to_sync_history column
	if _, ok := applied[13]; ok {
		hasDaysToSync, err := checkColumnExists(db, "users", "days_to_sync_history")
		if err != nil {
			return err
		}
		if !hasDaysToSync {
			// Re-apply migration 13
			if err := applyMigrationSQLOnly(db, migrations[12]); err != nil {
				return fmt.Errorf("failed to re-apply migration 13 (days_to_sync_history): %w", err)
			}
		}
	}

	// Verify migration 14 (ignore_groups) - check for ignore_groups column
	if _, ok := applied[14]; ok {
		hasIgnoreGroups, err := checkColumnExists(db, "users", "ignore_groups")
		if err != nil {
			return err
		}
		if !hasIgnoreGroups {
			// Re-apply migration 14
			if err := applyMigrationSQLOnly(db, migrations[13]); err != nil {
				return fmt.Errorf("failed to re-apply migration 14 (ignore_groups): %w", err)
			}
		}
	}

	return nil
}

// applyMigrationSQLOnly applies migration SQL without recording it in the migrations table
// This is used when a migration is marked as applied but the expected objects don't exist
// It uses the same logic as applyMigration but doesn't record the migration
func applyMigrationSQLOnly(db *sqlx.DB, migration Migration) error {
	tx, err := db.Beginx()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	// Use the same migration logic as applyMigration
	if migration.ID == 1 {
		// Handle initial schema creation differently per database
		if db.DriverName() == "sqlite" {
			err = createTableIfNotExistsSQLite(tx, "users", `
                CREATE TABLE users (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    token TEXT NOT NULL,
                    webhook TEXT NOT NULL DEFAULT '',
                    jid TEXT NOT NULL DEFAULT '',
                    qrcode TEXT NOT NULL DEFAULT '',
                    connected INTEGER,
                    expiration INTEGER,
                    events TEXT NOT NULL DEFAULT '',
                    proxy_url TEXT DEFAULT ''
                )`)
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 2 {
		if db.DriverName() == "sqlite" {
			err = addColumnIfNotExistsSQLite(tx, "users", "proxy_url", "TEXT DEFAULT ''")
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 3 {
		if db.DriverName() == "sqlite" {
			err = migrateSQLiteIDToString(tx)
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 4 {
		if db.DriverName() == "sqlite" {
			// Handle S3 columns for SQLite
			err = addColumnIfNotExistsSQLite(tx, "users", "s3_enabled", "BOOLEAN DEFAULT 0")
			if err == nil {
				err = addColumnIfNotExistsSQLite(tx, "users", "s3_endpoint", "TEXT DEFAULT ''")
			}
			if err == nil {
				err = addColumnIfNotExistsSQLite(tx, "users", "s3_region", "TEXT DEFAULT ''")
			}
			if err == nil {
				err = addColumnIfNotExistsSQLite(tx, "users", "s3_bucket", "TEXT DEFAULT ''")
			}
			if err == nil {
				err = addColumnIfNotExistsSQLite(tx, "users", "s3_access_key", "TEXT DEFAULT ''")
			}
			if err == nil {
				err = addColumnIfNotExistsSQLite(tx, "users", "s3_secret_key", "TEXT DEFAULT ''")
			}
			if err == nil {
				err = addColumnIfNotExistsSQLite(tx, "users", "s3_path_style", "BOOLEAN DEFAULT 1")
			}
			if err == nil {
				err = addColumnIfNotExistsSQLite(tx, "users", "s3_public_url", "TEXT DEFAULT ''")
			}
			if err == nil {
				err = addColumnIfNotExistsSQLite(tx, "users", "media_delivery", "TEXT DEFAULT 'base64'")
			}
			if err == nil {
				err = addColumnIfNotExistsSQLite(tx, "users", "s3_retention_days", "INTEGER DEFAULT 30")
			}
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 5 {
		if db.DriverName() == "sqlite" {
			// Handle message_history table creation for SQLite
			err = createTableIfNotExistsSQLite(tx, "message_history", `
				CREATE TABLE message_history (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					user_id TEXT NOT NULL,
					chat_jid TEXT NOT NULL,
					sender_jid TEXT NOT NULL,
					message_id TEXT NOT NULL,
					timestamp DATETIME NOT NULL,
					message_type TEXT NOT NULL,
					text_content TEXT,
					media_link TEXT,
					UNIQUE(user_id, message_id)
				)`)
			if err == nil {
				// Create index for SQLite
				_, err = tx.Exec(`
					CREATE INDEX IF NOT EXISTS idx_message_history_user_chat_timestamp 
					ON message_history (user_id, chat_jid, timestamp DESC)`)
			}
			if err == nil {
				// Add history column to users table
				err = addColumnIfNotExistsSQLite(tx, "users", "history", "INTEGER DEFAULT 0")
			}
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 6 {
		if db.DriverName() == "sqlite" {
			// Add quoted_message_id column to message_history table for SQLite
			err = addColumnIfNotExistsSQLite(tx, "message_history", "quoted_message_id", "TEXT")
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 7 {
		if db.DriverName() == "sqlite" {
			// Add hmac_key column as BLOB for encrypted data in SQLite
			err = addColumnIfNotExistsSQLite(tx, "users", "hmac_key", "BLOB")
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 8 {
		if db.DriverName() == "sqlite" {
			// Add dataJson column to message_history table for SQLite
			err = addColumnIfNotExistsSQLite(tx, "message_history", "datajson", "TEXT")
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 9 {
		if db.DriverName() == "sqlite" {
			// Handle Chatwoot columns for SQLite
			err = addColumnIfNotExistsSQLite(tx, "users", "chatwoot_base_url", "TEXT DEFAULT ''")
			if err == nil {
				err = addColumnIfNotExistsSQLite(tx, "users", "chatwoot_account_id", "TEXT DEFAULT ''")
			}
			if err == nil {
				err = addColumnIfNotExistsSQLite(tx, "users", "chatwoot_api_token", "TEXT DEFAULT ''")
			}
			if err == nil {
				err = addColumnIfNotExistsSQLite(tx, "users", "chatwoot_inbox_name", "TEXT DEFAULT ''")
			}
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 10 {
		if db.DriverName() == "sqlite" {
			// Handle Chatwoot inbox_id column for SQLite
			err = addColumnIfNotExistsSQLite(tx, "users", "chatwoot_inbox_id", "TEXT DEFAULT ''")
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 11 {
		if db.DriverName() == "sqlite" {
			// Handle Chatwoot sign message columns for SQLite
			err = addColumnIfNotExistsSQLite(tx, "users", "chatwoot_sign_msg", "BOOLEAN DEFAULT 0")
			if err == nil {
				err = addColumnIfNotExistsSQLite(tx, "users", "chatwoot_sign_delimiter", "TEXT DEFAULT '\n'")
			}
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 12 {
		if db.DriverName() == "sqlite" {
			// Handle Chatwoot mark read column for SQLite
			err = addColumnIfNotExistsSQLite(tx, "users", "chatwoot_mark_read", "BOOLEAN DEFAULT 0")
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 13 {
		if db.DriverName() == "sqlite" {
			// Handle days_to_sync_history column for SQLite
			err = addColumnIfNotExistsSQLite(tx, "users", "days_to_sync_history", "INTEGER DEFAULT 0")
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 14 {
		if db.DriverName() == "sqlite" {
			// Handle ignore_groups column for SQLite
			err = addColumnIfNotExistsSQLite(tx, "users", "ignore_groups", "BOOLEAN DEFAULT 1")
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 15 {
		if db.DriverName() == "sqlite" {
			// Handle chatwoot_import_database_connection_uri column for SQLite
			err = addColumnIfNotExistsSQLite(tx, "users", "chatwoot_import_database_connection_uri", "TEXT DEFAULT ''")
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 16 {
		if db.DriverName() == "sqlite" {
			// Handle chatwoot_import_database_ssl column for SQLite
			err = addColumnIfNotExistsSQLite(tx, "users", "chatwoot_import_database_ssl", "BOOLEAN DEFAULT 0")
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 17 {
		if db.DriverName() == "sqlite" {
			// Handle chatwoot_import_messages column for SQLite
			err = addColumnIfNotExistsSQLite(tx, "users", "chatwoot_import_messages", "BOOLEAN DEFAULT 0")
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 18 {
		if db.DriverName() == "sqlite" {
			// Handle push_name column for message_history table in SQLite
			err = addColumnIfNotExistsSQLite(tx, "message_history", "push_name", "TEXT")
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 19 {
		if db.DriverName() == "sqlite" {
			// SQLite doesn't support RENAME COLUMN directly in older versions
			// Check if push_name exists and sender_name doesn't, then rename
			var pushNameExists, senderNameExists int
			err = tx.Get(&pushNameExists, `
				SELECT COUNT(*) FROM pragma_table_info('message_history')
				WHERE name = 'push_name'`)
			if err == nil && pushNameExists > 0 {
				err = tx.Get(&senderNameExists, `
					SELECT COUNT(*) FROM pragma_table_info('message_history')
					WHERE name = 'sender_name'`)
				if err == nil && senderNameExists == 0 {
					// SQLite 3.25.0+ supports ALTER TABLE RENAME COLUMN
					// For older versions, we'd need to recreate the table, but let's try RENAME COLUMN first
					_, err = tx.Exec(`ALTER TABLE message_history RENAME COLUMN push_name TO sender_name`)
					if err != nil {
						// If RENAME COLUMN fails (old SQLite version), log warning but don't fail migration
						// The column will remain as push_name in old SQLite versions
						log.Warn().Err(err).Msg("SQLite version may not support RENAME COLUMN, column will remain as push_name")
						err = nil // Don't fail the migration
					}
				}
			}
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else {
		_, err = tx.Exec(migration.UpSQL)
	}

	if err != nil {
		return fmt.Errorf("failed to execute migration SQL: %w", err)
	}

	return tx.Commit()
}

func createMigrationsTable(db *sqlx.DB) error {
	var tableExists bool
	var err error

	switch db.DriverName() {
	case "postgres":
		// Check if table exists in current schema (respects search_path)
		err = db.Get(&tableExists, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.tables 
				WHERE table_schema = current_schema()
				AND table_name = 'migrations'
			)`)
	case "sqlite":
		err = db.Get(&tableExists, `
			SELECT EXISTS (
				SELECT 1 FROM sqlite_master 
				WHERE type='table' AND name='migrations'
			)`)
	default:
		return fmt.Errorf("unsupported database driver: %s", db.DriverName())
	}

	if err != nil {
		return fmt.Errorf("failed to check migrations table existence: %w", err)
	}

	if tableExists {
		return nil
	}

	// Create migrations table with database-specific SQL
	var createSQL string
	if db.DriverName() == "postgres" {
		createSQL = `
			CREATE TABLE migrations (
				id INTEGER PRIMARY KEY,
				name TEXT NOT NULL,
				applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
			)`
	} else {
		createSQL = `
			CREATE TABLE migrations (
				id INTEGER PRIMARY KEY,
				name TEXT NOT NULL,
				applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
			)`
	}

	_, err = db.Exec(createSQL)
	if err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	return nil
}

func getAppliedMigrations(db *sqlx.DB) (map[int]struct{}, error) {
	applied := make(map[int]struct{})
	var rows []struct {
		ID   int    `db:"id"`
		Name string `db:"name"`
	}

	err := db.Select(&rows, "SELECT id, name FROM migrations ORDER BY id ASC")
	if err != nil {
		return nil, fmt.Errorf("failed to query applied migrations: %w", err)
	}

	for _, row := range rows {
		applied[row.ID] = struct{}{}
	}

	return applied, nil
}

func applyMigration(db *sqlx.DB, migration Migration) error {
	tx, err := db.Beginx()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	if migration.ID == 1 {
		// Handle initial schema creation differently per database
		if db.DriverName() == "sqlite" {
			err = createTableIfNotExistsSQLite(tx, "users", `
                CREATE TABLE users (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    token TEXT NOT NULL,
                    webhook TEXT NOT NULL DEFAULT '',
                    jid TEXT NOT NULL DEFAULT '',
                    qrcode TEXT NOT NULL DEFAULT '',
                    connected INTEGER,
                    expiration INTEGER,
                    events TEXT NOT NULL DEFAULT '',
                    proxy_url TEXT DEFAULT ''
                )`)
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 2 {
		if db.DriverName() == "sqlite" {
			err = addColumnIfNotExistsSQLite(tx, "users", "proxy_url", "TEXT DEFAULT ''")
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 3 {
		if db.DriverName() == "sqlite" {
			err = migrateSQLiteIDToString(tx)
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 4 {
		if db.DriverName() == "sqlite" {
			// Handle S3 columns for SQLite
			err = addColumnIfNotExistsSQLite(tx, "users", "s3_enabled", "BOOLEAN DEFAULT 0")
			if err == nil {
				err = addColumnIfNotExistsSQLite(tx, "users", "s3_endpoint", "TEXT DEFAULT ''")
			}
			if err == nil {
				err = addColumnIfNotExistsSQLite(tx, "users", "s3_region", "TEXT DEFAULT ''")
			}
			if err == nil {
				err = addColumnIfNotExistsSQLite(tx, "users", "s3_bucket", "TEXT DEFAULT ''")
			}
			if err == nil {
				err = addColumnIfNotExistsSQLite(tx, "users", "s3_access_key", "TEXT DEFAULT ''")
			}
			if err == nil {
				err = addColumnIfNotExistsSQLite(tx, "users", "s3_secret_key", "TEXT DEFAULT ''")
			}
			if err == nil {
				err = addColumnIfNotExistsSQLite(tx, "users", "s3_path_style", "BOOLEAN DEFAULT 1")
			}
			if err == nil {
				err = addColumnIfNotExistsSQLite(tx, "users", "s3_public_url", "TEXT DEFAULT ''")
			}
			if err == nil {
				err = addColumnIfNotExistsSQLite(tx, "users", "media_delivery", "TEXT DEFAULT 'base64'")
			}
			if err == nil {
				err = addColumnIfNotExistsSQLite(tx, "users", "s3_retention_days", "INTEGER DEFAULT 30")
			}
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 5 {
		if db.DriverName() == "sqlite" {
			// Handle message_history table creation for SQLite
			err = createTableIfNotExistsSQLite(tx, "message_history", `
				CREATE TABLE message_history (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					user_id TEXT NOT NULL,
					chat_jid TEXT NOT NULL,
					sender_jid TEXT NOT NULL,
					message_id TEXT NOT NULL,
					timestamp DATETIME NOT NULL,
					message_type TEXT NOT NULL,
					text_content TEXT,
					media_link TEXT,
					UNIQUE(user_id, message_id)
				)`)
			if err == nil {
				// Create index for SQLite
				_, err = tx.Exec(`
					CREATE INDEX IF NOT EXISTS idx_message_history_user_chat_timestamp 
					ON message_history (user_id, chat_jid, timestamp DESC)`)
			}
			if err == nil {
				// Add history column to users table
				err = addColumnIfNotExistsSQLite(tx, "users", "history", "INTEGER DEFAULT 0")
			}
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 6 {
		if db.DriverName() == "sqlite" {
			// Add quoted_message_id column to message_history table for SQLite
			err = addColumnIfNotExistsSQLite(tx, "message_history", "quoted_message_id", "TEXT")
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 7 {
		if db.DriverName() == "sqlite" {
			// Add hmac_key column as BLOB for encrypted data in SQLite
			err = addColumnIfNotExistsSQLite(tx, "users", "hmac_key", "BLOB")
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 8 {
		if db.DriverName() == "sqlite" {
			// Add dataJson column to message_history table for SQLite
			err = addColumnIfNotExistsSQLite(tx, "message_history", "datajson", "TEXT")
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 9 {
		if db.DriverName() == "sqlite" {
			// Handle Chatwoot columns for SQLite
			err = addColumnIfNotExistsSQLite(tx, "users", "chatwoot_base_url", "TEXT DEFAULT ''")
			if err == nil {
				err = addColumnIfNotExistsSQLite(tx, "users", "chatwoot_account_id", "TEXT DEFAULT ''")
			}
			if err == nil {
				err = addColumnIfNotExistsSQLite(tx, "users", "chatwoot_api_token", "TEXT DEFAULT ''")
			}
			if err == nil {
				err = addColumnIfNotExistsSQLite(tx, "users", "chatwoot_inbox_name", "TEXT DEFAULT ''")
			}
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 10 {
		if db.DriverName() == "sqlite" {
			// Handle Chatwoot inbox_id column for SQLite
			err = addColumnIfNotExistsSQLite(tx, "users", "chatwoot_inbox_id", "TEXT DEFAULT ''")
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 11 {
		if db.DriverName() == "sqlite" {
			// Handle Chatwoot sign message columns for SQLite
			err = addColumnIfNotExistsSQLite(tx, "users", "chatwoot_sign_msg", "BOOLEAN DEFAULT 0")
			if err == nil {
				err = addColumnIfNotExistsSQLite(tx, "users", "chatwoot_sign_delimiter", "TEXT DEFAULT '\n'")
			}
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 12 {
		if db.DriverName() == "sqlite" {
			// Handle Chatwoot mark read column for SQLite
			err = addColumnIfNotExistsSQLite(tx, "users", "chatwoot_mark_read", "BOOLEAN DEFAULT 0")
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 13 {
		if db.DriverName() == "sqlite" {
			// Handle days_to_sync_history column for SQLite
			err = addColumnIfNotExistsSQLite(tx, "users", "days_to_sync_history", "INTEGER DEFAULT 0")
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 14 {
		if db.DriverName() == "sqlite" {
			// Handle ignore_groups column for SQLite
			err = addColumnIfNotExistsSQLite(tx, "users", "ignore_groups", "BOOLEAN DEFAULT 1")
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 15 {
		if db.DriverName() == "sqlite" {
			// Handle chatwoot_import_database_connection_uri column for SQLite
			err = addColumnIfNotExistsSQLite(tx, "users", "chatwoot_import_database_connection_uri", "TEXT DEFAULT ''")
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 16 {
		if db.DriverName() == "sqlite" {
			// Handle chatwoot_import_database_ssl column for SQLite
			err = addColumnIfNotExistsSQLite(tx, "users", "chatwoot_import_database_ssl", "BOOLEAN DEFAULT 0")
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 17 {
		if db.DriverName() == "sqlite" {
			// Handle chatwoot_import_messages column for SQLite
			err = addColumnIfNotExistsSQLite(tx, "users", "chatwoot_import_messages", "BOOLEAN DEFAULT 0")
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 18 {
		if db.DriverName() == "sqlite" {
			// Handle push_name column for message_history table in SQLite
			err = addColumnIfNotExistsSQLite(tx, "message_history", "push_name", "TEXT")
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else if migration.ID == 19 {
		if db.DriverName() == "sqlite" {
			// SQLite doesn't support RENAME COLUMN directly in older versions
			// Check if push_name exists and sender_name doesn't, then rename
			var pushNameExists, senderNameExists int
			err = tx.Get(&pushNameExists, `
				SELECT COUNT(*) FROM pragma_table_info('message_history')
				WHERE name = 'push_name'`)
			if err == nil && pushNameExists > 0 {
				err = tx.Get(&senderNameExists, `
					SELECT COUNT(*) FROM pragma_table_info('message_history')
					WHERE name = 'sender_name'`)
				if err == nil && senderNameExists == 0 {
					// SQLite 3.25.0+ supports ALTER TABLE RENAME COLUMN
					// For older versions, we'd need to recreate the table, but let's try RENAME COLUMN first
					_, err = tx.Exec(`ALTER TABLE message_history RENAME COLUMN push_name TO sender_name`)
					if err != nil {
						// If RENAME COLUMN fails (old SQLite version), log warning but don't fail migration
						// The column will remain as push_name in old SQLite versions
						log.Warn().Err(err).Msg("SQLite version may not support RENAME COLUMN, column will remain as push_name")
						err = nil // Don't fail the migration
					}
				}
			}
		} else {
			_, err = tx.Exec(migration.UpSQL)
		}
	} else {
		_, err = tx.Exec(migration.UpSQL)
	}

	if err != nil {
		return fmt.Errorf("failed to execute migration SQL: %w", err)
	}

	// Record the migration
	if _, err = tx.Exec(`
        INSERT INTO migrations (id, name) 
        VALUES ($1, $2)`, migration.ID, migration.Name); err != nil {
		return fmt.Errorf("failed to record migration: %w", err)
	}

	return tx.Commit()
}

func createTableIfNotExistsSQLite(tx *sqlx.Tx, tableName, createSQL string) error {
	var exists int
	err := tx.Get(&exists, `
        SELECT COUNT(*) FROM sqlite_master
        WHERE type='table' AND name=?`, tableName)
	if err != nil {
		return err
	}

	if exists == 0 {
		_, err = tx.Exec(createSQL)
		return err
	}
	return nil
}
func sqliteChangeIDType(tx *sqlx.Tx) error {
	// SQLite requires a more complex approach:
	// 1. Create new table with string ID
	// 2. Copy data with new UUIDs
	// 3. Drop old table
	// 4. Rename new table

	// Step 1: Get the current schema
	var tableInfo string
	err := tx.Get(&tableInfo, `
        SELECT sql FROM sqlite_master
        WHERE type='table' AND name='users'`)
	if err != nil {
		return fmt.Errorf("failed to get table info: %w", err)
	}

	// Step 2: Create new table with string ID
	newTableSQL := strings.Replace(tableInfo,
		"CREATE TABLE users (",
		"CREATE TABLE users_new (id TEXT PRIMARY KEY, ", 1)
	newTableSQL = strings.Replace(newTableSQL,
		"id INTEGER PRIMARY KEY AUTOINCREMENT,", "", 1)

	if _, err = tx.Exec(newTableSQL); err != nil {
		return fmt.Errorf("failed to create new table: %w", err)
	}

	// Step 3: Copy data with new UUIDs
	columns, err := getTableColumns(tx, "users")
	if err != nil {
		return fmt.Errorf("failed to get table columns: %w", err)
	}

	// Remove 'id' from columns list
	var filteredColumns []string
	for _, col := range columns {
		if col != "id" {
			filteredColumns = append(filteredColumns, col)
		}
	}

	columnList := strings.Join(filteredColumns, ", ")
	if _, err = tx.Exec(fmt.Sprintf(`
        INSERT INTO users_new (id, %s)
        SELECT gen_random_uuid(), %s FROM users`,
		columnList, columnList)); err != nil {
		return fmt.Errorf("failed to copy data: %w", err)
	}

	// Step 4: Drop old table
	if _, err = tx.Exec("DROP TABLE users"); err != nil {
		return fmt.Errorf("failed to drop old table: %w", err)
	}

	// Step 5: Rename new table
	if _, err = tx.Exec("ALTER TABLE users_new RENAME TO users"); err != nil {
		return fmt.Errorf("failed to rename table: %w", err)
	}

	return nil
}

func getTableColumns(tx *sqlx.Tx, tableName string) ([]string, error) {
	var columns []string
	rows, err := tx.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
	if err != nil {
		return nil, fmt.Errorf("failed to get table info: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, typ string
		var notnull int
		var dfltValue interface{}
		var pk int

		if err := rows.Scan(&cid, &name, &typ, &notnull, &dfltValue, &pk); err != nil {
			return nil, fmt.Errorf("failed to scan column info: %w", err)
		}
		columns = append(columns, name)
	}

	return columns, nil
}

func migrateSQLiteIDToString(tx *sqlx.Tx) error {
	// 1. Check if we need to do the migration
	var currentType string
	err := tx.QueryRow(`
        SELECT type FROM pragma_table_info('users')
        WHERE name = 'id'`).Scan(&currentType)
	if err != nil {
		return fmt.Errorf("failed to check column type: %w", err)
	}

	if currentType != "INTEGER" {
		// No migration needed
		return nil
	}

	// 2. Create new table with string ID
	_, err = tx.Exec(`
        CREATE TABLE users_new (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            token TEXT NOT NULL,
            webhook TEXT NOT NULL DEFAULT '',
            jid TEXT NOT NULL DEFAULT '',
            qrcode TEXT NOT NULL DEFAULT '',
            connected INTEGER,
            expiration INTEGER,
            events TEXT NOT NULL DEFAULT '',
            proxy_url TEXT DEFAULT ''
        )`)
	if err != nil {
		return fmt.Errorf("failed to create new table: %w", err)
	}

	// 3. Copy data with new UUIDs
	_, err = tx.Exec(`
        INSERT INTO users_new
        SELECT
            hex(randomblob(16)),
            name, token, webhook, jid, qrcode,
            connected, expiration, events, proxy_url 
        FROM users`)
	if err != nil {
		return fmt.Errorf("failed to copy data: %w", err)
	}

	// 4. Drop old table
	_, err = tx.Exec(`DROP TABLE users`)
	if err != nil {
		return fmt.Errorf("failed to drop old table: %w", err)
	}

	// 5. Rename new table
	_, err = tx.Exec(`ALTER TABLE users_new RENAME TO users`)
	if err != nil {
		return fmt.Errorf("failed to rename table: %w", err)
	}

	return nil
}

func addColumnIfNotExistsSQLite(tx *sqlx.Tx, tableName, columnName, columnDef string) error {
	var exists int
	err := tx.Get(&exists, `
        SELECT COUNT(*) FROM pragma_table_info(?)
        WHERE name = ?`, tableName, columnName)
	if err != nil {
		return fmt.Errorf("failed to check column existence: %w", err)
	}

	if exists == 0 {
		_, err = tx.Exec(fmt.Sprintf(
			"ALTER TABLE %s ADD COLUMN %s %s",
			tableName, columnName, columnDef))
		if err != nil {
			return fmt.Errorf("failed to add column: %w", err)
		}
	}
	return nil
}

const addHmacKeySQL = `
-- PostgreSQL version - Add encrypted HMAC key column
DO $$
BEGIN
    -- Add hmac_key column as BYTEA for encrypted data
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 'hmac_key') THEN
        ALTER TABLE users ADD COLUMN hmac_key BYTEA;
    END IF;
END $$;

-- SQLite version (handled in code)
`

const addChatwootSupportSQL = `
-- PostgreSQL version - Add Chatwoot configuration columns
DO $$
BEGIN
    -- Add Chatwoot configuration columns if they don't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 'chatwoot_base_url') THEN
        ALTER TABLE users ADD COLUMN chatwoot_base_url TEXT DEFAULT '';
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 'chatwoot_account_id') THEN
        ALTER TABLE users ADD COLUMN chatwoot_account_id TEXT DEFAULT '';
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 'chatwoot_api_token') THEN
        ALTER TABLE users ADD COLUMN chatwoot_api_token TEXT DEFAULT '';
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 'chatwoot_inbox_name') THEN
        ALTER TABLE users ADD COLUMN chatwoot_inbox_name TEXT DEFAULT '';
    END IF;
END $$;

-- SQLite version (handled in code)
`

const addChatwootInboxIDSQL = `
-- PostgreSQL version - Add Chatwoot inbox_id column
DO $$
BEGIN
    -- Add Chatwoot inbox_id column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 'chatwoot_inbox_id') THEN
        ALTER TABLE users ADD COLUMN chatwoot_inbox_id TEXT DEFAULT '';
    END IF;
END $$;

-- SQLite version (handled in code)
`

const addChatwootSignMessageSQL = `
-- PostgreSQL version - Add Chatwoot sign message columns
DO $$
BEGIN
    -- Add chatwoot_sign_msg column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 'chatwoot_sign_msg') THEN
        ALTER TABLE users ADD COLUMN chatwoot_sign_msg BOOLEAN DEFAULT false;
    END IF;
    
    -- Add chatwoot_sign_delimiter column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 'chatwoot_sign_delimiter') THEN
        ALTER TABLE users ADD COLUMN chatwoot_sign_delimiter TEXT DEFAULT '\n';
    END IF;
END $$;

-- SQLite version (handled in code)
`

const addChatwootMarkReadSQL = `
-- PostgreSQL version - Add Chatwoot mark read column
DO $$
BEGIN
    -- Add chatwoot_mark_read column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 'chatwoot_mark_read') THEN
        ALTER TABLE users ADD COLUMN chatwoot_mark_read BOOLEAN DEFAULT false;
    END IF;
END $$;

-- SQLite version (handled in code)
`

const addDaysToSyncHistorySQL = `
-- PostgreSQL version - Add days_to_sync_history column
DO $$
BEGIN
    -- Add days_to_sync_history column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 'days_to_sync_history') THEN
        ALTER TABLE users ADD COLUMN days_to_sync_history INTEGER DEFAULT 0;
    END IF;
END $$;

-- SQLite version (handled in code)
`

const addIgnoreGroupsSQL = `
-- PostgreSQL version - Add ignore_groups column
DO $$
BEGIN
    -- Add ignore_groups column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 'ignore_groups') THEN
        ALTER TABLE users ADD COLUMN ignore_groups BOOLEAN DEFAULT true;
    END IF;
END $$;

-- SQLite version (handled in code)
`

const addChatwootImportDatabaseURISQL = `
-- PostgreSQL version - Add Chatwoot import database URI column
DO $$
BEGIN
    -- Add chatwoot_import_database_connection_uri column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 'chatwoot_import_database_connection_uri') THEN
        ALTER TABLE users ADD COLUMN chatwoot_import_database_connection_uri TEXT DEFAULT '';
    END IF;
END $$;

-- SQLite version (handled in code)
`

const addChatwootImportDatabaseSSLSQL = `
-- PostgreSQL version - Add Chatwoot import database SSL column
DO $$
BEGIN
    -- Add chatwoot_import_database_ssl column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 'chatwoot_import_database_ssl') THEN
        ALTER TABLE users ADD COLUMN chatwoot_import_database_ssl BOOLEAN DEFAULT false;
    END IF;
END $$;

-- SQLite version (handled in code)
`

const addChatwootImportMessagesSQL = `
-- PostgreSQL version - Add Chatwoot import messages column
DO $$
BEGIN
    -- Add chatwoot_import_messages column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 'chatwoot_import_messages') THEN
        ALTER TABLE users ADD COLUMN chatwoot_import_messages BOOLEAN DEFAULT false;
    END IF;
END $$;

-- SQLite version (handled in code)
`

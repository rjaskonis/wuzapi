package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
)

type DatabaseConfig struct {
	Type     string
	Host     string
	Port     string
	User     string
	Password string
	Name     string
	Path     string
	SSLMode  string
	Schema   string
}

func InitializeDatabase(exPath string) (*sqlx.DB, error) {
	config := getDatabaseConfig(exPath)

	if config.Type == "postgres" {
		return initializePostgres(config)
	}
	return initializeSQLite(config)
}

func getDatabaseConfig(exPath string) DatabaseConfig {
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbSSL := os.Getenv("DB_SSLMODE")
	dbSchema := os.Getenv("DB_SCHEMA")

	sslMode := dbSSL
	if dbSSL == "true" {
		sslMode = "require"
	} else if dbSSL == "false" || dbSSL == "" {
		sslMode = "disable"
	}

	if dbUser != "" && dbPassword != "" && dbName != "" && dbHost != "" && dbPort != "" {
		return DatabaseConfig{
			Type:     "postgres",
			Host:     dbHost,
			Port:     dbPort,
			User:     dbUser,
			Password: dbPassword,
			Name:     dbName,
			SSLMode:  sslMode,
			Schema:   dbSchema,
		}
	}

	return DatabaseConfig{
		Type: "sqlite",
		Path: filepath.Join(exPath, "dbdata"),
	}
}

func initializePostgres(config DatabaseConfig) (*sqlx.DB, error) {
	// First, open a temporary connection without search_path to create schema if needed
	tempDSN := fmt.Sprintf(
		"user=%s password=%s dbname=%s host=%s port=%s sslmode=%s",
		config.User, config.Password, config.Name, config.Host, config.Port, config.SSLMode,
	)

	tempDB, err := sqlx.Open("postgres", tempDSN)
	if err != nil {
		return nil, fmt.Errorf("failed to open temporary postgres connection: %w", err)
	}
	defer tempDB.Close()

	if err := tempDB.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping postgres database: %w", err)
	}

	// Create schema if specified and doesn't exist
	var quotedSchema string
	if config.Schema != "" {
		// Use PostgreSQL's quote_ident function to safely quote the schema identifier
		err = tempDB.Get(&quotedSchema, `SELECT quote_ident($1::text)`, config.Schema)
		if err != nil {
			return nil, fmt.Errorf("failed to quote schema name: %w", err)
		}
		_, err = tempDB.Exec(`CREATE SCHEMA IF NOT EXISTS ` + quotedSchema)
		if err != nil {
			return nil, fmt.Errorf("failed to create schema %s: %w", config.Schema, err)
		}
	}

	// Now build the final DSN with search_path in connection string
	// This ensures all connections from the pool use the correct schema
	dsn := fmt.Sprintf(
		"user=%s password=%s dbname=%s host=%s port=%s sslmode=%s",
		config.User, config.Password, config.Name, config.Host, config.Port, config.SSLMode,
	)
	if config.Schema != "" {
		// Add search_path via options parameter so all pooled connections use it
		// lib/pq supports setting runtime parameters via options=-cparam=value
		// We need to properly escape the schema name if it contains special characters
		// Since quotedSchema is already properly quoted by quote_ident, we can use it directly
		// But we need to remove the quotes for the options parameter
		schemaForOptions := strings.Trim(quotedSchema, `"`)
		dsn += fmt.Sprintf(" options=-csearch_path=%s", schemaForOptions)
	}

	// Open the actual database connection with search_path in connection string
	db, err := sqlx.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open postgres connection: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping postgres database: %w", err)
	}

	// Configure connection pool to prevent stale connections
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(2 * time.Minute)

	return db, nil
}

func initializeSQLite(config DatabaseConfig) (*sqlx.DB, error) {
	if err := os.MkdirAll(config.Path, 0751); err != nil {
		return nil, fmt.Errorf("could not create dbdata directory: %w", err)
	}

	dbPath := filepath.Join(config.Path, "users.db")
	db, err := sqlx.Open("sqlite", dbPath+"?_pragma=foreign_keys(1)&_busy_timeout=3000")
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping sqlite database: %w", err)
	}

	// Configure connection pool to prevent stale connections
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(2 * time.Minute)

	return db, nil
}

type HistoryMessage struct {
	ID              int       `json:"id" db:"id"`
	UserID          string    `json:"user_id" db:"user_id"`
	ChatJID         string    `json:"chat_jid" db:"chat_jid"`
	SenderJID       string    `json:"sender_jid" db:"sender_jid"`
	MessageID       string    `json:"message_id" db:"message_id"`
	Timestamp       time.Time `json:"timestamp" db:"timestamp"`
	MessageType     string    `json:"message_type" db:"message_type"`
	TextContent     string    `json:"text_content" db:"text_content"`
	MediaLink       string    `json:"media_link" db:"media_link"`
	QuotedMessageID string    `json:"quoted_message_id,omitempty" db:"quoted_message_id"`
	DataJson        string    `json:"data_json" db:"datajson"`
}

func (s *server) saveMessageToHistory(userID, chatJID, senderJID, messageID, messageType, textContent, mediaLink, quotedMessageID, dataJson string) error {
	return s.saveMessageToHistoryWithTimestamp(userID, chatJID, senderJID, messageID, messageType, textContent, mediaLink, quotedMessageID, dataJson, time.Now())
}

func (s *server) saveMessageToHistoryWithTimestamp(userID, chatJID, senderJID, messageID, messageType, textContent, mediaLink, quotedMessageID, dataJson string, msgTimestamp time.Time) error {
	query := `INSERT INTO message_history (user_id, chat_jid, sender_jid, message_id, timestamp, message_type, text_content, media_link, quoted_message_id, datajson)
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
              ON CONFLICT (user_id, message_id) DO NOTHING`
	if s.db.DriverName() == "sqlite" {
		query = `INSERT OR IGNORE INTO message_history (user_id, chat_jid, sender_jid, message_id, timestamp, message_type, text_content, media_link, quoted_message_id, datajson)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	}
	_, err := s.db.Exec(query, userID, chatJID, senderJID, messageID, msgTimestamp, messageType, textContent, mediaLink, quotedMessageID, dataJson)
	if err != nil {
		return fmt.Errorf("failed to save message to history: %w", err)
	}
	return nil
}

func (s *server) trimMessageHistory(userID, chatJID string, limit int) error {
	var queryHistory, querySecrets string

	if s.db.DriverName() == "postgres" {
		queryHistory = `
            DELETE FROM message_history
            WHERE id IN (
                SELECT id FROM message_history
                WHERE user_id = $1 AND chat_jid = $2
                ORDER BY timestamp DESC
                OFFSET $3
            )`

		querySecrets = `
            DELETE FROM whatsmeow_message_secrets
            WHERE message_id IN (
                SELECT id FROM message_history
                WHERE user_id = $1 AND chat_jid = $2
                ORDER BY timestamp DESC
                OFFSET $3
            )`
	} else { // sqlite
		queryHistory = `
            DELETE FROM message_history
            WHERE id IN (
                SELECT id FROM message_history
                WHERE user_id = ? AND chat_jid = ?
                ORDER BY timestamp DESC
                LIMIT -1 OFFSET ?
            )`

		querySecrets = `
            DELETE FROM whatsmeow_message_secrets
            WHERE message_id IN (
                SELECT id FROM message_history
                WHERE user_id = ? AND chat_jid = ?
                ORDER BY timestamp DESC
                LIMIT -1 OFFSET ?
            )`
	}

	if _, err := s.db.Exec(querySecrets, userID, chatJID, limit); err != nil {
		return fmt.Errorf("failed to trim message secrets: %w", err)
	}

	if _, err := s.db.Exec(queryHistory, userID, chatJID, limit); err != nil {
		return fmt.Errorf("failed to trim message history: %w", err)
	}

	return nil
}

// ensureDBConnection checks if the database connection is healthy and attempts to reconnect if needed
func (s *server) ensureDBConnection() error {
	if err := s.db.Ping(); err != nil {
		// Connection is stale, try to reconnect
		// For sqlx.DB, Ping() will automatically try to get a new connection from the pool
		// If that fails, we need to check if it's a temporary issue
		if strings.Contains(err.Error(), "connection") || strings.Contains(err.Error(), "closed") {
			// Try pinging again after a short delay
			time.Sleep(100 * time.Millisecond)
			if err := s.db.Ping(); err != nil {
				return fmt.Errorf("database connection is unhealthy: %w", err)
			}
		} else {
			return fmt.Errorf("database ping failed: %w", err)
		}
	}
	return nil
}

// checkColumnExists checks if a column exists in a table
func (s *server) checkColumnExists(tableName, columnName string) (bool, error) {
	var exists bool
	var err error

	switch s.db.DriverName() {
	case "postgres":
		err = s.db.Get(&exists, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.columns 
				WHERE table_schema = current_schema()
				AND table_name = $1 AND column_name = $2
			)`, tableName, columnName)
	case "sqlite":
		var count int
		err = s.db.Get(&count, `
			SELECT COUNT(*) FROM pragma_table_info(?)
			WHERE name = ?`, tableName, columnName)
		if err == nil {
			exists = count > 0
		}
	default:
		return false, fmt.Errorf("unsupported database driver: %s", s.db.DriverName())
	}

	if err != nil {
		return false, fmt.Errorf("failed to check column existence: %w", err)
	}

	return exists, nil
}

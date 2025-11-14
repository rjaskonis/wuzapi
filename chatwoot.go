package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
	_ "github.com/lib/pq"
)

// normalizeToE164 normalizes a phone number to E164 format
// E164 format: +[country code][number] (e.g., +5511999999999)
func normalizeToE164(phone string, defaultCountry string) string {
	if phone == "" {
		return ""
	}
	
	// Remove all non-digit characters except +
	re := regexp.MustCompile(`[^\d+]`)
	cleaned := re.ReplaceAllString(phone, "")
	
	// If it already starts with +, return as is (assuming it's already in E164)
	if strings.HasPrefix(cleaned, "+") {
		return cleaned
	}
	
	// Remove leading zeros
	cleaned = strings.TrimLeft(cleaned, "0")
	
	// If empty after cleaning, return empty
	if cleaned == "" {
		return ""
	}
	
	// Default country codes (common ones)
	countryCodes := map[string]string{
		"BR": "55",
		"US": "1",
		"GB": "44",
		"DE": "49",
		"FR": "33",
		"IT": "39",
		"ES": "34",
		"PT": "351",
		"MX": "52",
		"AR": "54",
		"CL": "56",
		"CO": "57",
		"PE": "51",
	}
	
	// Get country code
	countryCode := countryCodes[strings.ToUpper(defaultCountry)]
	if countryCode == "" {
		countryCode = "55" // Default to Brazil if country not found
	}
	
	// Check if the number already starts with the country code
	// But make sure it's not just a partial match (e.g., "5" matching "55")
	if strings.HasPrefix(cleaned, countryCode) && len(cleaned) > len(countryCode) {
		return "+" + cleaned
	}
	
	// Check if it starts with other common country codes (to avoid double-prefixing)
	// Only check codes that are different from the default country code
	for code, _ := range countryCodes {
		if code != strings.ToUpper(defaultCountry) && strings.HasPrefix(cleaned, countryCodes[code]) && len(cleaned) > len(countryCodes[code]) {
			return "+" + cleaned
		}
	}
	
	// Add country code and + prefix
	return "+" + countryCode + cleaned
}

// ChatwootConfig represents the Chatwoot configuration for a user
type ChatwootConfig struct {
	BaseURL                     string `db:"chatwoot_base_url"`
	AccountID                   string `db:"chatwoot_account_id"`
	APIToken                    string `db:"chatwoot_api_token"`
	InboxName                   string `db:"chatwoot_inbox_name"`
	InboxID                     string `db:"chatwoot_inbox_id"`
	SignMsg                     bool   `db:"chatwoot_sign_msg"`
	SignDelimiter               string `db:"chatwoot_sign_delimiter"`
	MarkRead                    bool   `db:"chatwoot_mark_read"`
	ImportMessages              bool   `db:"chatwoot_import_messages"`
	ImportDatabaseConnectionURI  string `db:"chatwoot_import_database_connection_uri"`
	ImportDatabaseSSL           bool   `db:"chatwoot_import_database_ssl"`
}

// getChatwootConfig retrieves Chatwoot configuration from database
func (s *server) getChatwootConfig(userID string) (*ChatwootConfig, error) {
	var config ChatwootConfig
	
	// Try to get config with all fields first (including mark_read and sign_msg)
	query := `
		SELECT 
			chatwoot_base_url,
			chatwoot_account_id,
			chatwoot_api_token,
			chatwoot_inbox_name,
			chatwoot_inbox_id,
			COALESCE(chatwoot_sign_msg, false) as chatwoot_sign_msg,
			COALESCE(chatwoot_sign_delimiter, '\n') as chatwoot_sign_delimiter,
			COALESCE(chatwoot_mark_read, false) as chatwoot_mark_read,
			COALESCE(chatwoot_import_messages, true) as chatwoot_import_messages,
			COALESCE(chatwoot_import_database_connection_uri, '') as chatwoot_import_database_connection_uri,
			COALESCE(chatwoot_import_database_ssl, false) as chatwoot_import_database_ssl
		FROM users WHERE id = $1`
	
	if s.db.DriverName() == "sqlite" {
		query = strings.ReplaceAll(query, "$1", "?")
	}
	
	err := s.db.Get(&config, query, userID)
	if err != nil {
		// If query fails, try without mark_read column (for databases before migration 12)
		fallbackQuery1 := `
			SELECT 
				chatwoot_base_url,
				chatwoot_account_id,
				chatwoot_api_token,
				chatwoot_inbox_name,
				chatwoot_inbox_id,
				COALESCE(chatwoot_sign_msg, false) as chatwoot_sign_msg,
				COALESCE(chatwoot_sign_delimiter, '\n') as chatwoot_sign_delimiter,
				COALESCE(chatwoot_import_database_connection_uri, '') as chatwoot_import_database_connection_uri,
				COALESCE(chatwoot_import_database_ssl, false) as chatwoot_import_database_ssl
			FROM users WHERE id = $1`
		
		if s.db.DriverName() == "sqlite" {
			fallbackQuery1 = strings.ReplaceAll(fallbackQuery1, "$1", "?")
		}
		
		err2 := s.db.Get(&config, fallbackQuery1, userID)
		if err2 != nil {
			// If that also fails, try with just basic Chatwoot fields (for databases before migration 11)
			fallbackQuery2 := `
				SELECT 
					chatwoot_base_url,
					chatwoot_account_id,
					chatwoot_api_token,
					chatwoot_inbox_name,
					chatwoot_inbox_id,
					COALESCE(chatwoot_import_database_connection_uri, '') as chatwoot_import_database_connection_uri,
					COALESCE(chatwoot_import_database_ssl, false) as chatwoot_import_database_ssl
				FROM users WHERE id = $1`
			
			if s.db.DriverName() == "sqlite" {
				fallbackQuery2 = strings.ReplaceAll(fallbackQuery2, "$1", "?")
			}
			
			err3 := s.db.Get(&config, fallbackQuery2, userID)
			if err3 != nil {
				return nil, fmt.Errorf("failed to get Chatwoot configuration: %w", err)
			}
			// Set defaults for optional fields if columns don't exist
			config.SignMsg = false
			config.SignDelimiter = "\n"
			config.MarkRead = false
			config.ImportMessages = true // Default to enabled for backward compatibility
			config.ImportDatabaseConnectionURI = ""
			config.ImportDatabaseSSL = false
		} else {
			// Set default for mark_read if column doesn't exist
			config.MarkRead = false
			config.ImportMessages = true // Default to enabled for backward compatibility
			config.ImportDatabaseConnectionURI = ""
			config.ImportDatabaseSSL = false
		}
	}
	
	return &config, nil
}

// buildDatabaseConnectionURI builds a PostgreSQL connection URI with SSL mode
func buildDatabaseConnectionURI(baseURI string, useSSL bool) string {
	if baseURI == "" {
		return ""
	}
	
	// Parse the URI to add/modify sslmode parameter
	parsedURI, err := url.Parse(baseURI)
	if err != nil {
		// If parsing fails, just append sslmode to the end
		if useSSL {
			return baseURI
		}
		if strings.Contains(baseURI, "?") {
			return baseURI + "&sslmode=disable"
		}
		return baseURI + "?sslmode=disable"
	}
	
	// Get existing query parameters
	query := parsedURI.Query()
	
	// Set sslmode based on useSSL flag
	if useSSL {
		query.Set("sslmode", "require")
	} else {
		query.Set("sslmode", "disable")
	}
	
	// Rebuild the URI
	parsedURI.RawQuery = query.Encode()
	return parsedURI.String()
}

// updateChatwootInboxID updates the inbox ID in the database
func (s *server) updateChatwootInboxID(userID, inboxID string) error {
	query := `UPDATE users SET chatwoot_inbox_id = $1 WHERE id = $2`
	if s.db.DriverName() == "sqlite" {
		query = strings.ReplaceAll(query, "$1", "?")
		query = strings.ReplaceAll(query, "$2", "?")
	}
	
	_, err := s.db.Exec(query, inboxID, userID)
	return err
}

// getChatwootClient creates a REST client for Chatwoot API
func getChatwootClient(baseURL, apiToken string) *resty.Client {
	baseURL = strings.TrimSuffix(baseURL, "/")
	client := resty.New()
	client.SetBaseURL(baseURL)
	client.SetHeader("api_access_token", apiToken)
	client.SetTimeout(15 * time.Second)
	return client
}

// ChatwootInbox represents a Chatwoot inbox
type ChatwootInbox struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// ChatwootInboxResponse represents the response from Chatwoot inbox API
type ChatwootInboxResponse struct {
	Payload ChatwootInbox `json:"payload"`
	ID      int           `json:"id"`
}

// findInboxByName searches for an inbox by name
func findInboxByName(client *resty.Client, accountID, name string) (*ChatwootInbox, error) {
	var response struct {
		Payload []ChatwootInbox `json:"payload"`
		Data    []ChatwootInbox `json:"data"`
	}
	
	resp, err := client.R().
		SetResult(&response).
		Get(fmt.Sprintf("/api/v1/accounts/%s/inboxes", accountID))
	
	if err != nil {
		return nil, fmt.Errorf("failed to fetch inboxes: %w", err)
	}
	
	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch inboxes: status %d", resp.StatusCode())
	}
	
	inboxes := response.Payload
	if len(inboxes) == 0 {
		inboxes = response.Data
	}
	
	nameLower := strings.ToLower(name)
	for _, inbox := range inboxes {
		if strings.ToLower(inbox.Name) == nameLower {
			return &inbox, nil
		}
	}
	
	return nil, nil
}

// getInboxByID retrieves an inbox by ID
func getInboxByID(client *resty.Client, accountID string, inboxID string) (*ChatwootInbox, error) {
	var response ChatwootInboxResponse
	
	resp, err := client.R().
		SetResult(&response).
		Get(fmt.Sprintf("/api/v1/accounts/%s/inboxes/%s", accountID, inboxID))
	
	if err != nil {
		return nil, fmt.Errorf("failed to fetch inbox: %w", err)
	}
	
	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch inbox: status %d", resp.StatusCode())
	}
	
	if response.ID != 0 {
		return &ChatwootInbox{ID: response.ID, Name: response.Payload.Name}, nil
	}
	
	return &response.Payload, nil
}

// createAPIInbox creates a new API inbox in Chatwoot
func createAPIInbox(client *resty.Client, accountID, name, webhookURL string, allowMessagesAfterResolved bool) (*ChatwootInbox, error) {
	type Channel struct {
		Type       string `json:"type"`
		WebhookURL string `json:"webhook_url"`
	}
	
	type InboxRequest struct {
		Name                        string  `json:"name"`
		Channel                     Channel `json:"channel"`
		AllowMessagesAfterResolved  bool    `json:"allow_messages_after_resolved"`
	}
	
	request := InboxRequest{
		Name: name,
		Channel: Channel{
			Type:       "api",
			WebhookURL: webhookURL,
		},
		AllowMessagesAfterResolved: allowMessagesAfterResolved,
	}
	
	var response ChatwootInboxResponse
	
	resp, err := client.R().
		SetBody(request).
		SetResult(&response).
		Post(fmt.Sprintf("/api/v1/accounts/%s/inboxes", accountID))
	
	if err != nil {
		return nil, fmt.Errorf("failed to create inbox: %w", err)
	}
	
	if resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusCreated {
		return nil, fmt.Errorf("failed to create inbox: status %d, body: %s", resp.StatusCode(), string(resp.Body()))
	}
	
	if response.ID != 0 {
		return &ChatwootInbox{ID: response.ID, Name: response.Payload.Name}, nil
	}
	
	return &response.Payload, nil
}

// ChatwootContact represents a Chatwoot contact
type ChatwootContact struct {
	ID          int    `json:"id"`
	Identifier  string `json:"identifier"`
	PhoneNumber string `json:"phone_number"`
	Name        string `json:"name"`
	AvatarURL   string `json:"avatar_url"`
}

// ChatwootContactResponse represents the response from Chatwoot contact API
type ChatwootContactResponse struct {
	Payload struct {
		Contact ChatwootContact `json:"contact"`
	} `json:"payload"`
	ID int `json:"id"`
}

// findContactByIdentifier searches for a contact by identifier (phone, LID, or JID)
func findContactByIdentifier(client *resty.Client, accountID, identifier string) (*ChatwootContact, error) {
	var response struct {
		Payload []ChatwootContact `json:"payload"`
		Data    []ChatwootContact `json:"data"`
	}
	
	resp, err := client.R().
		SetQueryParam("q", identifier).
		SetResult(&response).
		Get(fmt.Sprintf("/api/v1/accounts/%s/contacts/search", accountID))
	
	if err != nil {
		return nil, fmt.Errorf("failed to search contact: %w", err)
	}
	
	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("failed to search contact: status %d", resp.StatusCode())
	}
	
	contacts := response.Payload
	if len(contacts) == 0 {
		contacts = response.Data
	}
	
	for _, contact := range contacts {
		if contact.Identifier == identifier || contact.PhoneNumber == identifier {
			return &contact, nil
		}
	}
	
	return nil, nil
}

// createContact creates a new contact in Chatwoot
func createContact(client *resty.Client, accountID string, name, identifier, phoneNumber, avatarURL string) (*ChatwootContact, error) {
	type ContactRequest struct {
		Name        string `json:"name"`
		Identifier  string `json:"identifier"`
		PhoneNumber string `json:"phone_number,omitempty"`
		AvatarURL   string `json:"avatar_url,omitempty"`
	}
	
	request := ContactRequest{
		Name:       name,
		Identifier: identifier,
		AvatarURL:  avatarURL,
	}
	
	if phoneNumber != "" {
		request.PhoneNumber = phoneNumber
	}
	
	var response ChatwootContactResponse
	
	resp, err := client.R().
		SetBody(request).
		SetResult(&response).
		Post(fmt.Sprintf("/api/v1/accounts/%s/contacts", accountID))
	
	if err != nil {
		return nil, fmt.Errorf("failed to create contact: %w", err)
	}
	
	if resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusCreated {
		return nil, fmt.Errorf("failed to create contact: status %d, body: %s", resp.StatusCode(), string(resp.Body()))
	}
	
	if response.Payload.Contact.ID != 0 {
		return &response.Payload.Contact, nil
	}
	
	return nil, fmt.Errorf("contact creation response missing contact data")
}

// findOrCreateContact finds an existing contact or creates a new one
func findOrCreateContact(client *resty.Client, accountID string, name, identifier, phoneNumber, avatarURL string) (*ChatwootContact, error) {
	// Normalize phone number to E164 format if provided
	// Skip normalization if already in E164 format (starts with +)
	normalizedPhone := phoneNumber
	if phoneNumber != "" && !strings.HasPrefix(phoneNumber, "+") {
		// Get default country from environment or use BR as default
		defaultCountry := os.Getenv("DEFAULT_COUNTRY")
		if defaultCountry == "" {
			defaultCountry = "BR"
		}
		normalizedPhone = normalizeToE164(phoneNumber, defaultCountry)
	}
	
	// Try to find by identifier first
	contact, err := findContactByIdentifier(client, accountID, identifier)
	if err != nil {
		log.Warn().Err(err).Str("identifier", identifier).Msg("Error searching for contact, will create new")
	}
	
	if contact != nil {
		log.Info().Int("contact_id", contact.ID).Str("identifier", identifier).Msg("Contact found")
		return contact, nil
	}
	
	// If not found and we have phone number, try searching by normalized phone
	if normalizedPhone != "" && normalizedPhone != identifier {
		contact, err = findContactByIdentifier(client, accountID, normalizedPhone)
		if err != nil {
			log.Warn().Err(err).Str("phone", normalizedPhone).Msg("Error searching for contact by phone")
		}
		if contact != nil {
			log.Info().Int("contact_id", contact.ID).Str("phone", normalizedPhone).Msg("Contact found by phone")
			return contact, nil
		}
	}
	
	// Create new contact with normalized phone number
	log.Info().Str("identifier", identifier).Str("name", name).Str("phone", normalizedPhone).Msg("Creating new contact")
	contact, err = createContact(client, accountID, name, identifier, normalizedPhone, avatarURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create contact: %w", err)
	}
	
	return contact, nil
}

// ChatwootConversation represents a Chatwoot conversation
type ChatwootConversation struct {
	ID     int `json:"id"`
	Status string `json:"status"`
	Meta   struct {
		Sender struct {
			ID int `json:"id"`
		} `json:"sender"`
	} `json:"meta"`
}

// ChatwootConversationResponse represents the response from Chatwoot conversation API
type ChatwootConversationResponse struct {
	Payload []ChatwootConversation `json:"payload"`
	Data    struct {
		Payload []ChatwootConversation `json:"payload"`
		Data    []ChatwootConversation `json:"data"`
	} `json:"data"`
	ID int `json:"id"`
}

// findConversationByContact searches for an open conversation with a contact
func findConversationByContact(client *resty.Client, accountID, inboxID string, contactID int) (*ChatwootConversation, error) {
	page := 1
	maxPages := 50
	
	for page <= maxPages {
		var response ChatwootConversationResponse
		
		resp, err := client.R().
			SetQueryParams(map[string]string{
				"status":    "open",
				"inbox_id":  inboxID,
				"page":      fmt.Sprintf("%d", page),
				"sort_order": "latest_first",
			}).
			SetResult(&response).
			Get(fmt.Sprintf("/api/v1/accounts/%s/conversations", accountID))
		
		if err != nil {
			return nil, fmt.Errorf("failed to fetch conversations: %w", err)
		}
		
		if resp.StatusCode() != http.StatusOK {
			return nil, fmt.Errorf("failed to fetch conversations: status %d", resp.StatusCode())
		}
		
		// Extract conversations from response (handle nested structure)
		conversations := response.Payload
		if len(conversations) == 0 {
			conversations = response.Data.Payload
		}
		if len(conversations) == 0 {
			conversations = response.Data.Data
		}
		
		if len(conversations) == 0 {
			break
		}
		
		// Search for conversation with matching contact
		for _, conv := range conversations {
			if conv.Meta.Sender.ID == contactID {
				return &conv, nil
			}
		}
		
		page++
	}
	
	return nil, nil
}

// findResolvedConversationByContact searches for a resolved conversation with a contact
func findResolvedConversationByContact(client *resty.Client, accountID, inboxID string, contactID int) (*ChatwootConversation, error) {
	page := 1
	maxPages := 50
	
	for page <= maxPages {
		var response ChatwootConversationResponse
		
		resp, err := client.R().
			SetQueryParams(map[string]string{
				"status":     "resolved",
				"inbox_id":   inboxID,
				"page":       fmt.Sprintf("%d", page),
				"sort_order": "latest_first",
			}).
			SetResult(&response).
			Get(fmt.Sprintf("/api/v1/accounts/%s/conversations", accountID))
		
		if err != nil {
			return nil, fmt.Errorf("failed to fetch resolved conversations: %w", err)
		}
		
		if resp.StatusCode() != http.StatusOK {
			return nil, fmt.Errorf("failed to fetch resolved conversations: status %d", resp.StatusCode())
		}
		
		// Extract conversations from response (handle nested structure)
		conversations := response.Payload
		if len(conversations) == 0 {
			conversations = response.Data.Payload
		}
		if len(conversations) == 0 {
			conversations = response.Data.Data
		}
		
		if len(conversations) == 0 {
			break
		}
		
		// Search for conversation with matching contact
		for _, conv := range conversations {
			if conv.Meta.Sender.ID == contactID {
				return &conv, nil
			}
		}
		
		page++
	}
	
	return nil, nil
}

// reopenConversation reopens a resolved conversation
func reopenConversation(client *resty.Client, accountID string, conversationID int) error {
	type ToggleRequest struct {
		Status string `json:"status"`
	}
	
	request := ToggleRequest{Status: "open"}
	
	resp, err := client.R().
		SetBody(request).
		Post(fmt.Sprintf("/api/v1/accounts/%s/conversations/%d/toggle_status", accountID, conversationID))
	
	if err != nil {
		return fmt.Errorf("failed to reopen conversation: %w", err)
	}
	
	if resp.StatusCode() != http.StatusOK {
		return fmt.Errorf("failed to reopen conversation: status %d", resp.StatusCode())
	}
	
	return nil
}

// createConversation creates a new conversation
func createConversation(client *resty.Client, accountID string, contactID int, inboxID string) (*ChatwootConversation, error) {
	type ConversationRequest struct {
		ContactID int    `json:"contact_id"`
		InboxID   string `json:"inbox_id"`
		Status    string `json:"status"`
	}
	
	request := ConversationRequest{
		ContactID: contactID,
		InboxID:   inboxID,
		Status:    "open",
	}
	
	var response struct {
		Payload ChatwootConversation `json:"payload"`
		ID      int                  `json:"id"`
	}
	
	resp, err := client.R().
		SetBody(request).
		SetResult(&response).
		Post(fmt.Sprintf("/api/v1/accounts/%s/conversations", accountID))
	
	if err != nil {
		return nil, fmt.Errorf("failed to create conversation: %w", err)
	}
	
	if resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusCreated {
		return nil, fmt.Errorf("failed to create conversation: status %d, body: %s", resp.StatusCode(), string(resp.Body()))
	}
	
	if response.ID != 0 {
		response.Payload.ID = response.ID
		return &response.Payload, nil
	}
	
	return &response.Payload, nil
}

// findOrCreateConversation finds an existing conversation or creates a new one
func findOrCreateConversation(client *resty.Client, accountID, inboxID string, contactID int, allowReopen bool) (*ChatwootConversation, error) {
	// First try to find open conversation
	conversation, err := findConversationByContact(client, accountID, inboxID, contactID)
	if err != nil {
		log.Warn().Err(err).Int("contact_id", contactID).Msg("Error searching for open conversation")
	}
	
	if conversation != nil {
		log.Info().Int("conversation_id", conversation.ID).Int("contact_id", contactID).Msg("Open conversation found")
		return conversation, nil
	}
	
	// If allowReopen is true, try to find resolved conversation and reopen it
	if allowReopen {
		resolvedConv, err := findResolvedConversationByContact(client, accountID, inboxID, contactID)
		if err != nil {
			log.Warn().Err(err).Int("contact_id", contactID).Msg("Error searching for resolved conversation")
		}
		
		if resolvedConv != nil {
			log.Info().Int("conversation_id", resolvedConv.ID).Int("contact_id", contactID).Msg("Resolved conversation found, reopening")
			err = reopenConversation(client, accountID, resolvedConv.ID)
			if err != nil {
				return nil, fmt.Errorf("failed to reopen conversation: %w", err)
			}
			return resolvedConv, nil
		}
	}
	
	// Create new conversation
	log.Info().Int("contact_id", contactID).Msg("Creating new conversation")
	conversation, err = createConversation(client, accountID, contactID, inboxID)
	if err != nil {
		return nil, fmt.Errorf("failed to create conversation: %w", err)
	}
	
	return conversation, nil
}

// sendTextMessage sends a text message to Chatwoot
func sendTextMessage(client *resty.Client, accountID string, conversationID int, content string, messageType string, replyID *int, sourceID string) error {
	type MessageRequest struct {
		Content     string                 `json:"content"`
		MessageType string                 `json:"message_type"`
		SourceID    string                 `json:"source_id,omitempty"`
		ContentAttributes map[string]interface{} `json:"content_attributes,omitempty"`
	}
	
	request := MessageRequest{
		Content:     content,
		MessageType: messageType,
	}
	
	if sourceID != "" {
		request.SourceID = sourceID
	}
	
	if replyID != nil {
		if request.ContentAttributes == nil {
			request.ContentAttributes = make(map[string]interface{})
		}
		request.ContentAttributes["in_reply_to"] = *replyID
		request.ContentAttributes["in_reply_to_external_id"] = nil
	}
	
	resp, err := client.R().
		SetBody(request).
		Post(fmt.Sprintf("/api/v1/accounts/%s/conversations/%d/messages", accountID, conversationID))
	
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}
	
	if resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusCreated {
		return fmt.Errorf("failed to send message: status %d, body: %s", resp.StatusCode(), string(resp.Body()))
	}
	
	return nil
}

// sendMessageWithAttachment sends a message with an attachment to Chatwoot
func sendMessageWithAttachment(client *resty.Client, accountID string, conversationID int, content string, messageType string, attachmentData []byte, filename, contentType string, replyID *int, sourceID string) error {
	// Validate attachment data
	if len(attachmentData) == 0 {
		return fmt.Errorf("attachment data is empty")
	}
	
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	
	// Add content field (only if content is provided, matching TypeScript behavior)
	// In TypeScript: if (content) { data.append('content', content); }
	if content != "" {
		if err := writer.WriteField("content", content); err != nil {
			writer.Close()
			return fmt.Errorf("failed to write content field: %w", err)
		}
	}
	if err := writer.WriteField("message_type", messageType); err != nil {
		writer.Close()
		return fmt.Errorf("failed to write message_type field: %w", err)
	}
	
	if sourceID != "" {
		if err := writer.WriteField("source_id", sourceID); err != nil {
			writer.Close()
			return fmt.Errorf("failed to write source_id field: %w", err)
		}
	}
	
	if replyID != nil {
		replyIDStr := fmt.Sprintf("%d", *replyID)
		if err := writer.WriteField("content_attributes[in_reply_to]", replyIDStr); err != nil {
			writer.Close()
			return fmt.Errorf("failed to write in_reply_to field: %w", err)
		}
		if err := writer.WriteField("content_attributes[in_reply_to_external_id]", ""); err != nil {
			writer.Close()
			return fmt.Errorf("failed to write in_reply_to_external_id field: %w", err)
		}
	}
	
	// Determine Content-Type: use provided contentType, or detect from filename extension
	detectedContentType := contentType
	if detectedContentType == "" {
		ext := strings.ToLower(filepath.Ext(filename))
		detectedContentType = mime.TypeByExtension(ext)
		if detectedContentType == "" {
			// Fallback to application/octet-stream if we can't detect
			detectedContentType = "application/octet-stream"
		}
	}
	
	// Create file part using CreatePart with explicit headers
	// This gives us full control over Content-Disposition and Content-Type
	// Rails/ActiveStorage expects the file in attachments[] array format
	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", fmt.Sprintf(`form-data; name="attachments[]"; filename="%s"`, filename))
	header.Set("Content-Type", detectedContentType)
	
	part, err := writer.CreatePart(header)
	if err != nil {
		writer.Close()
		return fmt.Errorf("failed to create multipart part: %w", err)
	}
	
	// Write attachment data using io.Copy to ensure all data is written
	// Using a bytes.Reader ensures we can write the full content
	dataReader := bytes.NewReader(attachmentData)
	bytesWritten, err := io.Copy(part, dataReader)
	if err != nil {
		writer.Close()
		return fmt.Errorf("failed to write attachment data: %w", err)
	}
	
	if bytesWritten != int64(len(attachmentData)) {
		writer.Close()
		return fmt.Errorf("incomplete write: wrote %d of %d bytes", bytesWritten, len(attachmentData))
	}
	
	// Get content type before closing writer
	contentTypeHeader := writer.FormDataContentType()
	
	// Close writer to finalize multipart data
	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to close multipart writer: %w", err)
	}
	
	// Validate that body has data
	if body.Len() == 0 {
		return fmt.Errorf("multipart body is empty after writing")
	}
	
	bodySize := body.Len()
	log.Debug().
		Int("body_size", bodySize).
		Int("attachment_size", len(attachmentData)).
		Str("filename", filename).
		Str("content_type", detectedContentType).
		Msg("Sending attachment to Chatwoot")
	
	// Create request with body as io.Reader using bytes.NewReader to ensure we read from the beginning
	// Using bytes.NewReader ensures the body is read from position 0
	req, err := http.NewRequest("POST", 
		fmt.Sprintf("%s/api/v1/accounts/%s/conversations/%d/messages", 
			strings.TrimSuffix(client.BaseURL, "/"), accountID, conversationID), bytes.NewReader(body.Bytes()))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	// Set headers
	req.Header.Set("Content-Type", contentTypeHeader)
	req.Header.Set("api_access_token", client.Header.Get("api_access_token"))
	req.ContentLength = int64(bodySize)
	
	httpClient := &http.Client{Timeout: 60 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	// Read response body for debugging
	respBodyBytes, _ := io.ReadAll(resp.Body)
	
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to send message with attachment: status %d, body: %s", resp.StatusCode, string(respBodyBytes))
	}
	
	// Log response for debugging (first 500 chars to avoid huge logs)
	respPreview := string(respBodyBytes)
	if len(respPreview) > 500 {
		respPreview = respPreview[:500] + "..."
	}
	log.Debug().
		Str("response_preview", respPreview).
		Int("response_size", len(respBodyBytes)).
		Msg("Chatwoot response received")
	
	log.Info().
		Int("status", resp.StatusCode).
		Int("attachment_size", len(attachmentData)).
		Str("filename", filename).
		Msg("Attachment sent successfully to Chatwoot")
	
	return nil
}

// downloadMediaFromBase64 decodes base64 media data
func downloadMediaFromBase64(base64Data string) ([]byte, error) {
	// Clean up base64 string
	base64Data = strings.TrimSpace(base64Data)
	base64Data = strings.ReplaceAll(base64Data, " ", "+")
	base64Data = strings.ReplaceAll(base64Data, "-", "+")
	base64Data = strings.ReplaceAll(base64Data, "_", "/")
	
	// Add padding if needed
	pad := len(base64Data) % 4
	if pad > 0 {
		base64Data += strings.Repeat("=", 4-pad)
	}
	
	data, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}
	
	return data, nil
}

// downloadMediaFromURL downloads media from a URL (e.g., S3 URL)
func downloadMediaFromURL(url string) ([]byte, error) {
	if url == "" {
		return nil, fmt.Errorf("empty URL")
	}
	
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download from URL: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download from URL: status %d", resp.StatusCode)
	}
	
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	
	return data, nil
}

// ProcessIncomingMessage processes an incoming WhatsApp message and sends it to Chatwoot
func (s *server) ProcessIncomingMessage(userID string, phone, content, senderPhoto, contactName string, lid, jid string, image, audio, document, video map[string]interface{}, messageID string, replyID *int) error {
	config, err := s.getChatwootConfig(userID)
	if err != nil {
		return fmt.Errorf("failed to get Chatwoot config: %w", err)
	}
	
	if config.BaseURL == "" || config.AccountID == "" || config.APIToken == "" {
		return fmt.Errorf("Chatwoot not configured")
	}
	
	if config.InboxID == "" {
		return fmt.Errorf("Chatwoot inbox not created. Please create inbox first")
	}
	
	client := getChatwootClient(config.BaseURL, config.APIToken)
	
	// Determine identifier (LID > JID > phone)
	identifier := lid
	if identifier == "" {
		identifier = jid
	}
	if identifier == "" {
		identifier = phone
	}
	
	if identifier == "" {
		return fmt.Errorf("no valid identifier (phone, lid, or jid)")
	}
	
	// Determine contact name
	if contactName == "" {
		if lid != "" {
			contactName = fmt.Sprintf("Contact %s", lid)
		} else if jid != "" {
			contactName = fmt.Sprintf("Contact %s", jid)
		} else {
			contactName = fmt.Sprintf("Contact %s", phone)
		}
	}
	
	// Find or create contact
	contact, err := findOrCreateContact(client, config.AccountID, contactName, identifier, phone, senderPhoto)
	if err != nil {
		return fmt.Errorf("failed to find or create contact: %w", err)
	}
	
	// Find or create conversation
	conversation, err := findOrCreateConversation(client, config.AccountID, config.InboxID, contact.ID, true)
	if err != nil {
		return fmt.Errorf("failed to find or create conversation: %w", err)
	}
	
	// Generate source_id to identify messages that originated from WhatsApp
	sourceID := ""
	if messageID != "" {
		sourceID = fmt.Sprintf("WAID:%s", messageID)
	}
	
	// Send message based on type
	if video != nil {
		// Send video - match ProcessOutgoingMessage logic
		videoBase64, _ := video["base64"].(string)
		videoData, err := downloadMediaFromBase64(videoBase64)
		if err == nil && videoData != nil && len(videoData) > 0 {
			mimeType, _ := video["mimeType"].(string)
			if mimeType == "" {
				mimeType = "video/mp4"
			}
			caption, _ := video["caption"].(string)
			if content == "" {
				content = caption
			}
			filename := fmt.Sprintf("video_%d.mp4", time.Now().Unix())
			err = sendMessageWithAttachment(client, config.AccountID, conversation.ID, content, "incoming", videoData, filename, mimeType, replyID, sourceID)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to send video, falling back to text")
				return sendTextMessage(client, config.AccountID, conversation.ID, content+" [Video]", "incoming", replyID, sourceID)
			}
			return nil
		}
		// If base64 failed, try S3 URL
		if s3url, ok := video["s3url"].(string); ok && s3url != "" {
			videoData, err = downloadMediaFromURL(s3url)
			if err == nil && videoData != nil && len(videoData) > 0 {
				mimeType, _ := video["mimeType"].(string)
				if mimeType == "" {
					mimeType = "video/mp4"
				}
				caption, _ := video["caption"].(string)
				if content == "" {
					content = caption
				}
				filename := fmt.Sprintf("video_%d.mp4", time.Now().Unix())
				err = sendMessageWithAttachment(client, config.AccountID, conversation.ID, content, "incoming", videoData, filename, mimeType, replyID, sourceID)
				if err != nil {
					log.Warn().Err(err).Msg("Failed to send video from S3, falling back to text")
					return sendTextMessage(client, config.AccountID, conversation.ID, content+" [Video]", "incoming", replyID, sourceID)
				}
				return nil
			}
		}
		log.Warn().Msg("Video has no valid base64 or S3 URL, falling back to text")
		return sendTextMessage(client, config.AccountID, conversation.ID, content+" [Video]", "incoming", replyID, sourceID)
	} else if document != nil {
		// Send document - match ProcessOutgoingMessage logic
		docBase64, _ := document["base64"].(string)
		docData, err := downloadMediaFromBase64(docBase64)
		if err == nil && docData != nil && len(docData) > 0 {
			mimeType, _ := document["mimeType"].(string)
			if mimeType == "" {
				mimeType = "application/octet-stream"
			}
			fileName, _ := document["fileName"].(string)
			if fileName == "" {
				fileName = "document"
			}
			caption, _ := document["caption"].(string)
			if content == "" {
				content = caption
			}
			err = sendMessageWithAttachment(client, config.AccountID, conversation.ID, content, "incoming", docData, fileName, mimeType, replyID, sourceID)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to send document, falling back to text")
				return sendTextMessage(client, config.AccountID, conversation.ID, content+" [Document]", "incoming", replyID, sourceID)
			}
			return nil
		}
		// If base64 failed, try S3 URL
		if s3url, ok := document["s3url"].(string); ok && s3url != "" {
			docData, err = downloadMediaFromURL(s3url)
			if err == nil && docData != nil && len(docData) > 0 {
				mimeType, _ := document["mimeType"].(string)
				if mimeType == "" {
					mimeType = "application/octet-stream"
				}
				fileName, _ := document["fileName"].(string)
				if fileName == "" {
					fileName = "document"
				}
				caption, _ := document["caption"].(string)
				if content == "" {
					content = caption
				}
				err = sendMessageWithAttachment(client, config.AccountID, conversation.ID, content, "incoming", docData, fileName, mimeType, replyID, sourceID)
				if err != nil {
					log.Warn().Err(err).Msg("Failed to send document from S3, falling back to text")
					return sendTextMessage(client, config.AccountID, conversation.ID, content+" [Document]", "incoming", replyID, sourceID)
				}
				return nil
			}
		}
		log.Warn().Msg("Document has no valid base64 or S3 URL, falling back to text")
		return sendTextMessage(client, config.AccountID, conversation.ID, content+" [Document]", "incoming", replyID, sourceID)
	} else if audio != nil {
		// Send audio - match ProcessOutgoingMessage logic
		audioBase64, _ := audio["base64"].(string)
		audioData, err := downloadMediaFromBase64(audioBase64)
		if err == nil && audioData != nil && len(audioData) > 0 {
			mimeType, _ := audio["mimeType"].(string)
			// Clean mimeType - remove any parameters (e.g., "audio/ogg; codecs=opus" -> "audio/ogg")
			if mimeType != "" {
				parts := strings.Split(mimeType, ";")
				mimeType = strings.TrimSpace(parts[0])
			}
			if mimeType == "" {
				mimeType = "audio/ogg"
			}
			// Extract extension from mimeType (e.g., "audio/ogg" -> "ogg")
			ext := "ogg"
			if strings.Contains(mimeType, "mp3") || strings.Contains(mimeType, "mpeg") {
				ext = "mp3"
				mimeType = "audio/mpeg" // Standardize to audio/mpeg for MP3
			} else if strings.Contains(mimeType, "m4a") || strings.Contains(mimeType, "mp4a") {
				ext = "m4a"
				mimeType = "audio/mp4" // Standardize to audio/mp4 for M4A
			} else if strings.Contains(mimeType, "ogg") {
				ext = "ogg"
				mimeType = "audio/ogg" // Ensure clean audio/ogg
			} else if strings.Contains(mimeType, "wav") {
				ext = "wav"
				mimeType = "audio/wav"
			}
			filename := fmt.Sprintf("audio.%s", ext)
			// Send audio without text content - Chatwoot will display the audio player
			// Pass empty string for content - Chatwoot will show only the audio player
			err = sendMessageWithAttachment(client, config.AccountID, conversation.ID, "", "incoming", audioData, filename, mimeType, replyID, sourceID)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to send audio")
				// Don't fallback to text for audio - if audio fails, just return the error
				return err
			}
			return nil
		}
		// If base64 failed, try S3 URL
		if s3url, ok := audio["s3url"].(string); ok && s3url != "" {
			audioData, err = downloadMediaFromURL(s3url)
			if err == nil && audioData != nil && len(audioData) > 0 {
				mimeType, _ := audio["mimeType"].(string)
				// Clean mimeType - remove any parameters
				if mimeType != "" {
					parts := strings.Split(mimeType, ";")
					mimeType = strings.TrimSpace(parts[0])
				}
				if mimeType == "" {
					mimeType = "audio/ogg"
				}
				// Extract extension from mimeType
				ext := "ogg"
				if strings.Contains(mimeType, "mp3") || strings.Contains(mimeType, "mpeg") {
					ext = "mp3"
					mimeType = "audio/mpeg"
				} else if strings.Contains(mimeType, "m4a") || strings.Contains(mimeType, "mp4a") {
					ext = "m4a"
					mimeType = "audio/mp4"
				} else if strings.Contains(mimeType, "ogg") {
					ext = "ogg"
					mimeType = "audio/ogg"
				} else if strings.Contains(mimeType, "wav") {
					ext = "wav"
					mimeType = "audio/wav"
				}
				filename := fmt.Sprintf("audio.%s", ext)
				err = sendMessageWithAttachment(client, config.AccountID, conversation.ID, "", "incoming", audioData, filename, mimeType, replyID, sourceID)
				if err != nil {
					log.Warn().Err(err).Msg("Failed to send audio from S3")
					return err
				}
				return nil
			}
		}
		log.Warn().Msg("Audio has no valid base64 or S3 URL")
		return fmt.Errorf("audio has no valid base64 or S3 URL")
	} else if image != nil {
		// Send image - match ProcessOutgoingMessage logic
		imageBase64, _ := image["base64"].(string)
		imageData, err := downloadMediaFromBase64(imageBase64)
		if err == nil && imageData != nil && len(imageData) > 0 {
			mimeType, _ := image["mimeType"].(string)
			if mimeType == "" {
				mimeType = "image/jpeg"
			}
			caption, _ := image["caption"].(string)
			if content == "" {
				content = caption
			}
			ext := "jpg"
			if strings.Contains(mimeType, "png") {
				ext = "png"
			} else if strings.Contains(mimeType, "gif") {
				ext = "gif"
			} else if strings.Contains(mimeType, "webp") {
				ext = "webp"
			}
			filename := fmt.Sprintf("image.%s", ext)
			err = sendMessageWithAttachment(client, config.AccountID, conversation.ID, content, "incoming", imageData, filename, mimeType, replyID, sourceID)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to send image, falling back to text")
				return sendTextMessage(client, config.AccountID, conversation.ID, content+" [Image]", "incoming", replyID, sourceID)
			}
			return nil
		}
		// If base64 failed, try S3 URL
		if s3url, ok := image["s3url"].(string); ok && s3url != "" {
			imageData, err = downloadMediaFromURL(s3url)
			if err == nil && imageData != nil && len(imageData) > 0 {
				mimeType, _ := image["mimeType"].(string)
				if mimeType == "" {
					mimeType = "image/jpeg"
				}
				caption, _ := image["caption"].(string)
				if content == "" {
					content = caption
				}
				ext := "jpg"
				if strings.Contains(mimeType, "png") {
					ext = "png"
				} else if strings.Contains(mimeType, "gif") {
					ext = "gif"
				} else if strings.Contains(mimeType, "webp") {
					ext = "webp"
				}
				filename := fmt.Sprintf("image.%s", ext)
				err = sendMessageWithAttachment(client, config.AccountID, conversation.ID, content, "incoming", imageData, filename, mimeType, replyID, sourceID)
				if err != nil {
					log.Warn().Err(err).Msg("Failed to send image from S3, falling back to text")
					return sendTextMessage(client, config.AccountID, conversation.ID, content+" [Image]", "incoming", replyID, sourceID)
				}
				return nil
			}
		}
		log.Warn().Msg("Image has no valid base64 or S3 URL, falling back to text")
		return sendTextMessage(client, config.AccountID, conversation.ID, content+" [Image]", "incoming", replyID, sourceID)
	}
	
	// Send text message
	return sendTextMessage(client, config.AccountID, conversation.ID, content, "incoming", replyID, sourceID)
}

// ProcessOutgoingMessage processes an outgoing WhatsApp message and sends it to Chatwoot
func (s *server) ProcessOutgoingMessage(userID string, phone, content string, lid, jid string, image, audio, document, video map[string]interface{}, messageID string, replyID *int) error {
	config, err := s.getChatwootConfig(userID)
	if err != nil {
		return fmt.Errorf("failed to get Chatwoot config: %w", err)
	}
	
	if config.BaseURL == "" || config.AccountID == "" || config.APIToken == "" {
		return fmt.Errorf("Chatwoot not configured")
	}
	
	if config.InboxID == "" {
		return fmt.Errorf("Chatwoot inbox not created. Please create inbox first")
	}
	
	client := getChatwootClient(config.BaseURL, config.APIToken)
	
	// Determine identifier (LID > JID > phone)
	identifier := lid
	if identifier == "" {
		identifier = jid
	}
	if identifier == "" {
		identifier = phone
	}
	
	if identifier == "" {
		return fmt.Errorf("no valid identifier (phone, lid, or jid)")
	}
	
	// Find or create contact
	contact, err := findOrCreateContact(client, config.AccountID, "", identifier, phone, "")
	if err != nil {
		return fmt.Errorf("failed to find or create contact: %w", err)
	}
	
	// Find or create conversation
	conversation, err := findOrCreateConversation(client, config.AccountID, config.InboxID, contact.ID, true)
	if err != nil {
		return fmt.Errorf("failed to find or create conversation: %w", err)
	}
	
	// Generate source_id to identify messages that originated from WhatsApp
	sourceID := ""
	if messageID != "" {
		sourceID = fmt.Sprintf("WAID:%s", messageID)
	}
	
	// Send message based on type
	if video != nil {
		// Send video
		videoBase64, _ := video["base64"].(string)
		videoData, err := downloadMediaFromBase64(videoBase64)
		if err == nil && videoData != nil && len(videoData) > 0 {
			mimeType, _ := video["mimeType"].(string)
			if mimeType == "" {
				mimeType = "video/mp4"
			}
			caption, _ := video["caption"].(string)
			if content == "" {
				content = caption
			}
			filename := fmt.Sprintf("video_%d.mp4", time.Now().Unix())
			err = sendMessageWithAttachment(client, config.AccountID, conversation.ID, content, "outgoing", videoData, filename, mimeType, replyID, sourceID)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to send video, falling back to text")
				return sendTextMessage(client, config.AccountID, conversation.ID, content+" [Video]", "outgoing", replyID, sourceID)
			}
			return nil
		}
	} else if document != nil {
		// Send document
		docBase64, _ := document["base64"].(string)
		docData, err := downloadMediaFromBase64(docBase64)
		if err == nil && docData != nil && len(docData) > 0 {
			mimeType, _ := document["mimeType"].(string)
			if mimeType == "" {
				mimeType = "application/octet-stream"
			}
			fileName, _ := document["fileName"].(string)
			if fileName == "" {
				fileName = "document"
			}
			caption, _ := document["caption"].(string)
			if content == "" {
				content = caption
			}
			err = sendMessageWithAttachment(client, config.AccountID, conversation.ID, content, "outgoing", docData, fileName, mimeType, replyID, sourceID)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to send document, falling back to text")
				return sendTextMessage(client, config.AccountID, conversation.ID, content+" [Document]", "outgoing", replyID, sourceID)
			}
			return nil
		}
	} else if audio != nil {
		// Send audio
		audioBase64, _ := audio["base64"].(string)
		audioData, err := downloadMediaFromBase64(audioBase64)
		if err == nil && audioData != nil && len(audioData) > 0 {
			mimeType, _ := audio["mimeType"].(string)
			// Clean mimeType - remove any parameters
			if mimeType != "" {
				parts := strings.Split(mimeType, ";")
				mimeType = strings.TrimSpace(parts[0])
			}
			if mimeType == "" {
				mimeType = "audio/ogg"
			}
			// Extract extension from mimeType
			ext := "ogg"
			if strings.Contains(mimeType, "mp3") || strings.Contains(mimeType, "mpeg") {
				ext = "mp3"
				mimeType = "audio/mpeg"
			} else if strings.Contains(mimeType, "m4a") || strings.Contains(mimeType, "mp4a") {
				ext = "m4a"
				mimeType = "audio/mp4"
			} else if strings.Contains(mimeType, "ogg") {
				ext = "ogg"
				mimeType = "audio/ogg"
			} else if strings.Contains(mimeType, "wav") {
				ext = "wav"
				mimeType = "audio/wav"
			}
			filename := fmt.Sprintf("audio.%s", ext)
			err = sendMessageWithAttachment(client, config.AccountID, conversation.ID, "", "outgoing", audioData, filename, mimeType, replyID, sourceID)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to send audio")
				return err
			}
			return nil
		}
	} else if image != nil {
		// Send image
		imageBase64, _ := image["base64"].(string)
		imageData, err := downloadMediaFromBase64(imageBase64)
		if err == nil && imageData != nil && len(imageData) > 0 {
			mimeType, _ := image["mimeType"].(string)
			if mimeType == "" {
				mimeType = "image/jpeg"
			}
			caption, _ := image["caption"].(string)
			if content == "" {
				content = caption
			}
			ext := "jpg"
			if strings.Contains(mimeType, "png") {
				ext = "png"
			} else if strings.Contains(mimeType, "gif") {
				ext = "gif"
			} else if strings.Contains(mimeType, "webp") {
				ext = "webp"
			}
			filename := fmt.Sprintf("image.%s", ext)
			err = sendMessageWithAttachment(client, config.AccountID, conversation.ID, content, "outgoing", imageData, filename, mimeType, replyID, sourceID)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to send image, falling back to text")
				return sendTextMessage(client, config.AccountID, conversation.ID, content+" [Image]", "outgoing", replyID, sourceID)
			}
			return nil
		}
	}
	
	// Send text message
	return sendTextMessage(client, config.AccountID, conversation.ID, content, "outgoing", replyID, sourceID)
}

// ChatwootUser represents a Chatwoot user from access_tokens table
type ChatwootUser struct {
	UserType string
	UserID   int
}

// getChatwootUser retrieves the Chatwoot user from access_tokens table
func getChatwootUser(chatwootDB *sql.DB, apiToken string) (*ChatwootUser, error) {
	var user ChatwootUser
	err := chatwootDB.QueryRow(`
		SELECT owner_type AS user_type, owner_id AS user_id
		FROM access_tokens
		WHERE token = $1`, apiToken).Scan(&user.UserType, &user.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get Chatwoot user: %w", err)
	}
	return &user, nil
}

// updateContactName updates a contact's name in Chatwoot database if pushName is found
// It updates the name if it's currently empty, null, or matches the phone number
func updateContactName(chatwootDB *sql.DB, accountID int, contactID int, pushName string) error {
	if pushName == "" {
		return nil
	}
	_, err := chatwootDB.Exec(`
		UPDATE contacts 
		SET name = $1, updated_at = NOW()
		WHERE id = $2 AND account_id = $3 AND (name IS NULL OR name = '' OR name = phone_number OR name = REPLACE(phone_number, '+', ''))`,
		pushName, contactID, accountID)
	return err
}

// ImportChatHistory imports chat history from message_history table to Chatwoot
func (s *server) ImportChatHistory(userID string, config *ChatwootConfig) error {
	// Check if message import is enabled
	if !config.ImportMessages {
		log.Info().Str("userID", userID).Msg("Message import is disabled, skipping import")
		return nil
	}

	if config.ImportDatabaseConnectionURI == "" {
		log.Info().Str("userID", userID).Msg("Import database URI not configured, skipping import")
		return nil
	}

	if config.InboxID == "" {
		log.Warn().Str("userID", userID).Msg("Inbox ID not set, cannot import history")
		return fmt.Errorf("inbox ID not set")
	}

	// Connect to Chatwoot's database with SSL setting
	connectionURI := buildDatabaseConnectionURI(config.ImportDatabaseConnectionURI, config.ImportDatabaseSSL)
	chatwootDB, err := sql.Open("postgres", connectionURI)
	if err != nil {
		return fmt.Errorf("failed to connect to Chatwoot database: %w", err)
	}
	defer chatwootDB.Close()

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if err := chatwootDB.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping Chatwoot database: %w", err)
	}

	// Get Chatwoot user from access_tokens table
	chatwootUser, err := getChatwootUser(chatwootDB, config.APIToken)
	if err != nil {
		return fmt.Errorf("failed to get Chatwoot user: %w", err)
	}

	// Get Chatwoot API client (for creating contacts/conversations)
	client := getChatwootClient(config.BaseURL, config.APIToken)
	accountIDInt, err := strconv.Atoi(config.AccountID)
	if err != nil {
		return fmt.Errorf("invalid account ID: %w", err)
	}
	inboxIDInt, err := strconv.Atoi(config.InboxID)
	if err != nil {
		return fmt.Errorf("invalid inbox ID: %w", err)
	}

	// Get all messages from message_history for this user
	var messages []HistoryMessage
	query := `
		SELECT id, user_id, chat_jid, sender_jid, sender_name, message_id, timestamp, message_type, 
		       text_content, media_link, COALESCE(quoted_message_id, '') as quoted_message_id, 
		       COALESCE(datajson, '') as datajson
		FROM message_history
		WHERE user_id = $1
		ORDER BY timestamp ASC`
	if s.db.DriverName() == "sqlite" {
		query = strings.ReplaceAll(query, "$1", "?")
	}

	err = s.db.Select(&messages, query, userID)
	if err != nil {
		return fmt.Errorf("failed to get messages from history: %w", err)
	}

	if len(messages) == 0 {
		log.Info().Str("userID", userID).Msg("No messages found in history to import")
		return nil
	}

	log.Info().Str("userID", userID).Int("message_count", len(messages)).Msg("Starting chat history import")

	// Group messages by chat_jid to create contacts and conversations
	chatMap := make(map[string][]HistoryMessage)
	for _, msg := range messages {
		chatMap[msg.ChatJID] = append(chatMap[msg.ChatJID], msg)
	}

	importedCount := 0
	errorCount := 0

	// Process each chat
	for chatJID, chatMessages := range chatMap {
		// Skip group chats (they end with @g.us)
		if strings.HasSuffix(chatJID, "@g.us") {
			log.Debug().Str("chatJID", chatJID).Msg("Skipping group chat")
			continue
		}

		// Extract phone number from chat JID
		phoneNumber := strings.Split(chatJID, "@")[0]
		if phoneNumber == "" {
			continue
		}

		// Find the best sender name from message_history table
		// We prefer sender_name from incoming messages (not from "me")
		contactName := phoneNumber
		var bestSenderName string
		for _, msg := range chatMessages {
			// Only use sender_name from incoming messages (not from instance)
			// Check if message is from contact by checking sender_jid and datajson
			isFromMe := false
			if msg.SenderJID == "me" {
				isFromMe = true
			} else if msg.DataJson != "" {
				var data map[string]interface{}
				if err := json.Unmarshal([]byte(msg.DataJson), &data); err == nil {
					if info, ok := data["Info"].(map[string]interface{}); ok {
						if isFromMeVal, ok := info["IsFromMe"].(bool); ok {
							isFromMe = isFromMeVal
						}
					}
					// Also check RawMessage.key.fromMe as fallback
					if !isFromMe {
						if rawMsg, ok := data["RawMessage"].(map[string]interface{}); ok {
							if key, ok := rawMsg["key"].(map[string]interface{}); ok {
								if fromMeVal, ok := key["fromMe"].(bool); ok {
									isFromMe = fromMeVal
								}
							}
						}
					}
				}
			}
			
			// Use sender_name from incoming messages only
			if !isFromMe && msg.SenderName != "" && msg.SenderName != phoneNumber {
				bestSenderName = msg.SenderName
				contactName = msg.SenderName
				// Continue checking to find the best sender_name
				// (we'll use the last non-empty one found)
			}
		}

		// Create or find contact with sender name from message_history
		contact, err := findOrCreateContact(client, config.AccountID, contactName, chatJID, phoneNumber, "")
		if err != nil {
			log.Warn().Err(err).Str("chatJID", chatJID).Msg("Failed to create/find contact")
			errorCount++
			continue
		}

		// Update contact name with sender_name if found and contact name is still phone number
		if bestSenderName != "" {
			err = updateContactName(chatwootDB, accountIDInt, contact.ID, bestSenderName)
			if err != nil {
				log.Warn().Err(err).Int("contact_id", contact.ID).Str("sender_name", bestSenderName).Msg("Failed to update contact name")
			}
		}

		// Get or create contact_inbox
		var contactInboxID int
		err = chatwootDB.QueryRow(`
			SELECT id FROM contact_inboxes 
			WHERE contact_id = $1 AND inbox_id = $2`,
			contact.ID, inboxIDInt).Scan(&contactInboxID)
		if err == sql.ErrNoRows {
			// Create contact_inbox
			err = chatwootDB.QueryRow(`
				INSERT INTO contact_inboxes (contact_id, inbox_id, source_id, created_at, updated_at)
				VALUES ($1, $2, gen_random_uuid(), NOW(), NOW())
				RETURNING id`,
				contact.ID, inboxIDInt).Scan(&contactInboxID)
			if err != nil {
				log.Warn().Err(err).Str("chatJID", chatJID).Msg("Failed to create contact_inbox")
				errorCount++
				continue
			}
		} else if err != nil {
			log.Warn().Err(err).Str("chatJID", chatJID).Msg("Failed to get contact_inbox")
			errorCount++
			continue
		}

		// Get or create conversation
		var conversationID int
		err = chatwootDB.QueryRow(`
			SELECT id FROM conversations 
			WHERE account_id = $1 AND inbox_id = $2 AND contact_id = $3 AND contact_inbox_id = $4`,
			accountIDInt, inboxIDInt, contact.ID, contactInboxID).Scan(&conversationID)
		if err == sql.ErrNoRows {
			// Create conversation
			err = chatwootDB.QueryRow(`
				INSERT INTO conversations (account_id, inbox_id, status, contact_id, contact_inbox_id, uuid, last_activity_at, created_at, updated_at)
				VALUES ($1, $2, 0, $3, $4, gen_random_uuid(), NOW(), NOW(), NOW())
				RETURNING id`,
				accountIDInt, inboxIDInt, contact.ID, contactInboxID).Scan(&conversationID)
			if err != nil {
				log.Warn().Err(err).Str("chatJID", chatJID).Msg("Failed to create conversation")
				errorCount++
				continue
			}
		} else if err != nil {
			log.Warn().Err(err).Str("chatJID", chatJID).Msg("Failed to get conversation")
			errorCount++
			continue
		}

		// Check which messages are already imported by querying Chatwoot's database
		existingSourceIDs := make(map[string]bool)
		rows, err := chatwootDB.QueryContext(ctx, `
			SELECT source_id 
			FROM messages 
			WHERE inbox_id = $1 AND conversation_id = $2 AND source_id IS NOT NULL`,
			inboxIDInt, conversationID)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var sourceID string
				if err := rows.Scan(&sourceID); err == nil {
					existingSourceIDs[sourceID] = true
				}
			}
		}

		// Prepare batch insert for messages
		var messagesToInsert []struct {
			content      string
			messageType  string
			senderType   string
			senderID     int
			sourceID     string
			timestamp    time.Time
			inReplyTo    *int
		}

		// Collect messages to import
		for _, msg := range chatMessages {
			// Skip if already imported
			sourceID := fmt.Sprintf("WAID:%s", msg.MessageID)
			if existingSourceIDs[sourceID] {
				continue
			}

			// Determine message type (0 = incoming, 1 = outgoing)
			// Check Info.IsFromMe in datajson to determine if message is from instance
			// Also check sender_jid == "me" as fallback for messages sent via API
			isFromMe := false
			if msg.DataJson != "" {
				var data map[string]interface{}
				if err := json.Unmarshal([]byte(msg.DataJson), &data); err == nil {
					if info, ok := data["Info"].(map[string]interface{}); ok {
						if isFromMeVal, ok := info["IsFromMe"].(bool); ok {
							isFromMe = isFromMeVal
						}
					}
					// Also check RawMessage.key.fromMe as fallback
					if !isFromMe {
						if rawMsg, ok := data["RawMessage"].(map[string]interface{}); ok {
							if key, ok := rawMsg["key"].(map[string]interface{}); ok {
								if fromMeVal, ok := key["fromMe"].(bool); ok {
									isFromMe = fromMeVal
								}
							}
						}
					}
				}
			}
			// Fallback: check if sender_jid is "me" (for messages sent via API)
			if !isFromMe && msg.SenderJID == "me" {
				isFromMe = true
			}

			messageType := "0"
			senderType := "Contact"
			senderID := contact.ID
			if isFromMe {
				messageType = "1"
				senderType = chatwootUser.UserType
				senderID = chatwootUser.UserID
			}

			// Get content
			content := msg.TextContent
			if content == "" && msg.MediaLink != "" {
				content = fmt.Sprintf("[Media: %s]", msg.MessageType)
			}

			// Handle quoted messages
			var inReplyTo *int
			if msg.QuotedMessageID != "" {
				var quotedMsgID int
				err := chatwootDB.QueryRowContext(ctx, `
					SELECT id FROM messages 
					WHERE inbox_id = $1 AND conversation_id = $2 AND source_id = $3`,
					inboxIDInt, conversationID, fmt.Sprintf("WAID:%s", msg.QuotedMessageID)).Scan(&quotedMsgID)
				if err == nil {
					inReplyTo = &quotedMsgID
				}
			}

			messagesToInsert = append(messagesToInsert, struct {
				content      string
				messageType  string
				senderType   string
				senderID     int
				sourceID     string
				timestamp    time.Time
				inReplyTo    *int
			}{
				content:     content,
				messageType: messageType,
				senderType:  senderType,
				senderID:    senderID,
				sourceID:    sourceID,
				timestamp:   msg.Timestamp,
				inReplyTo:   inReplyTo,
			})
		}

		// Insert messages in batches
		batchSize := 1000
		for i := 0; i < len(messagesToInsert); i += batchSize {
			end := i + batchSize
			if end > len(messagesToInsert) {
				end = len(messagesToInsert)
			}
			batch := messagesToInsert[i:end]

			// Build batch insert query
			var values []string
			var args []interface{}
			argIndex := 1

			for _, msgData := range batch {
				// Build content_attributes JSON for in_reply_to if needed
				var contentAttributes interface{}
				if msgData.inReplyTo != nil {
					contentAttributes = map[string]interface{}{
						"in_reply_to": *msgData.inReplyTo,
					}
				} else {
					contentAttributes = map[string]interface{}{}
				}

				// Convert to JSON string for PostgreSQL JSONB
				contentAttributesJSON, err := json.Marshal(contentAttributes)
				if err != nil {
					contentAttributesJSON = []byte("{}")
				}

				values = append(values, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d::jsonb, $%d, to_timestamp($%d), to_timestamp($%d))",
					argIndex,   // content
					argIndex+1, // processed_message_content
					argIndex+2, // account_id
					argIndex+3, // inbox_id
					argIndex+4, // conversation_id
					argIndex+5, // message_type
					argIndex+6, // private
					argIndex+7, // content_type
					argIndex+8, // sender_type
					argIndex+9, // sender_id
					argIndex+10, // source_id
					argIndex+11, // content_attributes (cast to jsonb)
					argIndex+12, // status
					argIndex+13, // timestamp
					argIndex+13)) // updated_at uses same timestamp

				args = append(args, msgData.content, msgData.content, accountIDInt, inboxIDInt, conversationID,
					msgData.messageType, false, 0, msgData.senderType, msgData.senderID, msgData.sourceID,
					string(contentAttributesJSON), 0, msgData.timestamp.Unix())

				argIndex += 14
			}

			query := fmt.Sprintf(`
				INSERT INTO messages 
				(content, processed_message_content, account_id, inbox_id, conversation_id, message_type, private, content_type,
				 sender_type, sender_id, source_id, content_attributes, status, created_at, updated_at)
				VALUES %s`,
				strings.Join(values, ", "))

			_, err = chatwootDB.ExecContext(ctx, query, args...)
			if err != nil {
				log.Warn().Err(err).Int("batch_start", i).Int("batch_end", end).Msg("Failed to insert message batch")
				errorCount += len(batch)
			} else {
				importedCount += len(batch)
			}
		}
	}

	log.Info().Str("userID", userID).
		Int("imported", importedCount).
		Int("errors", errorCount).
		Int("total", len(messages)).
		Msg("Chat history import completed")

	return nil
}


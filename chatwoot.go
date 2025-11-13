package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
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
	BaseURL       string `db:"chatwoot_base_url"`
	AccountID     string `db:"chatwoot_account_id"`
	APIToken      string `db:"chatwoot_api_token"`
	InboxName     string `db:"chatwoot_inbox_name"`
	InboxID       string `db:"chatwoot_inbox_id"`
	SignMsg       bool   `db:"chatwoot_sign_msg"`
	SignDelimiter string `db:"chatwoot_sign_delimiter"`
	MarkRead      bool   `db:"chatwoot_mark_read"`
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
			COALESCE(chatwoot_mark_read, false) as chatwoot_mark_read
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
				COALESCE(chatwoot_sign_delimiter, '\n') as chatwoot_sign_delimiter
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
					chatwoot_inbox_id
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
		} else {
			// Set default for mark_read if column doesn't exist
			config.MarkRead = false
		}
	}
	
	return &config, nil
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
func sendTextMessage(client *resty.Client, accountID string, conversationID int, content string, messageType string, replyID *int) error {
	type MessageRequest struct {
		Content     string                 `json:"content"`
		MessageType string                 `json:"message_type"`
		ContentAttributes map[string]interface{} `json:"content_attributes,omitempty"`
	}
	
	request := MessageRequest{
		Content:     content,
		MessageType: messageType,
	}
	
	if replyID != nil {
		request.ContentAttributes = map[string]interface{}{
			"in_reply_to":            *replyID,
			"in_reply_to_external_id": nil,
		}
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
func sendMessageWithAttachment(client *resty.Client, accountID string, conversationID int, content string, messageType string, attachmentData []byte, filename, contentType string, replyID *int) error {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	
	// Add content field (only if content is provided, matching TypeScript behavior)
	// In TypeScript: if (content) { data.append('content', content); }
	if content != "" {
		writer.WriteField("content", content)
	}
	writer.WriteField("message_type", messageType)
	
	if replyID != nil {
		replyIDStr := fmt.Sprintf("%d", *replyID)
		writer.WriteField("content_attributes[in_reply_to]", replyIDStr)
		writer.WriteField("content_attributes[in_reply_to_external_id]", "")
	}
	
	// Create form file part with explicit Content-Type header
	// This ensures Chatwoot recognizes images and audio properly
	// Following the pattern from TypeScript FormData.append('attachments[]', fileStream, { filename })
	var part io.Writer
	var err error
	
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
	
	// Create multipart part with explicit Content-Type header
	// This matches how FormData library in TypeScript handles it
	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", fmt.Sprintf(`form-data; name="attachments[]"; filename="%s"`, filename))
	header.Set("Content-Type", detectedContentType)
	
	part, err = writer.CreatePart(header)
	if err != nil {
		return fmt.Errorf("failed to create multipart part: %w", err)
	}
	
	_, err = part.Write(attachmentData)
	if err != nil {
		return fmt.Errorf("failed to write attachment data: %w", err)
	}
	
	err = writer.Close()
	if err != nil {
		return fmt.Errorf("failed to close multipart writer: %w", err)
	}
	
	req, err := http.NewRequest("POST", 
		fmt.Sprintf("%s/api/v1/accounts/%s/conversations/%d/messages", 
			strings.TrimSuffix(client.BaseURL, "/"), accountID, conversationID), &body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("api_access_token", client.Header.Get("api_access_token"))
	
	httpClient := &http.Client{Timeout: 60 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to send message with attachment: status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}
	
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
	
	// Send message based on type
	if video != nil {
		// Send video
		videoBase64, _ := video["base64"].(string)
		videoData, err := downloadMediaFromBase64(videoBase64)
		if err == nil {
			mimeType, _ := video["mimeType"].(string)
			if mimeType == "" {
				mimeType = "video/mp4"
			}
			caption, _ := video["caption"].(string)
			if content == "" {
				content = caption
			}
			filename := fmt.Sprintf("video_%d.mp4", time.Now().Unix())
			err = sendMessageWithAttachment(client, config.AccountID, conversation.ID, content, "incoming", videoData, filename, mimeType, replyID)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to send video, falling back to text")
				return sendTextMessage(client, config.AccountID, conversation.ID, content+" [Video]", "incoming", replyID)
			}
			return nil
		}
	} else if document != nil {
		// Send document
		docBase64, _ := document["base64"].(string)
		docData, err := downloadMediaFromBase64(docBase64)
		if err == nil {
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
			err = sendMessageWithAttachment(client, config.AccountID, conversation.ID, content, "incoming", docData, fileName, mimeType, replyID)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to send document, falling back to text")
				return sendTextMessage(client, config.AccountID, conversation.ID, content+" [Document]", "incoming", replyID)
			}
			return nil
		}
	} else if audio != nil {
		// Send audio
		audioBase64, _ := audio["base64"].(string)
		audioData, err := downloadMediaFromBase64(audioBase64)
		if err == nil {
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
			err = sendMessageWithAttachment(client, config.AccountID, conversation.ID, "", "incoming", audioData, filename, mimeType, replyID)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to send audio")
				// Don't fallback to text for audio - if audio fails, just return the error
				return err
			}
			return nil
		}
	} else if image != nil {
		// Send image
		imageBase64, _ := image["base64"].(string)
		imageData, err := downloadMediaFromBase64(imageBase64)
		if err == nil {
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
			err = sendMessageWithAttachment(client, config.AccountID, conversation.ID, content, "incoming", imageData, filename, mimeType, replyID)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to send image, falling back to text")
				return sendTextMessage(client, config.AccountID, conversation.ID, content+" [Image]", "incoming", replyID)
			}
			return nil
		}
	}
	
	// Send text message
	return sendTextMessage(client, config.AccountID, conversation.ID, content, "incoming", replyID)
}


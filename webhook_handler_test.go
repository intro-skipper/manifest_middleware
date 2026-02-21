package manifest_middleware

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// TestShortCommit tests the shortCommit helper function
func TestShortCommit(t *testing.T) {
	tests := []struct {
		name     string
		hash     string
		expected string
	}{
		{
			name:     "full 40-char hash",
			hash:     "d340f16ba1256ec563d7b08c0396645d555e65b8",
			expected: "d340f16",
		},
		{
			name:     "exactly 7 chars",
			hash:     "d340f16",
			expected: "d340f16",
		},
		{
			name:     "short hash",
			hash:     "abc",
			expected: "abc",
		},
		{
			name:     "empty hash",
			hash:     "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shortCommit(tt.hash)
			if result != tt.expected {
				t.Errorf("shortCommit(%q) = %q, want %q", tt.hash, result, tt.expected)
			}
		})
	}
}

// TestEmbedColor tests the embedColor helper function
func TestEmbedColor(t *testing.T) {
	successColor := 0x57F287 // Green
	failureColor := 0xED4245 // Red

	if embedColor(true) != successColor {
		t.Errorf("embedColor(true) = %d, want %d", embedColor(true), successColor)
	}

	if embedColor(false) != failureColor {
		t.Errorf("embedColor(false) = %d, want %d", embedColor(false), failureColor)
	}
}

// TestFormatDiscordStatus tests the formatDiscordStatus helper function
func TestFormatDiscordStatus(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		successMsg string
		wantPrefix string
	}{
		{
			name:       "success case",
			err:        nil,
			successMsg: "Operation completed",
			wantPrefix: "✅ Operation completed",
		},
		{
			name:       "error case",
			err:        context.DeadlineExceeded,
			successMsg: "Operation completed",
			wantPrefix: "❌ context deadline exceeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatDiscordStatus(tt.err, tt.successMsg)
			if result != tt.wantPrefix {
				t.Errorf("formatDiscordStatus() = %q, want %q", result, tt.wantPrefix)
			}
		})
	}
}

// TestVerifySignature tests the GitHub webhook signature verification
func TestVerifySignature(t *testing.T) {
	secret := "mysecret"
	payload := []byte(`{"test": "data"}`)

	// Create valid signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	validSignature := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	tests := []struct {
		name      string
		payload   []byte
		signature string
		secret    string
		expected  bool
	}{
		{
			name:      "valid signature",
			payload:   payload,
			signature: validSignature,
			secret:    secret,
			expected:  true,
		},
		{
			name:      "invalid signature",
			payload:   payload,
			signature: "sha256=invalid",
			secret:    secret,
			expected:  false,
		},
		{
			name:      "missing sha256 prefix",
			payload:   payload,
			signature: hex.EncodeToString(mac.Sum(nil)),
			secret:    secret,
			expected:  false,
		},
		{
			name:      "wrong secret",
			payload:   payload,
			signature: validSignature,
			secret:    "wrongsecret",
			expected:  false,
		},
		{
			name:      "empty signature",
			payload:   payload,
			signature: "",
			secret:    secret,
			expected:  false,
		},
		{
			name:      "malformed hex in signature",
			payload:   payload,
			signature: "sha256=ZZZZZZ",
			secret:    secret,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := verifySignature(tt.payload, tt.signature, tt.secret)
			if result != tt.expected {
				t.Errorf("verifySignature() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestCommitHashManager tests the CommitHashManager functionality
func TestCommitHashManager(t *testing.T) {
	manager := &CommitHashManager{}

	// Test initial state
	if manager.GetCommitHash() != "" {
		t.Error("Expected empty initial hash")
	}

	// Test SetCommitHash
	manager.SetCommitHash("abc123")
	if manager.GetCommitHash() != "abc123" {
		t.Errorf("GetCommitHash() = %q, want %q", manager.GetCommitHash(), "abc123")
	}

	// Test UpdateCommitHash (without persistence)
	ctx := context.Background()
	err := manager.UpdateCommitHash(ctx, "def456", "test/repo", false)
	if err != nil {
		t.Errorf("UpdateCommitHash() error = %v", err)
	}
	if manager.GetCommitHash() != "def456" {
		t.Errorf("GetCommitHash() = %q, want %q", manager.GetCommitHash(), "def456")
	}
}

// TestCommitHashManagerConcurrent tests concurrent access to CommitHashManager
func TestCommitHashManagerConcurrent(t *testing.T) {
	manager := &CommitHashManager{}

	// Run multiple goroutines to test thread safety
	done := make(chan bool)

	for i := 0; i < 100; i++ {
		go func(val string) {
			manager.SetCommitHash(val)
			_ = manager.GetCommitHash()
			done <- true
		}(string(rune(i)))
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}
}

// TestWebhookHandlerServeHTTP tests the ServeHTTP method of WebhookHandler
func TestWebhookHandlerServeHTTP(t *testing.T) {
	// Reset global manager
	globalHashManager = &CommitHashManager{}

	tests := []struct {
		name           string
		method         string
		path           string
		eventType      string
		signature      string
		secret         string
		body           interface{}
		expectedStatus int
	}{
		{
			name:           "non-webhook path passes through",
			method:         http.MethodGet,
			path:           "/other",
			eventType:      "",
			signature:      "",
			secret:         "",
			body:           nil,
			expectedStatus: http.StatusOK, // next handler returns 200
		},
		{
			name:           "GET request to webhook path rejected",
			method:         http.MethodGet,
			path:           "/hook",
			eventType:      "",
			signature:      "",
			secret:         "",
			body:           nil,
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "missing signature when secret configured",
			method:         http.MethodPost,
			path:           "/hook",
			eventType:      "push",
			signature:      "",
			secret:         "mysecret",
			body:           map[string]interface{}{},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "non-push event ignored",
			method:         http.MethodPost,
			path:           "/hook",
			eventType:      "ping",
			signature:      "",
			secret:         "",
			body:           map[string]interface{}{},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &WebhookHandler{
				GitHubSecret: tt.secret,
				WebhookPath:  "/hook",
				GitHubBranch: "main",
			}

			var bodyBytes []byte
			if tt.body != nil {
				bodyBytes, _ = json.Marshal(tt.body)
			}

			req := httptest.NewRequest(tt.method, tt.path, bytes.NewReader(bodyBytes))
			if tt.eventType != "" {
				req.Header.Set("X-GitHub-Event", tt.eventType)
			}
			if tt.signature != "" {
				req.Header.Set("X-Hub-Signature-256", tt.signature)
			}

			rec := httptest.NewRecorder()

			// Create a mock next handler
			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.WriteHeader(http.StatusOK)
				return nil
			})

			err := handler.ServeHTTP(rec, req, next)
			if err != nil {
				// Check if error response matches expected status
				if tt.expectedStatus >= 400 && tt.expectedStatus < 500 {
					// Expected error for 4xx responses
				} else {
					t.Errorf("ServeHTTP() error = %v", err)
				}
			}

			if rec.Code != tt.expectedStatus {
				t.Errorf("ServeHTTP() status = %d, want %d", rec.Code, tt.expectedStatus)
			}
		})
	}
}

// TestWebhookHandlerPushEvent tests handling of push events
func TestWebhookHandlerPushEvent(t *testing.T) {
	// Reset global manager
	globalHashManager = &CommitHashManager{}

	secret := "testsecret"
	handler := &WebhookHandler{
		GitHubSecret: secret,
		WebhookPath:  "/hook",
		GitHubBranch: "main",
	}

	pushEvent := map[string]interface{}{
		"ref":   "refs/heads/main",
		"after": "abc123def456abc123def456abc123def456abc1",
		"repository": map[string]interface{}{
			"full_name": "test/repo",
		},
	}

	bodyBytes, _ := json.Marshal(pushEvent)

	// Create valid signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(bodyBytes)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	req := httptest.NewRequest(http.MethodPost, "/hook", bytes.NewReader(bodyBytes))
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("X-Hub-Signature-256", signature)
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})

	err := handler.ServeHTTP(rec, req, next)
	if err != nil {
		t.Errorf("ServeHTTP() error = %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("ServeHTTP() status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Verify the hash was updated
	if globalHashManager.GetCommitHash() != "abc123def456abc123def456abc123def456abc1" {
		t.Errorf("Commit hash not updated correctly: %s", globalHashManager.GetCommitHash())
	}
}

// TestWebhookHandlerWrongBranch tests that pushes to wrong branch are ignored
func TestWebhookHandlerWrongBranch(t *testing.T) {
	// Reset global manager
	globalHashManager = &CommitHashManager{}
	globalHashManager.SetCommitHash("original")

	secret := "testsecret"
	handler := &WebhookHandler{
		GitHubSecret: secret,
		WebhookPath:  "/hook",
		GitHubBranch: "main",
	}

	pushEvent := map[string]interface{}{
		"ref":   "refs/heads/develop",
		"after": "newhash123456789012345678901234567890",
		"repository": map[string]interface{}{
			"full_name": "test/repo",
		},
	}

	bodyBytes, _ := json.Marshal(pushEvent)

	// Create valid signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(bodyBytes)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	req := httptest.NewRequest(http.MethodPost, "/hook", bytes.NewReader(bodyBytes))
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("X-Hub-Signature-256", signature)

	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})

	err := handler.ServeHTTP(rec, req, next)
	if err != nil {
		t.Errorf("ServeHTTP() error = %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("ServeHTTP() status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Verify the hash was NOT updated
	if globalHashManager.GetCommitHash() != "original" {
		t.Errorf("Commit hash should not have been updated")
	}
}

// TestWebhookHandlerAllowedRepos tests repository filtering
func TestWebhookHandlerAllowedRepos(t *testing.T) {
	// Reset global manager
	globalHashManager = &CommitHashManager{}
	globalHashManager.SetCommitHash("original")

	secret := "testsecret"
	handler := &WebhookHandler{
		GitHubSecret: secret,
		WebhookPath:  "/hook",
		GitHubBranch: "main",
		AllowedRepos: []string{"allowed/repo", "another/repo"},
	}

	pushEvent := map[string]interface{}{
		"ref":   "refs/heads/main",
		"after": "newhash123456789012345678901234567890",
		"repository": map[string]interface{}{
			"full_name": "notallowed/repo",
		},
	}

	bodyBytes, _ := json.Marshal(pushEvent)

	// Create valid signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(bodyBytes)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	req := httptest.NewRequest(http.MethodPost, "/hook", bytes.NewReader(bodyBytes))
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("X-Hub-Signature-256", signature)

	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})

	err := handler.ServeHTTP(rec, req, next)
	if err != nil {
		t.Errorf("ServeHTTP() error = %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("ServeHTTP() status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Verify the hash was NOT updated (repo not allowed)
	if globalHashManager.GetCommitHash() != "original" {
		t.Errorf("Commit hash should not have been updated for disallowed repo")
	}

	// Now test with allowed repo
	globalHashManager.SetCommitHash("original")
	pushEvent["repository"] = map[string]interface{}{"full_name": "allowed/repo"}
	bodyBytes, _ = json.Marshal(pushEvent)

	mac = hmac.New(sha256.New, []byte(secret))
	mac.Write(bodyBytes)
	signature = "sha256=" + hex.EncodeToString(mac.Sum(nil))

	req = httptest.NewRequest(http.MethodPost, "/hook", bytes.NewReader(bodyBytes))
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("X-Hub-Signature-256", signature)

	rec = httptest.NewRecorder()
	err = handler.ServeHTTP(rec, req, next)
	if err != nil {
		t.Errorf("ServeHTTP() error = %v", err)
	}

	// Verify the hash WAS updated (repo allowed)
	if globalHashManager.GetCommitHash() != "newhash123456789012345678901234567890" {
		t.Errorf("Commit hash should have been updated for allowed repo")
	}
}

// TestWebhookHandlerCustomPath tests custom webhook path
func TestWebhookHandlerCustomPath(t *testing.T) {
	handler := &WebhookHandler{
		WebhookPath: "/custom-webhook",
	}

	// Request to default path should pass through
	req := httptest.NewRequest(http.MethodPost, "/hook", nil)
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})

	handler.ServeHTTP(rec, req, next)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected pass-through for non-matching path")
	}

	// Request to custom path should be handled
	req = httptest.NewRequest(http.MethodGet, "/custom-webhook", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req, next)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected method not allowed for GET to webhook path")
	}
}

// TestDiscordPayload tests Discord payload structures
func TestDiscordPayload(t *testing.T) {
	payload := discordPayload{
		Content: "Test message",
		Embeds: []discordEmbed{
			{
				Title:       "Test Title",
				Description: "Test Description",
				Color:       0x57F287,
				Fields: []discordEmbedField{
					{
						Name:   "Field 1",
						Value:  "Value 1",
						Inline: true,
					},
				},
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Errorf("Failed to marshal discord payload: %v", err)
	}

	// Verify JSON structure
	if !strings.Contains(string(data), `"content"`) {
		t.Error("Expected content field in JSON")
	}
	if !strings.Contains(string(data), `"embeds"`) {
		t.Error("Expected embeds field in JSON")
	}
	if !strings.Contains(string(data), `"title"`) {
		t.Error("Expected title field in JSON")
	}
}

// TestWebhookHandlerProvision tests the Provision method
func TestWebhookHandlerProvision(t *testing.T) {
	handler := &WebhookHandler{}

	ctx := caddy.Context{}

	err := handler.Provision(ctx)
	if err != nil {
		t.Errorf("Provision() error = %v", err)
	}

	// Check defaults
	if handler.GitHubBranch != "main" {
		t.Errorf("Expected default branch 'main', got %q", handler.GitHubBranch)
	}
	if handler.WebhookPath != "/hook" {
		t.Errorf("Expected default path '/hook', got %q", handler.WebhookPath)
	}
}

// TestWebhookHandlerValidate tests the Validate method
func TestWebhookHandlerValidate(t *testing.T) {
	handler := &WebhookHandler{}

	err := handler.Validate()
	if err != nil {
		t.Errorf("Validate() error = %v", err)
	}
}

// TestWebhookHandlerCaddyModule tests the CaddyModule method
func TestWebhookHandlerCaddyModule(t *testing.T) {
	info := WebhookHandler{}.CaddyModule()

	if info.ID != "http.handlers.manifest_webhook" {
		t.Errorf("Expected module ID 'http.handlers.manifest_webhook', got %q", info.ID)
	}

	module := info.New()
	if _, ok := module.(*WebhookHandler); !ok {
		t.Error("Expected New() to return *WebhookHandler")
	}
}

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(WebhookHandler{})
	httpcaddyfile.RegisterHandlerDirective("manifest_webhook", parseWebhookCaddyfile)
}

// CommitHashManager manages the current commit hash and enables dynamic updates
type CommitHashManager struct {
	mu          sync.RWMutex
	currentHash string
	discordURL  string
	location    string
	caddyfile   string // Path to Caddyfile for persistence
}

// Global manager for the commit hash
var globalHashManager = &CommitHashManager{}

// GetCommitHash returns the current commit hash
func (m *CommitHashManager) GetCommitHash() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentHash
}

// SetCommitHash sets a new commit hash
func (m *CommitHashManager) SetCommitHash(hash string) {
	m.mu.Lock()
	m.currentHash = hash
	m.mu.Unlock()
}

// UpdateCommitHash updates the commit hash and optionally sends a Discord notification
// The in-memory hash is updated immediately - file persistence is optional for reference only
func (m *CommitHashManager) UpdateCommitHash(ctx context.Context, newHash, repoName string, persist bool) error {
	oldHash := m.GetCommitHash()
	m.SetCommitHash(newHash)

	log.Printf("Commit hash updated in memory: %s -> %s", shortCommit(oldHash), shortCommit(newHash))

	// Persist to Caddyfile if configured (optional - for reference only)
	if persist && m.caddyfile != "" {
		if err := updateCaddyfileHash(m.caddyfile, newHash); err != nil {
			log.Printf("Warning: failed to update Caddyfile (non-critical): %v", err)
		} else {
			log.Printf("Caddyfile updated for reference: %s", shortCommit(newHash))
		}
	}

	// Send Discord notification
	if m.discordURL != "" {
		m.notifyDiscord(ctx, repoName, oldHash, newHash, nil)
	}

	return nil
}

// WebhookHandler is a Caddy HTTP handler for GitHub webhooks
type WebhookHandler struct {
	// GitHub Secret for webhook verification
	GitHubSecret string `json:"github_secret,omitempty"`
	// Discord Webhook URL for notifications
	DiscordURL string `json:"discord_url,omitempty"`
	// Location information for Discord notifications
	Location string `json:"location,omitempty"`
	// Allowed repositories (optional, empty = all)
	AllowedRepos []string `json:"allowed_repos,omitempty"`
	// GitHub branch (default: main)
	GitHubBranch string `json:"github_branch,omitempty"`
	// Webhook path (default: /hook)
	WebhookPath string `json:"webhook_path,omitempty"`
	// Caddyfile path for persistence
	Caddyfile string `json:"caddyfile,omitempty"`
	// GitHub repository owner for startup check
	GitHubOwner string `json:"github_owner,omitempty"`
	// GitHub repository name for startup check
	GitHubRepo string `json:"github_repo,omitempty"`
	// GitHub token for API access
	GitHubToken string `json:"github_token,omitempty"`
}

// CaddyModule returns the Caddy module information
func (WebhookHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.manifest_webhook",
		New: func() caddy.Module { return new(WebhookHandler) },
	}
}

// Provision initializes the webhook handler
func (h *WebhookHandler) Provision(ctx caddy.Context) error {
	if h.GitHubBranch == "" {
		h.GitHubBranch = "main"
	}
	if h.WebhookPath == "" {
		h.WebhookPath = "/hook"
	}

	// Pass Discord URL, location, and caddyfile to the global manager
	globalHashManager.discordURL = h.DiscordURL
	globalHashManager.location = h.Location
	globalHashManager.caddyfile = h.Caddyfile

	// Run startup check in background
	if h.GitHubOwner != "" && h.GitHubRepo != "" {
		go h.checkCommitUpToDate(context.Background())
	}

	return nil
}

// Validate ensures the configuration is valid
func (h *WebhookHandler) Validate() error {
	return nil
}

// ServeHTTP implements the caddyhttp.MiddlewareHandler interface
func (h WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Only handle the configured webhook path
	if r.URL.Path != h.WebhookPath {
		return next.ServeHTTP(w, r)
	}

	// Only process POST requests
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return nil
	}

	// Read body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return fmt.Errorf("failed to read request body: %w", err)
	}
	defer r.Body.Close()

	// Verify webhook signature (if secret is configured)
	if h.GitHubSecret != "" {
		signature := r.Header.Get("X-Hub-Signature-256")
		if signature == "" {
			http.Error(w, "Missing signature", http.StatusUnauthorized)
			return fmt.Errorf("missing X-Hub-Signature-256 header")
		}

		if !verifySignature(body, signature, h.GitHubSecret) {
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return fmt.Errorf("invalid webhook signature")
		}
	}

	// Determine event type
	eventType := r.Header.Get("X-GitHub-Event")
	if eventType != "push" {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Event type ignored")
		return nil
	}

	// Parse push event
	var pushEvent struct {
		Ref   string `json:"ref"`
		After string `json:"after"`
		Repo  struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
	}

	if err := json.Unmarshal(body, &pushEvent); err != nil {
		http.Error(w, "Failed to parse payload", http.StatusBadRequest)
		return fmt.Errorf("failed to parse push event: %w", err)
	}

	// Check branch
	if !strings.EqualFold(pushEvent.Ref, "refs/heads/"+h.GitHubBranch) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Branch %s ignored", pushEvent.Ref)
		return nil
	}

	// Check repository (if AllowedRepos is configured)
	repoName := pushEvent.Repo.FullName
	if len(h.AllowedRepos) > 0 {
		allowed := false
		for _, allowedRepo := range h.AllowedRepos {
			if strings.EqualFold(repoName, allowedRepo) {
				allowed = true
				break
			}
		}
		if !allowed {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "Repository %s not allowed", repoName)
			return nil
		}
	}

	// Extract new commit hash
	newHash := pushEvent.After
	if newHash == "" {
		http.Error(w, "No commit hash found", http.StatusBadRequest)
		return fmt.Errorf("push event missing commit hash")
	}

	// Update commit hash and persist to Caddyfile
	err = globalHashManager.UpdateCommitHash(r.Context(), newHash, repoName, true)
	if err != nil {
		http.Error(w, "Failed to update commit hash", http.StatusInternalServerError)
		return fmt.Errorf("failed to update commit hash: %w", err)
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Commit hash updated to %s", shortCommit(newHash))
	return nil
}

// verifySignature verifies the GitHub webhook signature
func verifySignature(payload []byte, signature, secret string) bool {
	// Signature format: sha256=<hex>
	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}
	expectedMAC, err := hex.DecodeString(signature[7:])
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	actualMAC := mac.Sum(nil)

	return hmac.Equal(expectedMAC, actualMAC)
}

// UnmarshalCaddyfile parses the Caddyfile configuration
func (h *WebhookHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "github_secret":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.GitHubSecret = d.Val()
			case "discord_url":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.DiscordURL = d.Val()
			case "location":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.Location = d.Val()
			case "allowed_repos":
				for d.NextArg() {
					h.AllowedRepos = append(h.AllowedRepos, d.Val())
				}
			case "github_branch":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.GitHubBranch = d.Val()
			case "webhook_path":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.WebhookPath = d.Val()
			case "caddyfile":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.Caddyfile = d.Val()
			case "github_owner":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.GitHubOwner = d.Val()
			case "github_repo":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.GitHubRepo = d.Val()
			case "github_token":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.GitHubToken = d.Val()
			default:
				return d.Errf("unrecognized subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

// parseWebhookCaddyfile parses the Caddyfile directive
func parseWebhookCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := &WebhookHandler{}
	err := m.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// checkCommitUpToDate checks if the current commit hash matches the remote head
func (h *WebhookHandler) checkCommitUpToDate(ctx context.Context) {
	// Get current hash from Caddyfile if configured
	var localHash string
	if h.Caddyfile != "" {
		var err error
		localHash, err = commitFromCaddyfile(h.Caddyfile)
		if err != nil {
			log.Println("Startup check: could not read commit from Caddyfile:", err)
		}
	}

	// If no local hash, use the one from manifest_redirect (already set in globalHashManager)
	if localHash == "" {
		localHash = globalHashManager.GetCommitHash()
	}

	// Fetch remote head
	remoteHash, err := h.fetchRemoteHead(ctx)
	if err != nil {
		log.Println("Startup check: failed to fetch remote head:", err)
		h.reportDiscordStartup(ctx, localHash, "", false, err, nil)
		return
	}

	// Compare hashes
	if strings.EqualFold(remoteHash, localHash) {
		log.Printf("Startup check: commit %s is up to date", shortCommit(localHash))
		globalHashManager.SetCommitHash(localHash)
		h.reportDiscordStartup(ctx, localHash, remoteHash, false, nil, nil)
		return
	}

	// Update needed
	log.Printf("Startup check: updating %s -> %s", shortCommit(localHash), shortCommit(remoteHash))

	// Update in-memory hash
	globalHashManager.SetCommitHash(remoteHash)

	// Update Caddyfile if configured
	var updateErr error
	if h.Caddyfile != "" {
		updateErr = updateCaddyfileHash(h.Caddyfile, remoteHash)
		if updateErr != nil {
			log.Println("Startup check: failed to update Caddyfile:", updateErr)
		} else {
			log.Println("Startup check: Caddyfile updated")
		}
	}

	h.reportDiscordStartup(ctx, localHash, remoteHash, true, nil, updateErr)
}

// commitFromCaddyfile extracts the commit hash from a Caddyfile
func commitFromCaddyfile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read caddyfile: %w", err)
	}

	// Look for commit_hash directive inside manifest_redirect block
	// Pattern: commit_hash <hash>
	re := regexp.MustCompile(`commit_hash\s+([a-fA-F0-9]{40})`)
	if match := re.FindStringSubmatch(string(data)); len(match) == 2 {
		return strings.ToLower(match[1]), nil
	}

	return "", errors.New("no commit hash found in Caddyfile")
}

// updateCaddyfileHash updates the commit hash in a Caddyfile
// Only updates the commit_hash directive inside manifest_redirect block
func updateCaddyfileHash(path, newHash string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	content := string(data)

	// Pattern: commit_hash <hash> (inside manifest_redirect block)
	re := regexp.MustCompile(`(commit_hash\s+)[a-fA-F0-9]{40}`)
	updated := re.ReplaceAllString(content, fmt.Sprintf("$1%s", newHash))

	return os.WriteFile(path, []byte(updated), 0644)
}

// fetchRemoteHead fetches the latest commit hash from GitHub
func (h *WebhookHandler) fetchRemoteHead(ctx context.Context) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/%s", h.GitHubOwner, h.GitHubRepo, h.GitHubBranch)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "manifest-middleware")
	if h.GitHubToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", h.GitHubToken))
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("github API returned %s: %s", resp.Status, strings.TrimSpace(string(snippet)))
	}

	var payload struct {
		SHA string `json:"sha"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("decode github response: %w", err)
	}
	if payload.SHA == "" {
		return "", errors.New("github response missing commit sha")
	}

	return strings.ToLower(payload.SHA), nil
}

// notifyDiscord sends a notification to Discord
func (m *CommitHashManager) notifyDiscord(ctx context.Context, repoName, oldHash, newHash string, err error) {
	if m.discordURL == "" {
		return
	}

	success := err == nil

	embed := discordEmbed{
		Title:       fmt.Sprintf("Manifest Updated • %s", repoName),
		Description: fmt.Sprintf("Commit hash changed: `%s` → `%s`", shortCommit(oldHash), shortCommit(newHash)),
		Color:       embedColor(success),
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}

	if m.location != "" {
		embed.Fields = append(embed.Fields, discordEmbedField{
			Name:   "Location",
			Value:  m.location,
			Inline: true,
		})
	}

	embed.Fields = append(embed.Fields,
		discordEmbedField{
			Name:   "Old Hash",
			Value:  fmt.Sprintf("`%s`", shortCommit(oldHash)),
			Inline: true,
		},
		discordEmbedField{
			Name:   "New Hash",
			Value:  fmt.Sprintf("`%s`", shortCommit(newHash)),
			Inline: true,
		},
	)

	payload := discordPayload{Embeds: []discordEmbed{embed}}

	if sendErr := sendDiscordMessage(ctx, m.discordURL, payload); sendErr != nil {
		log.Println("Failed to notify Discord:", sendErr)
	}
}

// reportDiscordStartup sends a startup sync notification to Discord
func (h *WebhookHandler) reportDiscordStartup(ctx context.Context, localHash, remoteHash string, attempted bool, metaErr, updateErr error) {
	if h.DiscordURL == "" {
		return
	}

	success := metaErr == nil && updateErr == nil

	embed := discordEmbed{
		Title:     "Startup Sync",
		Color:     embedColor(success),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	if h.Location != "" {
		embed.Fields = append(embed.Fields, discordEmbedField{
			Name:   "Location",
			Value:  h.Location,
			Inline: true,
		})
	}

	switch {
	case metaErr != nil:
		embed.Description = fmt.Sprintf("Commit alignment failed: %v", metaErr)
	case !attempted:
		embed.Description = "Caddyfile already matches GitHub head."
	case updateErr != nil:
		embed.Description = "Failed updating Caddyfile to match GitHub head."
	default:
		embed.Description = "Caddyfile synchronized with GitHub head."
	}

	if localHash != "" {
		embed.Fields = append(embed.Fields, discordEmbedField{
			Name:   "Caddyfile Hash",
			Value:  fmt.Sprintf("`%s`", shortCommit(localHash)),
			Inline: true,
		})
	}
	if remoteHash != "" {
		embed.Fields = append(embed.Fields, discordEmbedField{
			Name:   "GitHub Head",
			Value:  fmt.Sprintf("`%s`", shortCommit(remoteHash)),
			Inline: true,
		})
	}

	if attempted {
		embed.Fields = append(embed.Fields, discordEmbedField{
			Name:   "Update",
			Value:  formatDiscordStatus(updateErr, "Caddyfile synchronized."),
			Inline: false,
		})
	}

	payload := discordPayload{Embeds: []discordEmbed{embed}}

	if err := sendDiscordMessage(ctx, h.DiscordURL, payload); err != nil {
		log.Println("Failed to notify Discord:", err)
	}
}

// Helper functions

func shortCommit(hash string) string {
	if len(hash) >= 7 {
		return hash[:7]
	}
	return hash
}

func embedColor(success bool) int {
	if success {
		return 0x57F287 // Green
	}
	return 0xED4245 // Red
}

func formatDiscordStatus(err error, successMsg string) string {
	if err != nil {
		return fmt.Sprintf("❌ %v", err)
	}
	return fmt.Sprintf("✅ %s", successMsg)
}

type discordPayload struct {
	Content string         `json:"content,omitempty"`
	Embeds  []discordEmbed `json:"embeds,omitempty"`
}

type discordEmbed struct {
	Title       string              `json:"title,omitempty"`
	Description string              `json:"description,omitempty"`
	Color       int                 `json:"color,omitempty"`
	Timestamp   string              `json:"timestamp,omitempty"`
	Fields      []discordEmbedField `json:"fields,omitempty"`
}

type discordEmbedField struct {
	Name   string `json:"name,omitempty"`
	Value  string `json:"value,omitempty"`
	Inline bool   `json:"inline,omitempty"`
}

func sendDiscordMessage(ctx context.Context, webhookURL string, payload discordPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal discord payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create discord request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("send discord request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("discord webhook returned %s", resp.Status)
	}

	return nil
}

// Interface implementations
var (
	_ caddy.Provisioner           = (*WebhookHandler)(nil)
	_ caddy.Validator             = (*WebhookHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*WebhookHandler)(nil)
	_ caddyfile.Unmarshaler       = (*WebhookHandler)(nil)
)

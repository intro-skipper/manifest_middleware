package manifest_middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// TestManifestRedirectProvision tests the Provision method
func TestManifestRedirectProvision(t *testing.T) {
	// Reset global manager
	globalHashManager = &CommitHashManager{}

	m := &ManifestRedirect{}

	err := m.Provision(caddy.Context{})
	if err != nil {
		t.Errorf("Provision() error = %v", err)
	}

	// Check defaults
	if m.BaseURL != "https://cdn.jsdelivr.net/gh/intro-skipper/manifest" {
		t.Errorf("Expected default BaseURL, got %q", m.BaseURL)
	}
	if m.DefaultVersion != "10.11" {
		t.Errorf("Expected default version '10.11', got %q", m.DefaultVersion)
	}
	if m.GitHubURL != "https://github.com/intro-skipper/" {
		t.Errorf("Expected default GitHubURL, got %q", m.GitHubURL)
	}
	if m.ManifestPath != "/manifest.json" {
		t.Errorf("Expected default ManifestPath '/manifest.json', got %q", m.ManifestPath)
	}
	if m.CommitHash != "d340f16ba1256ec563d7b08c0396645d555e65b8" {
		t.Errorf("Expected default CommitHash, got %q", m.CommitHash)
	}

	// Check default allowed versions
	if len(m.AllowedVersions) != 4 {
		t.Errorf("Expected 4 default allowed versions, got %d", len(m.AllowedVersions))
	}
	expectedVersions := []string{"10.8", "10.9", "10.10", "10.11"}
	for i, v := range expectedVersions {
		if m.AllowedVersions[i] != v {
			t.Errorf("Expected allowed version %q at index %d, got %q", v, i, m.AllowedVersions[i])
		}
	}

	// Verify regexes are compiled
	if m.versionRegex == nil {
		t.Error("versionRegex should be compiled")
	}
	if m.fallbackRegex == nil {
		t.Error("fallbackRegex should be compiled")
	}
	if m.jellyfinRegex == nil {
		t.Error("jellyfinRegex should be compiled")
	}
}

// TestManifestRedirectProvisionCustomValues tests Provision with custom values
func TestManifestRedirectProvisionCustomValues(t *testing.T) {
	// Reset global manager
	globalHashManager = &CommitHashManager{}

	m := &ManifestRedirect{
		BaseURL:        "https://custom.cdn.example.com/repo",
		DefaultVersion: "10.9",
		GitHubURL:      "https://custom.github.com/",
		ManifestPath:   "/custom-manifest.json",
		CommitHash:     "customhash123456789012345678901234567",
	}

	err := m.Provision(caddy.Context{})
	if err != nil {
		t.Errorf("Provision() error = %v", err)
	}

	// Check custom values are preserved
	if m.BaseURL != "https://custom.cdn.example.com/repo" {
		t.Errorf("Expected custom BaseURL, got %q", m.BaseURL)
	}
	if m.DefaultVersion != "10.9" {
		t.Errorf("Expected custom version '10.9', got %q", m.DefaultVersion)
	}
	if m.GitHubURL != "https://custom.github.com/" {
		t.Errorf("Expected custom GitHubURL, got %q", m.GitHubURL)
	}
	if m.ManifestPath != "/custom-manifest.json" {
		t.Errorf("Expected custom ManifestPath, got %q", m.ManifestPath)
	}
	if m.CommitHash != "customhash123456789012345678901234567" {
		t.Errorf("Expected custom CommitHash, got %q", m.CommitHash)
	}

	// Verify global hash manager was updated
	if globalHashManager.GetCommitHash() != "customhash123456789012345678901234567" {
		t.Errorf("Global hash manager should have custom hash")
	}
}

// TestManifestRedirectCustomAllowedVersions tests custom allowed versions
func TestManifestRedirectCustomAllowedVersions(t *testing.T) {
	// Reset global manager
	globalHashManager = &CommitHashManager{}

	m := &ManifestRedirect{
		AllowedVersions: []string{"10.9", "10.10", "10.11"},
	}

	err := m.Provision(caddy.Context{})
	if err != nil {
		t.Errorf("Provision() error = %v", err)
	}

	// Check custom allowed versions are preserved
	if len(m.AllowedVersions) != 3 {
		t.Errorf("Expected 3 allowed versions, got %d", len(m.AllowedVersions))
	}

	// Test that only configured versions match
	tests := []struct {
		userAgent   string
		shouldMatch bool
		version     string
	}{
		{"Jellyfin-Server/10.8.0", false, ""},      // Not in allowed list
		{"Jellyfin-Server/10.9.0", true, "10.9"},   // In allowed list
		{"Jellyfin-Server/10.10.0", true, "10.10"}, // In allowed list
		{"Jellyfin-Server/10.11.0", true, "10.11"}, // In allowed list
	}

	for _, tt := range tests {
		matches := m.versionRegex.FindStringSubmatch(tt.userAgent)
		if tt.shouldMatch {
			if matches == nil {
				t.Errorf("Expected %q to match version regex", tt.userAgent)
			} else if matches[1] != tt.version {
				t.Errorf("Expected version %q, got %q", tt.version, matches[1])
			}
		} else {
			if matches != nil {
				t.Errorf("Expected %q to NOT match version regex, but got %v", tt.userAgent, matches)
			}
		}
	}
}

// TestManifestRedirectValidate tests the Validate method
func TestManifestRedirectValidate(t *testing.T) {
	m := &ManifestRedirect{}

	err := m.Validate()
	if err != nil {
		t.Errorf("Validate() error = %v", err)
	}
}

// TestManifestRedirectCaddyModule tests the CaddyModule method
func TestManifestRedirectCaddyModule(t *testing.T) {
	info := ManifestRedirect{}.CaddyModule()

	if info.ID != "http.handlers.manifest_redirect" {
		t.Errorf("Expected module ID 'http.handlers.manifest_redirect', got %q", info.ID)
	}

	module := info.New()
	if _, ok := module.(*ManifestRedirect); !ok {
		t.Error("Expected New() to return *ManifestRedirect")
	}
}

// TestManifestRedirectServeHTTP tests the ServeHTTP method
func TestManifestRedirectServeHTTP(t *testing.T) {
	// Reset global manager
	globalHashManager = &CommitHashManager{}
	globalHashManager.SetCommitHash("testcommit000000000000000000000000000")

	m := &ManifestRedirect{
		BaseURL:        "https://cdn.example.com/repo",
		DefaultVersion: "10.11",
		GitHubURL:      "https://github.com/example/",
		ManifestPath:   "/manifest.json",
		CommitHash:     "testcommit000000000000000000000000000",
	}

	// Compile regexes
	m.Provision(caddy.Context{})

	tests := []struct {
		name           string
		path           string
		userAgent      string
		expectedURL    string
		expectedStatus int
	}{
		{
			name:           "non-manifest path passes through",
			path:           "/other",
			userAgent:      "Jellyfin-Server/10.9.0",
			expectedURL:    "",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Jellyfin 10.8.x",
			path:           "/manifest.json",
			userAgent:      "Jellyfin-Server/10.8.0",
			expectedURL:    "https://cdn.example.com/repo@testcommit000000000000000000000000000/10.8/manifest.json",
			expectedStatus: http.StatusFound,
		},
		{
			name:           "Jellyfin 10.9.x",
			path:           "/manifest.json",
			userAgent:      "Jellyfin-Server/10.9.5",
			expectedURL:    "https://cdn.example.com/repo@testcommit000000000000000000000000000/10.9/manifest.json",
			expectedStatus: http.StatusFound,
		},
		{
			name:           "Jellyfin 10.10.x",
			path:           "/manifest.json",
			userAgent:      "Jellyfin-Server/10.10.2",
			expectedURL:    "https://cdn.example.com/repo@testcommit000000000000000000000000000/10.10/manifest.json",
			expectedStatus: http.StatusFound,
		},
		{
			name:           "Jellyfin 10.11.x",
			path:           "/manifest.json",
			userAgent:      "Jellyfin-Server/10.11.0",
			expectedURL:    "https://cdn.example.com/repo@testcommit000000000000000000000000000/10.11/manifest.json",
			expectedStatus: http.StatusFound,
		},
		{
			name:           "Jellyfin 10.12.x (fallback to default)",
			path:           "/manifest.json",
			userAgent:      "Jellyfin-Server/10.12.0",
			expectedURL:    "https://cdn.example.com/repo@testcommit000000000000000000000000000/10.11/manifest.json",
			expectedStatus: http.StatusFound,
		},
		{
			name:           "Jellyfin 10.7.x (fallback to default)",
			path:           "/manifest.json",
			userAgent:      "Jellyfin-Server/10.7.0",
			expectedURL:    "https://cdn.example.com/repo@testcommit000000000000000000000000000/10.11/manifest.json",
			expectedStatus: http.StatusFound,
		},
		{
			name:           "Non-Jellyfin client redirects to GitHub",
			path:           "/manifest.json",
			userAgent:      "Mozilla/5.0",
			expectedURL:    "https://github.com/example/",
			expectedStatus: http.StatusPermanentRedirect,
		},
		{
			name:           "Empty User-Agent redirects to GitHub",
			path:           "/manifest.json",
			userAgent:      "",
			expectedURL:    "https://github.com/example/",
			expectedStatus: http.StatusPermanentRedirect,
		},
		{
			name:           "Jellyfin 11.x redirects to GitHub",
			path:           "/manifest.json",
			userAgent:      "Jellyfin-Server/11.0.0",
			expectedURL:    "https://github.com/example/",
			expectedStatus: http.StatusPermanentRedirect,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			if tt.userAgent != "" {
				req.Header.Set("User-Agent", tt.userAgent)
			}

			rec := httptest.NewRecorder()
			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.WriteHeader(http.StatusOK)
				return nil
			})

			err := m.ServeHTTP(rec, req, next)
			if err != nil {
				t.Errorf("ServeHTTP() error = %v", err)
			}

			if rec.Code != tt.expectedStatus {
				t.Errorf("ServeHTTP() status = %d, want %d", rec.Code, tt.expectedStatus)
			}

			if tt.expectedURL != "" {
				location := rec.Header().Get("Location")
				if location != tt.expectedURL {
					t.Errorf("ServeHTTP() redirect = %q, want %q", location, tt.expectedURL)
				}
			}
		})
	}
}

// TestManifestRedirectDynamicCommitHash tests that the commit hash can be updated dynamically
func TestManifestRedirectDynamicCommitHash(t *testing.T) {
	// Reset global manager
	globalHashManager = &CommitHashManager{}
	globalHashManager.SetCommitHash("original00000000000000000000000000000")

	m := &ManifestRedirect{
		BaseURL:        "https://cdn.example.com/repo",
		DefaultVersion: "10.11",
		GitHubURL:      "https://github.com/example/",
		ManifestPath:   "/manifest.json",
		CommitHash:     "original00000000000000000000000000000",
	}
	m.Provision(caddy.Context{})

	// First request with original hash
	req := httptest.NewRequest(http.MethodGet, "/manifest.json", nil)
	req.Header.Set("User-Agent", "Jellyfin-Server/10.9.0")
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})

	m.ServeHTTP(rec, req, next)

	location := rec.Header().Get("Location")
	if location != "https://cdn.example.com/repo@original00000000000000000000000000000/10.9/manifest.json" {
		t.Errorf("Expected original hash in URL, got %q", location)
	}

	// Update the global hash
	globalHashManager.SetCommitHash("updated00000000000000000000000000000")

	// Second request should use updated hash
	req = httptest.NewRequest(http.MethodGet, "/manifest.json", nil)
	req.Header.Set("User-Agent", "Jellyfin-Server/10.9.0")
	rec = httptest.NewRecorder()

	m.ServeHTTP(rec, req, next)

	location = rec.Header().Get("Location")
	if location != "https://cdn.example.com/repo@updated00000000000000000000000000000/10.9/manifest.json" {
		t.Errorf("Expected updated hash in URL, got %q", location)
	}
}

// TestManifestRedirectCustomPath tests custom manifest path
func TestManifestRedirectCustomPath(t *testing.T) {
	// Reset global manager
	globalHashManager = &CommitHashManager{}

	m := &ManifestRedirect{
		BaseURL:        "https://cdn.example.com/repo",
		DefaultVersion: "10.11",
		GitHubURL:      "https://github.com/example/",
		ManifestPath:   "/custom-manifest.json",
		CommitHash:     "testcommit000000000000000000000000000",
	}
	m.Provision(caddy.Context{})

	// Request to default path should pass through
	req := httptest.NewRequest(http.MethodGet, "/manifest.json", nil)
	req.Header.Set("User-Agent", "Jellyfin-Server/10.9.0")
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})

	m.ServeHTTP(rec, req, next)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected pass-through for default path when custom path configured")
	}

	// Request to custom path should be handled
	req = httptest.NewRequest(http.MethodGet, "/custom-manifest.json", nil)
	req.Header.Set("User-Agent", "Jellyfin-Server/10.9.0")
	rec = httptest.NewRecorder()

	m.ServeHTTP(rec, req, next)

	if rec.Code != http.StatusFound {
		t.Errorf("Expected redirect for custom manifest path")
	}
}

// TestVersionRegex tests the version regex pattern
func TestVersionRegex(t *testing.T) {
	m := &ManifestRedirect{}
	m.Provision(caddy.Context{})

	tests := []struct {
		userAgent   string
		shouldMatch bool
		version     string
	}{
		{"Jellyfin-Server/10.8.0", true, "10.8"},
		{"Jellyfin-Server/10.8.13", true, "10.8"},
		{"Jellyfin-Server/10.9.0", true, "10.9"},
		{"Jellyfin-Server/10.9.5", true, "10.9"},
		{"Jellyfin-Server/10.10.0", true, "10.10"},
		{"Jellyfin-Server/10.10.1", true, "10.10"},
		{"Jellyfin-Server/10.11.0", true, "10.11"},
		{"Jellyfin-Server/10.11.5", true, "10.11"},
		{"Jellyfin-Server/10.7.0", false, ""},
		{"Jellyfin-Server/10.12.0", false, ""},
		{"Jellyfin-Server/11.0.0", false, ""},
		{"Mozilla/5.0", false, ""},
		{"", false, ""},
	}

	for _, tt := range tests {
		matches := m.versionRegex.FindStringSubmatch(tt.userAgent)
		if tt.shouldMatch {
			if matches == nil {
				t.Errorf("Expected %q to match version regex", tt.userAgent)
			} else if matches[1] != tt.version {
				t.Errorf("Expected version %q, got %q", tt.version, matches[1])
			}
		} else {
			if matches != nil {
				t.Errorf("Expected %q to NOT match version regex, but got %v", tt.userAgent, matches)
			}
		}
	}
}

// TestFallbackRegex tests the fallback regex pattern
func TestFallbackRegex(t *testing.T) {
	m := &ManifestRedirect{}
	m.Provision(caddy.Context{})

	tests := []struct {
		userAgent   string
		shouldMatch bool
	}{
		{"Jellyfin-Server/10.7.0", true},
		{"Jellyfin-Server/10.8.0", true},
		{"Jellyfin-Server/10.9.0", true},
		{"Jellyfin-Server/10.10.0", true},
		{"Jellyfin-Server/10.11.0", true},
		{"Jellyfin-Server/10.12.0", true},
		{"Jellyfin-Server/10.13.5", true},
		{"Jellyfin-Server/11.0.0", false},
		{"Jellyfin-Server/9.0.0", false},
		{"Mozilla/5.0", false},
		{"", false},
	}

	for _, tt := range tests {
		matches := m.fallbackRegex.MatchString(tt.userAgent)
		if matches != tt.shouldMatch {
			t.Errorf("fallbackRegex.MatchString(%q) = %v, want %v", tt.userAgent, matches, tt.shouldMatch)
		}
	}
}

// TestJellyfinRegex tests the jellyfin regex pattern
func TestJellyfinRegex(t *testing.T) {
	m := &ManifestRedirect{}
	m.Provision(caddy.Context{})

	tests := []struct {
		userAgent   string
		shouldMatch bool
	}{
		{"Jellyfin-Server/10.8.0", true},
		{"Jellyfin-Server/10.9.0", true},
		{"Jellyfin-Server/10.10.0", true},
		{"Jellyfin-Server/10.11.0", true},
		{"Jellyfin-Server/11.0.0", true},
		{"Jellyfin-Server/9.0.0", true},
		{"Jellyfin-Server/anything", true},
		{"Mozilla/5.0", false},
		{"", false},
		{"Other-Client/1.0", false},
	}

	for _, tt := range tests {
		matches := m.jellyfinRegex.MatchString(tt.userAgent)
		if matches != tt.shouldMatch {
			t.Errorf("jellyfinRegex.MatchString(%q) = %v, want %v", tt.userAgent, matches, tt.shouldMatch)
		}
	}
}

// TestManifestRedirectInterface tests interface implementations
func TestManifestRedirectInterface(t *testing.T) {
	// This is a compile-time check
	var _ caddy.Provisioner = (*ManifestRedirect)(nil)
	var _ caddy.Validator = (*ManifestRedirect)(nil)
	var _ caddyhttp.MiddlewareHandler = (*ManifestRedirect)(nil)
}

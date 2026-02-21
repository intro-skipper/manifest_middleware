package manifest_middleware

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(ManifestRedirect{})
	httpcaddyfile.RegisterHandlerDirective("manifest_redirect", parseCaddyfile)
}

// ManifestRedirect is a Caddy HTTP middleware that redirects based on User-Agent
// to different manifest versions.
type ManifestRedirect struct {
	// BaseURL is the base URL for manifest redirection
	BaseURL string `json:"base_url,omitempty"`
	// DefaultVersion is the fallback version for unknown Jellyfin versions
	DefaultVersion string `json:"default_version,omitempty"`
	// GitHubURL is the redirect URL for non-Jellyfin clients
	GitHubURL string `json:"github_url,omitempty"`
	// ManifestPath is the path to the manifest file
	ManifestPath string `json:"manifest_path,omitempty"`
	// CommitHash is the initial Git commit hash for the CDN URL (can be updated via webhook)
	CommitHash string `json:"commit_hash,omitempty"`

	// Compiled regex patterns
	versionRegex  *regexp.Regexp
	fallbackRegex *regexp.Regexp
	jellyfinRegex *regexp.Regexp
}

// CaddyModule returns the Caddy module information
func (ManifestRedirect) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.manifest_redirect",
		New: func() caddy.Module { return new(ManifestRedirect) },
	}
}

// Provision initializes the middleware
func (m *ManifestRedirect) Provision(ctx caddy.Context) error {
	// Set default values
	if m.BaseURL == "" {
		m.BaseURL = "https://cdn.jsdelivr.net/gh/intro-skipper/manifest"
	}
	if m.DefaultVersion == "" {
		m.DefaultVersion = "10.11"
	}
	if m.GitHubURL == "" {
		m.GitHubURL = "https://github.com/intro-skipper/"
	}
	if m.ManifestPath == "" {
		m.ManifestPath = "/manifest.json"
	}
	if m.CommitHash == "" {
		m.CommitHash = "d340f16ba1256ec563d7b08c0396645d555e65b8"
	}

	// Set initial commit hash in global manager
	globalHashManager.SetCommitHash(m.CommitHash)

	// Compile regex patterns
	var err error
	m.versionRegex, err = regexp.Compile(`^Jellyfin-Server/(10\.(?:8|9|10|11))\..*$`)
	if err != nil {
		return fmt.Errorf("failed to compile version regex: %w", err)
	}

	m.fallbackRegex, err = regexp.Compile(`^Jellyfin-Server/10\..*$`)
	if err != nil {
		return fmt.Errorf("failed to compile fallback regex: %w", err)
	}

	m.jellyfinRegex, err = regexp.Compile(`^Jellyfin-Server/.*$`)
	if err != nil {
		return fmt.Errorf("failed to compile jellyfin regex: %w", err)
	}

	return nil
}

// Validate ensures the configuration is valid
func (m *ManifestRedirect) Validate() error {
	return nil
}

// ServeHTTP implements the caddyhttp.MiddlewareHandler interface
func (m *ManifestRedirect) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Only handle /manifest.json requests
	if r.URL.Path != m.ManifestPath {
		return next.ServeHTTP(w, r)
	}

	userAgent := r.Header.Get("User-Agent")

	// Get current commit hash from global manager (dynamically updatable)
	commitHash := globalHashManager.GetCommitHash()
	if commitHash == "" {
		commitHash = m.CommitHash // Fallback to configured value
	}

	// 1. Exact version detection (10.8, 10.9, 10.10, 10.11)
	if matches := m.versionRegex.FindStringSubmatch(userAgent); matches != nil {
		version := matches[1]
		targetURL := fmt.Sprintf("%s@%s/%s/manifest.json", m.BaseURL, commitHash, version)
		http.Redirect(w, r, targetURL, http.StatusFound)
		return nil
	}

	// 2. Fallback for other 10.x versions
	if m.fallbackRegex.MatchString(userAgent) {
		targetURL := fmt.Sprintf("%s@%s/%s/manifest.json", m.BaseURL, commitHash, m.DefaultVersion)
		http.Redirect(w, r, targetURL, http.StatusFound)
		return nil
	}

	// 3. Redirect non-Jellyfin clients to GitHub
	if !m.jellyfinRegex.MatchString(userAgent) {
		http.Redirect(w, r, m.GitHubURL, http.StatusPermanentRedirect)
		return nil
	}

	// 4. For other Jellyfin versions (not 10.x), also redirect to GitHub
	http.Redirect(w, r, m.GitHubURL, http.StatusPermanentRedirect)
	return nil
}

// UnmarshalCaddyfile parses the Caddyfile configuration
func (m *ManifestRedirect) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "base_url":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.BaseURL = d.Val()
			case "default_version":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.DefaultVersion = d.Val()
			case "github_url":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.GitHubURL = d.Val()
			case "manifest_path":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.ManifestPath = d.Val()
			case "commit_hash":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.CommitHash = d.Val()
			default:
				return d.Errf("unrecognized subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

// parseCaddyfile parses the Caddyfile directive
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := &ManifestRedirect{}
	err := m.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// Interface implementations
var (
	_ caddy.Provisioner           = (*ManifestRedirect)(nil)
	_ caddy.Validator             = (*ManifestRedirect)(nil)
	_ caddyhttp.MiddlewareHandler = (*ManifestRedirect)(nil)
	_ caddyfile.Unmarshaler       = (*ManifestRedirect)(nil)
)

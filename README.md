# Manifest Redirect Middleware for Caddy v2

A Caddy v2 HTTP handler middleware that redirects based on the User-Agent header to different manifest versions. Specifically designed for Jellyfin Server manifest redirections with dynamic commit hash updates via GitHub webhooks.

## Features

### Manifest Redirect Middleware

The middleware analyzes the `User-Agent` header from requests to `/manifest.json` and redirects based on the Jellyfin version:

1. **Exact version detection** (10.8, 10.9, 10.10, 10.11):
   - User-Agent: `Jellyfin-Server/10.8.x` → `{base_url}@{commit_hash}/10.8/manifest.json`
   - User-Agent: `Jellyfin-Server/10.9.x` → `{base_url}@{commit_hash}/10.9/manifest.json`
   - etc.

2. **Fallback for other 10.x versions**:
   - User-Agent: `Jellyfin-Server/10.x` (not 10.8-10.11) → `{base_url}@{commit_hash}/{default_version}/manifest.json`

3. **Non-Jellyfin clients**:
   - All other User-Agents → GitHub URL

### Webhook Handler

The webhook handler enables dynamic commit hash updates:

- Receives GitHub push events
- Verifies webhook signature (HMAC-SHA256)
- Updates commit hash at runtime (no Caddy reload required)
- **Startup check**: Compares local commit hash with GitHub remote head
- **Caddyfile persistence**: Writes new commit hash back to Caddyfile
- Sends Discord notifications on updates

## Installation

### Build with xcaddy

```bash
xcaddy build --with github.com/intro-skipper/manifest_middleware
```

### Integrate as Caddy plugin

Add the module to your `go.mod` and rebuild Caddy:

```go
package main

import (
    caddycmd "github.com/caddyserver/caddy/v2/cmd"
    _ "github.com/caddyserver/caddy/v2/modules/standard"
    _ "github.com/intro-skipper/manifest_middleware"
)

func main() {
    caddycmd.Main()
}
```

## Caddyfile Configuration

### Basic Usage

```caddyfile
example.org {
    manifest_redirect
}
```

### With Webhook Support and Startup Check

```caddyfile
{
    order manifest_redirect before redir
    order manifest_webhook before redir
}

example.org {
    manifest_webhook {
        github_secret {$GITHUB_SECRET}
        discord_url {$DISCORD_WEBHOOK_URL}
        location "Production"
        allowed_repos intro-skipper/manifest
        github_branch main
        webhook_path /hook
        caddyfile /etc/caddy/Caddyfile
        github_owner intro-skipper
        github_repo manifest
        github_token {$GITHUB_TOKEN}
    }

    manifest_redirect {
        base_url https://cdn.jsdelivr.net/gh/intro-skipper/manifest
        default_version 10.11
        github_url https://github.com/intro-skipper/
        manifest_path /manifest.json
        commit_hash d340f16ba1256ec563d7b08c0396645d555e65b8
    }
}
```

## Configuration Options

### manifest_redirect

| Option           | Description                                          | Default                                                        |
|------------------|------------------------------------------------------|----------------------------------------------------------------|
| `base_url`       | Base URL for manifest redirection                    | `https://cdn.jsdelivr.net/gh/intro-skipper/manifest`           |
| `default_version`| Fallback version for unknown Jellyfin 10.x versions  | `10.11`                                                        |
| `github_url`     | Redirect URL for non-Jellyfin clients                | `https://github.com/intro-skipper/`                            |
| `manifest_path`  | Path to the manifest file                            | `/manifest.json`                                               |
| `commit_hash`    | Initial Git commit hash (can be updated via webhook) | `d340f16ba1256ec563d7b08c0396645d555e65b8`                     |

### manifest_webhook

| Option           | Description                                    | Default                   |
|------------------|------------------------------------------------|---------------------------|
| `github_secret`  | GitHub webhook secret for signature verification | (empty = no verification) |
| `discord_url`    | Discord webhook URL for notifications          | (empty = no notifications)|
| `location`       | Location information for Discord notifications | (empty)                   |
| `allowed_repos`  | Allowed repositories (space-separated)         | (empty = all)             |
| `github_branch`  | GitHub branch for push events                  | `main`                    |
| `webhook_path`   | Path for the webhook endpoint                  | `/hook`                   |
| `caddyfile`      | Path to Caddyfile for persistence              | (empty = no persistence)  |
| `github_owner`   | GitHub repository owner for startup check      | (empty = no startup check)|
| `github_repo`    | GitHub repository name for startup check       | (empty = no startup check)|
| `github_token`   | GitHub token for API access                    | (empty = unauthenticated) |

## How It Works

### Startup Check

When `github_owner` and `github_repo` are configured, the middleware performs a startup check:

1. Reads the current commit hash from the Caddyfile (or uses the configured value)
2. Fetches the latest commit hash from GitHub API
3. If they differ, updates the in-memory hash and writes it back to the Caddyfile
4. Sends a Discord notification about the sync status

### Webhook Updates

When a GitHub push event is received:

1. Verifies the webhook signature (if `github_secret` is configured)
2. Checks if the repository and branch match
3. Updates the in-memory commit hash
4. Writes the new hash back to the Caddyfile (if `caddyfile` is configured)
5. Sends a Discord notification

### Caddyfile Persistence

The middleware can optionally write the new commit hash back to the Caddyfile for reference. It updates the `commit_hash` directive inside the `manifest_redirect` block:

```caddyfile
manifest_redirect {
    commit_hash abc1234567890abcdef1234567890abcdef1234
}
```

**Note**: The in-memory hash is updated immediately when a webhook is received - the file persistence is optional and only for reference. The actual redirections use the in-memory value, so no Caddy reload is required.

## JSON Configuration

```json
{
    "handle": [
        {
            "handler": "manifest_webhook",
            "github_secret": "your-secret",
            "discord_url": "https://discord.com/api/webhooks/...",
            "location": "Production",
            "allowed_repos": ["intro-skipper/manifest"],
            "github_branch": "main",
            "webhook_path": "/hook",
            "caddyfile": "/etc/caddy/Caddyfile",
            "github_owner": "intro-skipper",
            "github_repo": "manifest",
            "github_token": "ghp_..."
        },
        {
            "handler": "manifest_redirect",
            "base_url": "https://cdn.jsdelivr.net/gh/intro-skipper/manifest",
            "default_version": "10.11",
            "github_url": "https://github.com/intro-skipper/",
            "manifest_path": "/manifest.json",
            "commit_hash": "d340f16ba1256ec563d7b08c0396645d555e65b8"
        }
    ]
}
```

## Setting up GitHub Webhook

1. Go to your repository on GitHub
2. Navigate to Settings → Webhooks → Add webhook
3. Configure:
   - **Payload URL**: `https://your-domain.com/hook`
   - **Content type**: `application/json`
   - **Secret**: Your configured `github_secret`
   - **Events**: Select "Just the push event"
4. Click "Add webhook"

## Example: Complete Caddyfile

```caddyfile
{
    order manifest_redirect before redir
    order manifest_webhook before redir
}

*.intro-skipper.org intro-skipper.org {
    tls {
        dns cloudflare {env.CLOUDFLARE_API_TOKEN}
    }

    log {
        output file /var/log/caddy/access.log
        format filter {
            wrap json
            fields {
                request>remote_addr delete
                request>remote_ip delete
                request>client_ip delete
            }
        }
    }

    # Discord redirect
    @discord host discord.intro-skipper.org
    redir @discord https://discord.gg/AYZ7RJ3BuA 308

    # GitHub webhook handler
    manifest_webhook {
        github_secret {$GITHUB_SECRET}
        discord_url {$DISCORD_WEBHOOK_URL}
        location "Production"
        allowed_repos intro-skipper/manifest
        github_branch main
        webhook_path /hook
        caddyfile /etc/caddy/Caddyfile
        github_owner intro-skipper
        github_repo manifest
        github_token {$GITHUB_TOKEN}
    }

    # Manifest Redirect Middleware
    manifest_redirect {
        base_url https://cdn.jsdelivr.net/gh/intro-skipper/manifest
        default_version 10.11
        github_url https://github.com/intro-skipper/
        manifest_path /manifest.json
        commit_hash d340f16ba1256ec563d7b08c0396645d555e65b8
    }

    # Fallback for other paths
    @notManifest not path /manifest.json
    redir @notManifest https://github.com/intro-skipper/ 308
}
```

## HTTP Status Codes

- **302 Found**: For manifest redirects (temporary, allows cache updates)
- **308 Permanent Redirect**: For GitHub redirects (permanent)

## Discord Notifications

The middleware sends Discord notifications for:

- **Startup sync**: When checking if local hash matches remote
- **Webhook updates**: When a push event updates the commit hash

Notifications include:

- Repository name
- Old and new commit hash
- Location information (if configured)
- Success/failure status

## Development

### Prerequisites

- Go 1.21 or higher
- Caddy v2

### Build

```bash
go build
```

### Test

```bash
go test ./...
```

## License

MIT License

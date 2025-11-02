# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OAuth2-bro is an OAuth2/OpenID Connect server that authenticates users based on their IP address. Written in Go, it's designed for trusted network environments (internal services, development environments, university classrooms) where IP-based authentication is appropriate.

The project supports two operational modes:
- **Standard OAuth2 mode**: Provides standard OAuth2 endpoints (/login, /token, /jwks)
- **Proxy mode**: Acts as a reverse proxy sidecar that automatically injects JWT tokens based on client IP, includes simplified OAuth2 endpoints for client compatibility

## Architecture

### Module Structure

This is a Go workspace project with multiple independent modules using local path replacements. Each module has its own `go.mod`:

- **oauth2-bro/** - Main executable and entry point (main.go)
- **user/** - IP-based user resolution and validation (`ResolveUserInfoFromRequest` in user-manager.go)
- **client/** - Client credential validation
- **keymanager/** - RSA key management and JWT token signing/validation
- **bro-server/** - Standard OAuth2 server implementation (login flow, token endpoint)
- **bro-proxy/** - Reverse proxy mode implementation with OAuth2 compatibility endpoints
- **bro-server-common/** - Shared HTTP handlers (health, JWKS, favicon, make-root)

### Key Components

**Main Entry (oauth2-bro/main.go)**
- Decides between standard OAuth2 mode or proxy mode based on `OAUTH2_BRO_PROXY_TARGET` env var
- Standard mode creates: RefreshKeys, CodeKeys, TokenKeys
- Proxy mode creates only: TokenKeys (simpler setup)
- Proxy mode includes OAuth2 endpoints for client compatibility (returns proxy-prefixed tokens)

**User Resolution (user/user-manager.go)**
- `ResolveUserInfoFromRequest()` extracts client IP from various headers (X-Forwarded-For, X-Real-IP, etc.)
- Creates username format: `ip-127-0-0-1` (dots/colons replaced with hyphens)
- Validates against `OAUTH2_BRO_ALLOWED_IP_MASKS` CIDR ranges
- Fork this file to customize authentication logic

**Key Management (keymanager/)**
- Three types of keys: Token (access/ID), Code (authorization codes), Refresh (refresh tokens)
- Uses RSA signing (2048-bit for token/code, 4096-bit for refresh)
- Keys can be loaded from PEM files or auto-generated in memory
- Exposes JWKS endpoint for token validation

**Make me Root Feature**
- Allows temporary admin override via cookie
- Standard mode: `/login?cookieSecret=...&sid=...&sub=...&name=...&email=...`
- Proxy mode: `/oauth2-bro/make-root?cookieSecret=...&sid=...` (POST)
- Cookie contains a JWT token; one-time use in standard mode, persistent in proxy mode
- Requires `OAUTH2_BRO_MAKE_ROOT_SECRET` environment variable

## Common Development Commands

### Building
```bash
# Build from the oauth2-bro subdirectory
cd oauth2-bro && go build .

# Build with version info
cd oauth2-bro && go build -ldflags="-X 'main.version=1.0.0'" -o oauth2-bro

# Build Docker image
docker build -t oauth2-bro .
```

### Testing
```bash
# Run tests for all modules
find . -name "go.mod" -type f | while read -r modfile; do
  module_dir=$(dirname "$modfile")
  echo "Testing module: $module_dir"
  cd "$module_dir" && go test ./... && cd -
done

# Run tests for a specific module
cd user && go test ./...
cd keymanager && go test ./...
```

### Running Locally
```bash
# HTTP only mode
cd oauth2-bro && OAUTH2_BRO_HTTP_PORT=8077 go run .

# HTTPS only mode (requires certificate)
cd oauth2-bro && \
  OAUTH2_BRO_HTTPS_PORT=8443 \
  OAUTH2_BRO_HTTPS_CERT_FILE=/path/to/cert.pem \
  OAUTH2_BRO_HTTPS_CERT_KEY_FILE=/path/to/key.pem \
  go run .

# Dual HTTP/HTTPS mode (recommended)
cd oauth2-bro && \
  OAUTH2_BRO_HTTP_PORT=8077 \
  OAUTH2_BRO_HTTPS_PORT=8443 \
  OAUTH2_BRO_HTTPS_CERT_FILE=/path/to/cert.pem \
  OAUTH2_BRO_HTTPS_CERT_KEY_FILE=/path/to/key.pem \
  go run .

# Proxy mode
cd oauth2-bro && \
  OAUTH2_BRO_HTTP_PORT=8077 \
  OAUTH2_BRO_PROXY_TARGET=http://localhost:8080 \
  go run .
```

### Integration Testing
```bash
# Run IDE Services integration tests
./integration-test/run-ide-services-demo.sh      # Standard OAuth2 flow
./integration-test/run-ide-services-proxy.sh     # Proxy mode
```

## Important Configuration

All configuration is via environment variables. Key variables:

**Network Settings**
- `OAUTH2_BRO_BIND_HOST` (default: localhost)
- `OAUTH2_BRO_HTTP_PORT` - HTTP port for internal connections
- `OAUTH2_BRO_HTTPS_PORT` - HTTPS port for external connections
- `OAUTH2_BRO_HTTPS_CERT_FILE` - Path to PEM certificate (required for HTTPS)
- `OAUTH2_BRO_HTTPS_CERT_KEY_FILE` - Path to PEM private key (required for HTTPS)
- At least one port (HTTP or HTTPS) must be configured
- Both can run simultaneously for dual HTTP/HTTPS operation

**Authentication**
- `OAUTH2_BRO_EMAIL_DOMAIN` - Domain for generated email addresses
- `OAUTH2_BRO_ALLOWED_IP_MASKS` - CIDR ranges (e.g., "10.0.0.0/8,192.168.0.0/16")

**Mode Selection**
- `OAUTH2_BRO_PROXY_TARGET` - If set, enables proxy mode (e.g., "http://service:8080")

**Keys (Production Multi-Node)**
- `OAUTH2_BRO_TOKEN_RSA_KEY_PEM_FILE` - Access token signing key
- `OAUTH2_BRO_CODE_RSA_KEY_PEM_FILE` - Authorization code signing key
- `OAUTH2_BRO_REFRESH_RSA_KEY_PEM_FILE` - Refresh token signing key

**Admin Override**
- `OAUTH2_BRO_MAKE_ROOT_SECRET` - Required for "Make me Root" functionality

See Spec.md for complete configuration reference.

## Multi-Node Deployment Considerations

For stateless multi-node deployments:
1. All nodes must share the same RSA signing keys (provide via `*_PEM_FILE` env vars)
2. This ensures tokens/codes generated by one node can be validated by another
3. No session affinity required at load balancer
4. Essential for Make me Root cookie functionality across nodes

## Code Style and Conventions

- Go interfaces defined in `*-interface.go` files, implementations in `*-manager.go`
- Use local imports: `jonnyzzz.com/oauth2-bro/<module>`
- HTTP handlers follow pattern: `http-<endpoint>.go` (e.g., http-login.go, http-token.go)
- Common server setup in `server.go` with `SetupServer()` function
- Tests in `*_test.go` files
- Environment variable reading in init/constructor functions

## Project-Specific Notes

1. **User Authentication Logic**: The core IP-to-user logic is in `user/user-manager.go:ResolveUserInfoFromRequest()`. This is the primary customization point for authentication rules.

2. **Proxy vs Standard Mode**: The main.go switches between modes. Proxy mode injects JWT tokens automatically and includes simplified OAuth2 endpoints (`/oauth2-bro/login` and `/oauth2-bro/token`) for client compatibility. These endpoints return proxy-prefixed tokens (e.g., `oauth2-bro-proxy-access-*`) that satisfy OAuth2 client expectations, but are not used for actual authorization (the proxy replaces all Authorization headers). Standard mode implements full OAuth2 authorization code grant.

3. **Dual HTTP/HTTPS Operation**: OAuth2-bro can run HTTP and HTTPS simultaneously on different ports. This solves the common problem where backend services (like JetBrains IDE Services) struggle to connect to HTTPS OAuth2 providers:
   - HTTPS port (8443) for external clients (browsers, external tools)
   - HTTP port (8077) for internal service-to-service communication
   - Both serve the same OAuth2 server, no session affinity needed
   - Eliminates certificate configuration complexity for backend services

4. **Security Context**: This is designed for TRUSTED networks only. IP-based authentication is inherently less secure than credential-based auth. Always deploy behind firewalls/VPNs.

5. **JetBrains IDE Services Integration**: See Ide-Services-Recipes.md for practical integration patterns. The dual HTTP/HTTPS mode is the recommended configuration for IDE Services deployments.

6. **Docker Build**: The Dockerfile runs tests for ALL modules during build, ensuring the entire workspace is validated before producing the final image.

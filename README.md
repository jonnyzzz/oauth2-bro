[![Build](https://github.com/jonnyzzz/oauth2-bro/actions/workflows/go.yml/badge.svg)](https://github.com/jonnyzzz/oauth2-bro/actions/workflows/go.yml)

# OAuth2-bro

<img width="20%" alt="OAuth2-bro logo" src="https://github.com/user-attachments/assets/83601875-ba6f-4366-a775-a55e9384222e" />

OAuth2 server that authenticates users based on their IP address - no client credentials needed.
Perfect for internal services, development environments, and regulated businesses.

## 🎯 What it does

OAuth2-bro simplifies authentication by:
- **Authenticating** users based on their request IP address (who you are)
- **Authorizing** access to resources without managing client IDs/secrets (what you can access)
- Providing standard OAuth2 flows for seamless integration or proxy
- Supporting stateless, multi-node deployments

It helps:
- **University classrooms** - Shared computers with rotating users
- **Remote development servers** - Secure access to development machines without credential distribution
- **Internal microservices** - Skip credential management for services behind your firewall
- **Machine-to-machine auth** - Authorize services based on their network location
- **Corporate integration** - Bridge to existing authentication systems
- **Development environments** - Quick auth setup without the complexity

## Recipes

📖 [Complete Guide: Dual HTTP/HTTPS Setup](Dual-HTTP-HTTPS-Setup.md) - Architecture diagrams, security considerations, and deployment examples
📖 [JetBrains IDE Services Integration Recipes](Ide-Services-Recipes.md)

## 📄 License

Apache 2.0 — see [LICENSE](LICENSE)

## 🙏 Background

OAuth2-bro was created by [Eugene Petrenko](https://jonnyzzz.com) to support customer
requests at [JetBrains IDE Services](https://jetbrains.com/ide-services), focusing on
management, security, and governance of AI and Developer Tools at scale. The name is
inspired by Orwell's "1984" — but instead of watching you, this Big Brother just checks
your IP address!

### NOTICE

This project is **NOT** an official JetBrains product and is **NOT** affiliated with, endorsed
by, or maintained by JetBrains or any of its subsidiaries.

OAuth2-bro is an independent, community-driven open-source project created to solve IP-based
authentication challenges. While it was initially developed to support JetBrains IDE Services
integration scenarios, it is a standalone solution that can be used with any service requiring
seamless OAuth2 authentication.

# 🚀 Quick Start

```bash
docker build -t oauth2-bro .
docker run -p 8077:8077 -env OAUTH2_BRO_HTTP_PORT=8087 oauth2-bro
```

## Functioning Modes

OAuth2-bro can operate in two modes:
- **Bro Mode** — Runs as a standalone service, providing OAuth2 endpoints for clients. Default.
- **Proxy Mode** — Runs as a sidecar container, intercepting all incoming requests and injecting JWT tokens

### Bro Mode
This mode is activated by default. It provides OAuth2 endpoints for clients to authenticate and authorize.

| Endpoint       | Method | Description                                                                             |
|----------------|--------|-----------------------------------------------------------------------------------------|
| `/`            | GET    | Home page/server info                                                                   |
| `/favicon.ico` | GET    | Favicon handler                                                                         |
| `/health`      | GET    | Health check endpoint                                                                   |
| `/jwks`        | GET    | JSON Web Key Set (public keys for token verification)                                   |
| `/login`       | GET    | OAuth2 authorization endpoint (login flow)                                              |
| `/make-root`   | GET    | Admin override endpoint (requires `cookieSecret`, `sid`, `sub`, `name`, `email` params) |
| `/token`       | POST   | OAuth2 token endpoint (exchange code for tokens)                                        |


### Proxy Mode
This mode is activated by setting the `OAUTH2_BRO_PROXY_TARGET` environment variable pointing to the target service.
It intercepts all incoming requests and injects JWT tokens.

When `OAUTH2_BRO_PROXY_TARGET` is set, OAuth2-bro runs in proxy mode, acting as a sidecar
container that:
- Forwards all incoming requests to the specified target service
- Removes any existing Authorization header
- Adds a freshly generated JWT access token based on the client's IP address
- Exposes a JWKS endpoint at `/oauth2-bro/jwks` for token validation
- Provides OAuth2 compatibility endpoints (`/oauth2-bro/login` and `/oauth2-bro/token`) for OAuth2 clients

| Endpoint                  | Method   | Description                                                         |
|---------------------------|----------|---------------------------------------------------------------------|
| `**`                      | *        | Proxies all requests to the `OAUTH2_BRO_PROXY_TARGET` environment   |
| `/oauth2-bro/unmake-root` | GET/POST | Remove admin override (clear make-root cookie)                      |
| `/oauth2-bro/make-root`   | POST     | Admin override endpoint (requires `cookieSecret`, `sid` params)     |
| `/oauth2-bro/health`      | GET      | Health check endpoint                                               |
| `/oauth2-bro/jwks`        | GET      | JSON Web Key Set (public keys for token verification)               |
| `/oauth2-bro/login`       | GET      | OAuth2 compatibility endpoint (returns proxy-prefixed tokens)       |
| `/oauth2-bro/token`       | POST     | OAuth2 compatibility endpoint (returns proxy-prefixed tokens)       |

## Configuration

### HTTP Server Settings

| Variable                         | Description                                  | Default   |
|----------------------------------|----------------------------------------------|-----------|
| `OAUTH2_BRO_BIND_HOST`           | Bind address                                 | localhost |
| `OAUTH2_BRO_HTTP_PORT`           | HTTP port for internal connections           | -         |
| `OAUTH2_BRO_HTTPS_PORT`          | HTTPS port for external connections          | -         |
| `OAUTH2_BRO_HTTPS_CERT_FILE`     | Path to PEM certificate (required for HTTPS) | -         |
| `OAUTH2_BRO_HTTPS_CERT_KEY_FILE` | Path to PEM private key (required for HTTPS) | -         |

**Note:** At least one port (HTTP or HTTPS) must be configured. Both can run simultaneously for dual operation.
Avoid opening the HTTP port to the public network or internet.

### Client Authentication based on IP Settings

| Variable                        | Description                                                              | Default |
|---------------------------------|--------------------------------------------------------------------------|---------|
| `OAUTH2_BRO_EMAIL_DOMAIN`       | Domain for generated emails (e.g., `ip-127-0-0-1@your-domain`)           | -       |
| `OAUTH2_BRO_ALLOWED_IP_MASKS`   | Comma-separated CIDR ranges (e.g., "10.0.0.0/8,192.168.0.0/16")          | -       |

The rules are set in the `OAUTH2_BRO_ALLOWED_IP_MASKS` environment variable, which is the ',' separated list of CIDR ranges.
Authentication is successful if the request IP address is within one of the ranges.

Implementation uses resolves the true real IP from the proxy headers, just make sure your
reverse proxy is configured properly to pass the real client IP.

The `OAUTH2_BRO_EMAIL_DOMAIN` generates email addresses based on the IP address with the specified domain.

For more details, see the [Proxy Mode Configuration Sources](user/user-manager.go). This is the place,
where we need to add more rules based on your needs. Create PR or issues and let us know.

### OAuth2 Client Configuration

| Variable                        | Description                                                              | Default |
|---------------------------------|--------------------------------------------------------------------------|---------|
| `OAUTH2_BRO_CLIENT_CREDENTIALS` | Optional clientId/secret credentials ("client1=secret1,client2=secret2") | -       |

**Note:** If the `OAUTH2_BRO_CLIENT_CREDENTIALS` variable is not set, OAuth2-bro will accept requests with all possible client/secret combinations.

### Token Keys Configuration

OAuth2-Bro uses RSA keys for signing and verifying tokens, no storage is used.
For production deployments, especially multi-node setups, provide your own RSA keys:

| Variable                                | Description                              | Default          |
|-----------------------------------------|------------------------------------------|------------------|
| `OAUTH2_BRO_TOKEN_RSA_KEY_PEM_FILE`     | Path to token signing key (2048-bit RSA) | Auto-generated   |
| `OAUTH2_BRO_TOKEN_EXPIRATION_SECONDS`   | Access token lifetime                    | 300 (5 min)      |
| `OAUTH2_BRO_CODE_RSA_KEY_PEM_FILE`      | Path to code signing key (2048-bit RSA)  | Auto-generated   |
| `OAUTH2_BRO_CODE_EXPIRATION_SECONDS`    | Authorization code lifetime              | 5                |
| `OAUTH2_BRO_REFRESH_RSA_KEY_PEM_FILE`   | Path to refresh token key (4096-bit RSA) | Auto-generated   |
| `OAUTH2_BRO_REFRESH_EXPIRATION_SECONDS` | Refresh token lifetime                   | 864000 (10 days) |

### Make Me Root Access

You may want to bypass the normal login flow and impersonate as a specific user. To allow this,
first set the `OAUTH2_BRO_MAKE_ROOT_SECRET` environment variable to enable the feature. 

Now you can mark the current browser session to impersonate as a specific user (aka "make me root").
For that, кun the following request (for parameters, see below) to the following endpoint:
* `/make-root` (for Bro Mode)
* `/oauth2-bro/make-root` (for Proxy Mode)

The payload should contain the following parameters:
- `cookieSecret`: Must match the `OAUTH2_BRO_MAKE_ROOT_SECRET` environment variable
- At least one of: `sid`, `sub`, `name`, or `email` (missing values are autofilled from provided ones)
- Make sure your target service expects such compination to gain you additional permissions.

[See examples with IDE Services](integration-test/root-cookie.md)

## 🏭 Production Deployment

We recommend building the Docker image and running it with the necessary environment variables and volumes for production deployments.

Single node deployments do not require generating and saving the keys. Service restart will require all clients to (implicitly) log in again.

Multi-node deployments require generating and settings the same keys to all nodes. It will also make the JWKS file more stable and 

Use `/health` and `/oauth2-bro/health` endpoints to check the health of the service.

### 🔑 Key and Certificate Generation

For production deployments, keep keys secure! Leaking them will allow anyone to impersonate your users.
You can start by generating RSA keys and certificates manually:

```bash
# Generate RSA keys for token signing
openssl genrsa -out token-key.pem 2048
openssl genrsa -out code-key.pem 2048
openssl genrsa -out refresh-key.pem 4096

# Generate HTTPS certificate (replace with your domain)
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server-key.pem -out server-cert.pem \
  -days 365 -subj "/CN=your-domain.com"
```

## 🤝 Contributing

We welcome contributions! For major changes:
1. Open an issue to discuss your idea
2. Fork the repository
3. Create a pull request

Let's build better authentication together!

## 🛠️ Development

OAuth2-bro is written in Go for easy customization. Feel free to fork and modify 
for your specific needs:

```bash
# Clone the repository
git clone https://github.com/jonnyzzz/oauth2-bro
cd oauth2-bro

# Build locally
go build .

# Run with custom logic
./oauth2-bro

# Run all tests (we run tests during the container build)
docker build -t oauth2-bro .
```

Pull requests are welcome! Report issues if you find any. Star the repository.

[![Build](https://github.com/jonnyzzz/oauth2-bro/actions/workflows/go.yml/badge.svg)](https://github.com/jonnyzzz/oauth2-bro/actions/workflows/go.yml)

# OAuth2-bro

<img width="20%" alt="OAuth2-bro logo" src="https://github.com/user-attachments/assets/83601875-ba6f-4366-a775-a55e9384222e" />

OAuth2 server that authenticates users based on their IP address - no client credentials needed.
Perfect for internal services, development environments, and regulated businesses.

## 🎯 What it does

OAuth2-bro simplifies authentication by:
- **Authenticating** users based on their request IP address (who you are)
- **Authorizing** access to resources without managing client IDs/secrets (what you can access)
- Providing standard OAuth2 flows for seamless integration
- Supporting stateless, multi-node deployments

### User Authentication Rules
See the `ResolveUserInfoFromRequest` function under `user/user-manager.go` to understand the current approach better.
Fork this repository to change the logic or contribute to the original one. We are eager to learn about your needs.

### Quick Start Recipes

📖 [Complete Guide: Dual HTTP/HTTPS Setup](Dual-HTTP-HTTPS-Setup.md) - Architecture diagrams, security considerations, and deployment examples
📖 [JetBrains IDE Services Integration Recipes](Ide-Services-Recipes.md)

## 🤝 Contributing

We welcome contributions! For major changes:
1. Open an issue to discuss your idea
2. Fork the repository
3. Create a pull request

Let's build better authentication together!

## 📄 License

Apache 2.0 — see [LICENSE](LICENSE) file

## 🙏 Background

OAuth2-bro was created by [Eugene Petrenko](https://jonnyzzz.com) to support customer
requests at [JetBrains IDE Services](https://jetbrains.com/ide-services), focusing on
management, security, and governance of AI and Developer Tools at scale. The name is
inspired by Orwell's "1984" — but instead of watching you, this Big Brother just checks
your IP address!

**⚠️ IMPORTANT NOTICE**

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

## 📋 Use Cases

- **University classrooms** - Shared computers with rotating users
- **Remote development** - Secure access to development machines without credential distribution
- **Internal microservices** - Skip credential management for services behind your firewall
- **Machine-to-machine auth** - Authorize services based on their network location
- **Corporate integration** - Bridge to existing authentication systems
- **Development environments** - Quick auth setup without the complexity

## 🔒 Security Considerations

⚠️ **Important**: IP-based authentication is only secure in trusted environments:
- Use only behind firewalls or VPNs
- Not suitable for public-facing services
- Consider the risk of IP spoofing in your environment
- Always use HTTPS in production
- Configure `OAUTH2_BRO_ALLOWED_IP_MASKS` to restrict access

## ⚙️ Configuration

OAuth2-bro uses environment variables for all configuration:

### Network Settings

| Variable                         | Description                                  | Default   |
|----------------------------------|----------------------------------------------|-----------|
| `OAUTH2_BRO_BIND_HOST`           | Bind address                                 | localhost |
| `OAUTH2_BRO_HTTP_PORT`           | HTTP port for internal connections           | -         |
| `OAUTH2_BRO_HTTPS_PORT`          | HTTPS port for external connections          | -         |
| `OAUTH2_BRO_HTTPS_CERT_FILE`     | Path to PEM certificate (required for HTTPS) | -         |
| `OAUTH2_BRO_HTTPS_CERT_KEY_FILE` | Path to PEM private key (required for HTTPS) | -         |

**Note:** At least one port (HTTP or HTTPS) must be configured. Both can run simultaneously for dual operation:
- **HTTPS** for external clients (requires certificate)
- **HTTP** for internal service-to-service communication (avoids certificate complexity, risky)

### Authentication Settings

| Variable                        | Description                                                              | Default |
|---------------------------------|--------------------------------------------------------------------------|---------|
| `OAUTH2_BRO_EMAIL_DOMAIN`       | Domain for generated emails (e.g., `ip-127-0-0-1@your-domain`)           | -       |
| `OAUTH2_BRO_ALLOWED_IP_MASKS`   | Comma-separated CIDR ranges (e.g., "10.0.0.0/8,192.168.0.0/16")          | -       |
| `OAUTH2_BRO_CLIENT_CREDENTIALS` | Optional clientId/secret credentials ("client1=secret1,client2=secret2") | -       |


### Token Configuration

For production deployments, especially multi-node setups, provide your own RSA keys:

| Variable                                | Description                              | Default          |
|-----------------------------------------|------------------------------------------|------------------|
| `OAUTH2_BRO_TOKEN_RSA_KEY_PEM_FILE`     | Path to token signing key (2048-bit RSA) | Auto-generated   |
| `OAUTH2_BRO_TOKEN_EXPIRATION_SECONDS`   | Access token lifetime                    | 300 (5 min)      |
| `OAUTH2_BRO_CODE_RSA_KEY_PEM_FILE`      | Path to code signing key (2048-bit RSA)  | Auto-generated   |
| `OAUTH2_BRO_CODE_EXPIRATION_SECONDS`    | Authorization code lifetime              | 5                |
| `OAUTH2_BRO_REFRESH_RSA_KEY_PEM_FILE`   | Path to refresh token key (4096-bit RSA) | Auto-generated   |
| `OAUTH2_BRO_REFRESH_EXPIRATION_SECONDS` | Refresh token lifetime                   | 864000 (10 days) |

### Admin Access

| Variable                      | Description                             |
|-------------------------------|-----------------------------------------|
| `OAUTH2_BRO_MAKE_ROOT_SECRET` | Secret for admin override functionality |

### Proxy Mode Configuration

| Variable                  | Description                                                        |
|---------------------------|--------------------------------------------------------------------|
| `OAUTH2_BRO_PROXY_TARGET` | Target URL to enable proxy mode (e.g., "http://your-service:8080") |

When `OAUTH2_BRO_PROXY_TARGET` is set, OAuth2-bro runs in proxy mode, acting as a sidecar container that:
- Forwards all incoming requests to the specified target service
- Removes any existing Authorization header
- Adds a freshly generated JWT access token based on the client's IP address
- Exposes a JWKS endpoint at `/oauth2-bro/jwks` for token validation
- Provides OAuth2 compatibility endpoints (`/oauth2-bro/login` and `/oauth2-bro/token`) for OAuth2 clients

**OAuth2 Client Compatibility:**
Proxy mode includes simplified OAuth2 authorization endpoints that make OAuth2 clients happy by providing 
the expected OAuth2 flow. The returned tokens (with `oauth2-bro-proxy-*` prefix) are not used for actual 
authorization - the proxy replaces all Authorization headers with fresh JWTs. This allows OAuth2 clients 
to complete their authentication flow while the proxy handles actual token injection.

This allows services to receive authenticated requests without implementing OAuth2 themselves.

## Make me Root

Marks the current browser session as a special account. 
It can be used to bypass the normal login flow and access the admin panel, when that specific account
is registered in the target service as an admin. 
Run the following request (for parameters, see below) to the following endpoints:
* `/make-root` (for bro mode)
* `/oauth2-bro/make-root` (for proxy mode)

The payload should contain the following parameters:
- `cookieSecret`: Must match the `OAUTH2_BRO_MAKE_ROOT_SECRET` environment variable
- At least one of: `sid`, `sub`, `name`, or `email` (missing values are autofilled from provided ones)

[Examples](integration-test/root-cookie.md)

Standard bro mode supports "Make me Root" for the interactive OAuth2 login flow:
- Set cookie: call ` or `/login` endpoint
- Behavior: This sets a one-time cookie. On the next regular login flow, the `oauth2-bro` consumes the cookie, authenticates as the specified user, and immediately clears the cookie.

The `/make-root` endpoint is dedicated to setting the admin override cookie, while `/login` can also handle it alongside the normal login flow. Both endpoints require:
- `cookieSecret`: Must match the `OAUTH2_BRO_MAKE_ROOT_SECRET` environment variable
- At least one of: `sid`, `sub`, `name`, or `email` (missing values are auto-filled from provided ones)

The JWT token expiration time is used for the cookie expiration time, adjust if needed. For the bro mode, the cookie is cleared on the next login flow.

## 🔑 Key and Certificate Generation

For production deployments, generate RSA keys and certificates manually:

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

## 🏭 Production Deployment

We recommend building the Docker image and running it with the necessary environment variables and volumes for production deployments.

Single node deployments do not require generating and saving the keys. Service restart will require all clients to (implicitly) log in again.

Multi-node deployments require generating and settings the same keys to all nodes. It will also make the JWKS file more stable and 

Use `/health` and `/oauth2-bro/health` endpoints to check the health of the service.

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

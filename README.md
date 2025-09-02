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

## 🔧 JetBrains IDE Services Recipes and Integration

Looking for practical integration options with JetBrains IDE Services, including no-login proxy mode and admin override? See Ide-Services-Recipes.md for detailed recipes, configuration snippets, and local demo scripts.

- Recipes: [JetBrains IDE Services](Ide-Services-Recipes.md)

## 🤝 Contributing

We welcome contributions! For major changes:
1. Open an issue to discuss your idea
2. Fork the repository
3. Create a pull request

Let's build better authentication together!

## 📄 License

Apache 2.0 - see [LICENSE](LICENSE) file

## 🙏 Background

OAuth2-bro was created by [Eugene Petrenko](https://jonnyzzz.com) to support customer
requests at [JetBrains IDE Services](https://jetbrains.com/ide-services), focusing on
management, security, and governance of AI and Developer Tools at scale. The name is
inspired by Orwell's "1984" - but instead of watching you, this Big Brother just checks
your IP address!

## User Authentication Rules
See the `ResolveUserInfoFromRequest` function under `user/user-manager.go` to understand the current approach better.
Fork this repository to change the logic or contribute to the original one. We are eager to learn about your needs.

# 🚀 Quick Start

```bash
# Using Docker
docker run -p 8077:8077 oauth2-bro

# Or build from source
docker build -t oauth2-bro .
docker run -p 8077:8077 oauth2-bro
```

Your OAuth2 server is now running at `http://localhost:8077`

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

### Basic Settings

| Variable | Description                                                              | Default |
|----------|--------------------------------------------------------------------------|---------|
| `OAUTH2_BRO_BIND_PORT` | Server port                                                              | 8077 |
| `OAUTH2_BRO_BIND_HOST` | Bind address                                                             | localhost |
| `OAUTH2_BRO_EMAIL_DOMAIN` | Domain for generated emails (e.g., `ip-127-0-0-1@your-domain`)           | - |
| `OAUTH2_BRO_ALLOWED_IP_MASKS` | Comma-separated CIDR ranges (e.g., "10.0.0.0/8,192.168.0.0/16")          | - |
| `OAUTH2_BRO_CLIENT_CREDENTIALS` | Optional clientId/secret credentials ("client1=secret1,client2=secret2") | - |

### HTTPS Configuration (optional)

| Variable | Description |
|----------|-------------|
| `OAUTH2_BRO_HTTPS_CERT_FILE` | Path to PEM encoded certificate |
| `OAUTH2_BRO_HTTPS_CERT_KEY_FILE` | Path to PEM encoded private key |


### Token Configuration

For production deployments, especially multi-node setups, provide your own RSA keys:

| Variable | Description | Default |
|----------|-------------|---------|
| `OAUTH2_BRO_TOKEN_RSA_KEY_PEM_FILE` | Path to token signing key (2048-bit RSA) | Auto-generated |
| `OAUTH2_BRO_TOKEN_EXPIRATION_SECONDS` | Access token lifetime | 300 (5 min) |
| `OAUTH2_BRO_CODE_RSA_KEY_PEM_FILE` | Path to code signing key (2048-bit RSA) | Auto-generated |
| `OAUTH2_BRO_CODE_EXPIRATION_SECONDS` | Authorization code lifetime | 5 |
| `OAUTH2_BRO_REFRESH_RSA_KEY_PEM_FILE` | Path to refresh token key (4096-bit RSA) | Auto-generated |
| `OAUTH2_BRO_REFRESH_EXPIRATION_SECONDS` | Refresh token lifetime | 864000 (10 days) |

### Admin Access

| Variable | Description |
|----------|-------------|
| `OAUTH2_BRO_MAKE_ROOT_SECRET` | Secret for admin override functionality |

### Proxy Mode Configuration

| Variable | Description |
|----------|-------------|
| `OAUTH2_BRO_PROXY_TARGET` | Target URL to enable proxy mode (e.g., "http://your-service:8080") |

When `OAUTH2_BRO_PROXY_TARGET` is set, OAuth2-bro runs in proxy mode, acting as a sidecar container that:
- Forwards all incoming requests to the specified target service
- Removes any existing Authorization header
- Adds a freshly generated JWT access token based on the client's IP address
- Exposes a JWKS endpoint at `/oauth2-bro/jwks` for token validation

This allows services to receive authenticated requests without implementing OAuth2 themselves.


#### Make me Root (bro mode)

Standard bro mode also supports "Make me Root" for the interactive OAuth2 login flow:
- Set cookie: call `/login?cookieSecret=...&sid=...&sub=...&name=...&email=...` (same parameters as proxy mode)
- Behavior: This sets a one-time cookie. On the next regular login flow, the `oauth2-bro` consumes the cookie, authenticates as the specified user, and immediately clears the cookie.

#### Make me Root (proxy mode)

Proxy mode supports an admin override via a cookie-based "Make me Root" feature:
- Set cookie: POST `/oauth2-bro/make-root?cookieSecret=...&sid=...&sub=...&name=...&email=...`
- Clear cookie: POST `/oauth2-bro/unmake-root`
- Behavior: For every proxied request, if the cookie is present and valid, the proxy sets `Authorization` header based on the provided credentials.

The JWT token expiration time is affecting the cookie expiration time, adjust if needed.

Important for multi-node setups: all proxy nodes must use the same token signing keys so that the JWT in the cookie can be validated by any node. Share/synchronize the Token keys across nodes. See Spec.md for details.


## 🔑 Key Generation

For production deployments, generate RSA keys manually:

```bash
# Generate 2048-bit RSA key for tokens/codes
openssl genrsa -out token-key.pem 2048
openssl genrsa -out code-key.pem 2048
openssl genrsa -out refresh-key.pem 4096
```

## 🏭 Production Deployment

### Single Node

```bash
docker run -d \
  --name oauth2-bro \
  --restart unless-stopped \
  -p 443:8077 \
  -e OAUTH2_BRO_EMAIL_DOMAIN=company.com \
  -e OAUTH2_BRO_ALLOWED_IP_MASKS="10.0.0.0/8,192.168.0.0/16" \
  -e OAUTH2_BRO_TOKEN_RSA_KEY_PEM_FILE=/keys/token-key.pem \
  -e OAUTH2_BRO_CODE_RSA_KEY_PEM_FILE=/keys/code-key.pem \
  -e OAUTH2_BRO_REFRESH_RSA_KEY_PEM_FILE=/keys/refresh-key.pem \
  -e OAUTH2_BRO_HTTPS_CERT_FILE=/certs/server.crt \
  -e OAUTH2_BRO_HTTPS_CERT_KEY_FILE=/certs/server.key \
  -v /path/to/keys:/keys:ro \
  -v /path/to/certs:/certs:ro \
  oauth2-bro
```

### Multi-Node Deployment

OAuth2-bro is stateless when configured with external keys. For high availability:

1. Generate RSA keys once
2. Deploy multiple nodes with the same keys
3. Use any load balancer (no session affinity needed)

## 🏗️ How it Works

1. **Client requests access** - Application redirects to OAuth2-bro's `/authorize` endpoint
2. **IP-based authentication** - OAuth2-bro identifies the user based on their IP address
3. **Token generation** - If IP is allowed, OAuth2-bro issues JWT tokens
4. **Resource access** - Client uses tokens to access protected resources

The flow follows standard OAuth2 authorization code grant, but skips the user login step by using IP addresses for authentication.

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
```

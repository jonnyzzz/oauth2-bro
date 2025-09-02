# JetBrains IDE Services: OAuth2-bro Recipes

This document collects practical, field-tested ways to integrate JetBrains IDE Services with OAuth2-bro. It expands
the brief scenarios into concrete recipes with when-to-use guidance, local demo commands, configuration
snippets, and links to deeper specifications.

If you’re new to `OAuth2-bro`, start with the project overview in README.md. For implementation details and rationale, see [Spec.md](Spec.md).

## Recipe 1: Browser Flow (Implicit, IP-based)

Description
- IDE Services redirects users to `OAuth2-bro` for OAuth2/OpenID Connect login.
- `OAuth2-bro` authenticates users automatically based on IP; no credentials are requested.
- Good for trusted networks, labs, internal environments, or quick-start demos.

How to try locally
- Run the demo script: `integration-test/run-ide-services-demo.sh`
- It starts a local stack you can explore end-to-end.

IDE Services configuration:
```yaml
tbe:
  auth:
    login-url: 'http://oauth2-bro:8077/login'
    token-url: 'http://oauth2-bro:8077/token'
    jwt-certs-url: 'http://oauth2-bro:8077/jwks'
    root-admin-emails:
      - 'admin@company.com'
    root-admin-subjects:
      - 'admin'
```

Notes
- Ensure `OAUTH2_BRO_ALLOWED_IP_MASKS` is configured for your network ranges.
- Use HTTPS/ingress TLS in production, better via an external reverse-proxy or ingress

## Recipe 2: Sidecar Proxy Mode (No-login Authentication)

Description
- Run OAuth2-bro as a sidecar reverse-proxy in front of IDE Services container.
- The proxy strips any incoming Authorization header and injects a fresh JWT based on client IP.
- IDEs and Toolbox App do not perform interactive auth; the token is added transparently by the sidecar.
- Ideal for “no-login” scenarios and controlled environments.

How to try locally
- Run the proxy demo: `integration-test/run-ide-services-proxy.sh`

Important notes
- Admin Web UI currently needs a small fix to honor the injected token: https://youtrack.jetbrains.com/issue/IDES-9819/Admin-Web-UI-requires-login-ignoring-token
- This approach aligns with JetBrains docs: https://www.jetbrains.com/help/ide-services/no-login-authentication.html

Implementation details and links
- Enable with env var: `OAUTH2_BRO_PROXY_TARGET` (see README.md#proxy-mode-configuration)
- JWKS in proxy mode is exposed at `/oauth2-bro/jwks` (see Spec.md#proxy-mode)

# User Authentication Rules
See the `ResolveUserInfoFromRequest` function under `user/user-manager.go` to understand the current approach better.
Fork this repository to change the logic or contribute to the original one. We are eager to learn about your needs.


# Admin Override (“Make me Root”)

Description
- Sometimes you need to authenticate as a specific admin user (e.g., for IDE Services Admin Console) instead of IP-based identity.
- OAuth2-bro supports a temporary admin override cookie set via a special URL.

How to use
- Configure `OAUTH2_BRO_MAKE_ROOT_SECRET` in the server environment.
- Open a URL for Recipe 1 (Browser Flow)
  `http://localhost:8077/login?cookieSecret=your-secret&sid=admin&email=admin@company.com`
- Open a URL for Recipe 2 (Sidecar Proxy)
  `http://localhost:8443/oauth2-bro/login?cookieSecret=your-secret&sid=admin&email=admin@company.com`
- Proceed with the usual login flow in the same browser

Parameters
- `cookieSecret`: must match `OAUTH2_BRO_MAKE_ROOT_SECRET`
- `sid` or `sub`: subject ID
- `name`: optional user name
- `email`: optional email address

Security notes
- Use HTTPS in production; keep `OAUTH2_BRO_MAKE_ROOT_SECRET` secure.
- Cookie is HttpOnly and scoped to /login; removed after login.

## When to choose which recipe
- Prefer Recipe 1 (Browser Flow) when your users can follow a standard OAuth2 redirect with implicit IP-based auth.
- Prefer Recipe 2 (Sidecar Proxy) to achieve no-login UX or when integrating legacy clients that can’t perform OAuth2 flows reliably.
- Use Recipe 3 (Admin Override) selectively for admin operations or break-glass needs.

## Contributing and Extensions
- We welcome contributions and customer-driven tweaks; small fixes can be integrated upstream.
- For complex deployments, consider engaging Professional Services.
- See [Spec.md](Spec.md) for potential future extensions: Explicit Tokens, multi-node key distribution, and chained auth.

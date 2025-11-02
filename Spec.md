OAuth2-bro Specification
----------


The OAuth2 server is working as follows
- sid and sub of users is `ip-<ip with - as separator>`
- client IP addresses are extracted from HTTP requests using various headers including X-Forwarded-For, X-Real-IP, Forwarded, X-Client-IP, CF-Connecting-IP, True-Client-IP, and falling back to RemoteAddr
- every JWT access and ID tokens are JWT
- refresh token is also JWT
- we keep list of public keys for access tokens
- we keep list of public keys for refresh tokens
- the service uses it's main private key for access/id tokens
- the server uses it's another main private key for refresh tokens
- all configuration parameters can be read from ~~the configuration file or~~ environment variables 
- the server lists ~~all~~ token public keys as JWKs via the `/jwks` endpoint
- ~~additionally, we let the server list all refresh tokens as another JWKs~~ (not implemented in current version)
- the server can run HTTPS, given it receives the certificate and private keys to do so (we still recommend terminate HTTPS at a load balancer level)
- the server is built minimalistic to allow wide range of deployments, from docker to kubernetes and cloud providers


HTTP Server
---

`OAUTH2_BRO_BIND_HOST` (defaults to localhost) -- the server bind host address, for production, or Docker use the right network interface(s) to bind

`OAUTH2_BRO_HTTP_PORT` -- HTTP server port for internal connections (optional, at least one of HTTP_PORT or HTTPS_PORT must be set)

`OAUTH2_BRO_HTTPS_PORT` -- HTTPS server port for external connections (optional, at least one of HTTP_PORT or HTTPS_PORT must be set)

`OAUTH2_BRO_HTTPS_CERT_FILE` -- Path to PEM encoded certificate file (required if HTTPS_PORT is set)

`OAUTH2_BRO_HTTPS_CERT_KEY_FILE` -- Path to PEM encoded private key file (required if HTTPS_PORT is set)

**Dual HTTP/HTTPS Operation:**

Both HTTP and HTTPS ports can run simultaneously on the same server instance. This is the recommended configuration for services that need to:
- Expose HTTPS to external clients (browsers, external tools)
- Provide HTTP endpoint for internal service-to-service communication (avoiding certificate complexity for backend services like JetBrains IDE Services)

Example: `OAUTH2_BRO_HTTP_PORT=8077 OAUTH2_BRO_HTTPS_PORT=8443` runs both protocols simultaneously

`OAUTH2_BRO_TOKEN_RSA_KEY_PEM_FILE` -- optional key file for access token private key, PEM encoded

`OAUTH2_BRO_TOKEN_RSA_KEY_ID` -- optional, the key file key id, otherwise a hash of the token public key

`OAUTH2_BRO_TOKEN_EXPIRATION_SECONDS` -- optional, the access/id token lifetime, default 300 seconds

`OAUTH2_BRO_CODE_RSA_KEY_PEM_FILE` -- optional, key file for the OAuth2 code responses, PEM encoded

`OAUTH2_BRO_CODE_RSA_KEY_ID` -- optional, the key file ID

`OAUTH2_BRO_CODE_EXPIRATION_SECONDS` -- optional, expiration of code response, default 5 seconds

`OAUTH2_BRO_REFRESH_RSA_KEY_PEM_FILE` -- optional, key file for the OAuth2 code responses, PEM encoded

`OAUTH2_BRO_REFRESH_RSA_KEY_ID` -- optional, the key file ID

`OAUTH2_BRO_REFRESH_EXPIRATION_SECONDS` -- optional, expiration of code response, default 10 days in seconds

`OAUTH2_BRO_EMAIL_DOMAIN` -- the domain of email addresses which we create for IP address users

`OAUTH2_BRO_ALLOWED_IP_MASKS` -- optional, comma-separated list of IP address masks in CIDR notation (e.g., "192.168.1.0/24,10.0.0.0/8,2001:db8::/32") to filter which IP addresses are allowed to be processed for user information. Supports both IPv4 and IPv6 masks. If not set or empty, all IP addresses are allowed.

`OAUTH2_BRO_CLIENT_CREDENTIALS` -- optional, the list of clientId and clientSecret in the format like `"client1=secret1,client2=secret2,client3=secret3"`

`OAUTH2_BRO_MAKE_ROOT_SECRET` -- required for Make me Root functionality, the secret used to validate the cookieSecret parameter

`OAUTH2_BRO_PROXY_TARGET` -- enables proxy mode to send generated token for all requests to the given host

Auth Scenarios
-----

We support IDE Services deployments 
 * on-prem, where OAuth2-bro is configured in the YAML configs (TBD)
 * SaaS version, where OAuth2-bro is connected to JetBrains Hub (TBD)

On the client side, we support the following clients, through IDE Services
abstraction
* Toolbox App
* IntelliJ's license dialog
* IDE Services Administration Console 



Keys in Memory
--------------

The OAuth2-bro keeps it's signing keys in memory (please create issue or pull request to support KMS).

Restart of a server means all keys are lost. 

We recommend to collect all public keys from all server replicas,
and pass them to each of the server instances. This way,
you can maintain older keys to run.

Detailed recommendations for deployments will follow. 


Deployment schema
---

That is essential for deployments to keep the list of all server
public keys for tokens. It can be the case, where we still need to
authenticate older JWT tokens. For that we keep the full list of public
keys. 

On practice, we may not need to keep private keys at all, and configure
the server to generate a unique key on every start (or even time after time)

The necessary step -- we should keep all public keys shared between
all replicas of that server. Various backends could be used to share
the public keys


Notice on Security
-------

This server operates with RSA keys to sign JWT tokens. 

We use different keys to sign refresh tokens and access tokens. 

Private keys has to be kept in secret, leaking such keys may make
the whole system vulnerable to attacts and impersonations. Say, 
an attacker could create an admin token themselves. 

Our basic implementation uses on-memory private keys, which are
never exported from the application. For better security, 
we recommend using an external services like KMS or hardware,
which guarantees no access to the private key body.

Endpoints
---

`/` is the information and fallback endpoint

`/health` can be used for monitoring purposes 

`/jwks` provides the JSON Web Key Set (JWKS) containing the public key for token validation

`/login` the OAuth2 / OpenId Connect endpoint to start the login, here the OAuth2-bro makes the login happen automatically without actually showing any pages

`/token` the endpoint to complete the OAuth2 login flow or refresh a token.



Multi-node configuration
-------------

The production setup of OAuth2-bro assumes we have multiple instances of
the service running behind the load balances (which handles HTTPS too)

Ideal configuration of the service is to keep private-keys unique per-instance,
that creates a complexity, because user sessions are not sticky and can start
from one instance and return the the other one. 

There are the following tokens/keys/validations which we are going to maintain
* public keys to sign Access/ID tokens + private key per each node
* public keys to sign Refresh tokens + private key per each node
* public keys to sing the OAuth2 code response + private key per each node

The main undecided yet problem is to understand how a new node will communicate
its fresh-ly generated public keys back to the running nodes. We want to simplify
or even avoid the communication between nodes, and we want to avoid the avalanche
restart of the nodes to update the list of keys. 

One of the possible solutions is to use a common database or KMS service, where all public keys
are registered. 

The other solution is to do something similar to certificates, where
each new key-pair is signed with the common key/certificate allowing to avoid listing
all keys explicitly. That solution requires to have an access to generate signatures
of fresh keys, which can be equivalent of having the actual key in-place


Having these parts unknown, we can still define the following concepts 
* the Access/ID tokens are JWT tokens with JWKs listed keys
* the `code` response to be a JWT token, with 5 seconds lifetime, and
  yet another internal to OAuth2-bro list of accepted public keys. This way it can
  allow any node to handle the code request
* ~~each node remembers requested `code` to allow it working only once. The cache TTL is also included.~~ (not implemented in current version - code tokens can be used multiple times within their lifetime)
* refresh token is yet another JWT token with yet another list of accepted public keys. It is
  up to the service administrator to define the lifetime or presence of the refresh token.
* ~~OAuth2-bro must re-validate that refresh token matches the same network parameters, as
  it was on the moment of the initial login. It means we include encrypted/hashed data in the
  refresh token JWT to use for validation~~ (not implemented in current version - refresh tokens are validated for signature and expiration only)


On the Client ID and Secret
---

The service validates client ID and secret pairs. Client authentication is configured through
the `OAUTH2_BRO_CLIENT_CREDENTIALS` environment variable, which contains a comma-separated list
of clientId=clientSecret pairs.

Example:
```
export OAUTH2_BRO_CLIENT_CREDENTIALS="client1=secret1,client2=secret2,client3=secret3"
```

If this environment variable is not set or is empty, all clients are allowed.

The service validates that the client ID is in the list of supported clients and that
the provided client secret matches the configured secret for that client ID.



Proxy Mode
----

We can implement rule-based authentication, where for some users, it works
implicitly, but for other users it redirects further to the next authentication
service, such as Google or Okta. 

The use case for that can be, say, if we want to authentication N machines in the
local networks with local rules (TBD), and M users from their personal decides. 

So to implement that, the following tweaks has to be implemented
* Allow multiple external JWKs to be merged into the resulting one
* Encode the next chained services in the `code` and refresh token responses


Explicit Tokens
----

Automation scripts at the client side may still need us to generate
valid JWT tokens without following the full authentication flow. 

For this scenario, we need to allow the login or token endpoints (TBD)
to generate and return a token. 

An usage example could go to the [No Login](https://www.jetbrains.com/help/ide-services/no-login-authentication.html)
flow of IDE Services. And to implement that, we also need a utility to
resolve and patch the `machine-config.json` file on the user machine. 


Key Generation
---

It is usually a task to generate a key, public key, certificate. There are
way to many services and tools which can help with that. 

~~To simplify operations, we include the necessary commands directly to the
`oauth2-bro` tool. TBD~~ (not implemented in current version - use external tools for key generation)


Make me Root (Bro mode)
------

In addition to the idea of authentication to proxy to the next service, 
we may implement the more simple one. 

Problem: I want to be an admin, for which my email/sid has to be specified in
the IDE Services configuration. Some may not want to allow admin access based
in IP address only. Or an IP address is not that stable to make as admin access. 

Solution: Create a specialized endpoint and the cookie to make the specific
browser as admin. 

Implementation idea: 
We add additional handler in the `/login` endpoint to get `cookieSecret`, `sid`, `sub`, `name`, and `email` claims,
the implementation of that handle will set the cookie with a refresh-token inside to map to that user. 
The cookie is one-time, and it's removed after the successful login. 

Once the ordinary `/login` handler is executed as a part of usual login flow, we must check for the 
cookie, and if it's set, use the data to proceed. The cookie has to be removed after login. 

Example URL:
```
http://localhost:8085/login?cookieSecret=your-secret&sid=toolbox.admin
```

This will set a cookie in your browser that will be used during the next regular 
login flow to authenticate you as the specified user. After successful login, the 
cookie will be removed.

Security and multi-node note: for this feature to work reliably in a multi-node setup, all nodes that may process the login must use the same signing keys for refresh tokens so that the cookie (which contains a refresh token) can be validated by every node. Ensure that the Refresh keys are shared/synchronized across nodes.

It might be better to supply a signed URL similar to AWS's approach, where cookieSecret
is never the original secret, but a temporary token. TBD.

Make me Root (Proxy mode)
------

In proxy mode, OAuth2-bro supports a Make me Root capability that elevates all requests coming through the proxy as a specific user. This is implemented via a cookie set by a dedicated endpoint.

- Endpoint to set cookie: POST /oauth2-bro/make-root with query parameters cookieSecret, sid, sub, name, email
- Endpoint to clear cookie: POST /oauth2-bro/unmake-root
- The proxy checks every incoming request for the cookie and, if present and valid, forwards the request to the target with the Authorization: Bearer <token-from-cookie> header. If the cookie is absent, the proxy generates a token using the configured user resolver for each request.

Security and multi-node note: for this feature to work reliably in a multi-node setup, all nodes that may process requests must use the same signing keys so that the JWT stored in the cookie (and used by the proxy) can be validated by every node. Ensure that the Token keys set for the proxy are shared/synchronized across nodes.

Example URL to set the cookie:
```
http://localhost:8085/oauth2-bro/make-root?cookieSecret=your-secret&sid=toolbox.admin
```

This will set a cookie in your browser that will be used by the proxy to authorize all subsequent proxied requests as the specified user, until cleared via /oauth2-bro/unmake-root or cookie expiration.

Proxy Mode
---------

It is possible to run OAuth2-bro in proxy mode, in that case,
we implement the same login of user management, but implicitly
with the following flow

```
client ---[request without Authorization]--> OAuth2-bro proxy --[added Authorization]--> target service
```

This setup can be implemented as side-car container and in that case, there is
no need to synchronize token keys, since we keep that container as close as possible
to the actual application container. This works with the assumption that the application
container is not sending the received Authentication header to any other external services.

### OAuth2 Endpoints in Proxy Mode

In proxy mode, OAuth2-bro provides simplified OAuth2 endpoints to maintain compatibility with OAuth2 clients. These endpoints implement a lightweight OAuth2 authorization code flow:

**`/oauth2-bro/login`** - OAuth2 authorization endpoint
- Accepts standard OAuth2 parameters: `response_type`, `client_id`, `redirect_uri`, `state`
- Only supports `response_type=code`
- Authenticates user based on IP address (via userResolver)
- Returns authorization code with proxy-specific prefix: `oauth2-bro-proxy-code-{sid}-{token}`
- Redirects to `redirect_uri` with `code` and `state` parameters

**`/oauth2-bro/token`** - OAuth2 token endpoint
- Accepts form-encoded POST requests with `grant_type`, `code`, `redirect_uri`
- Only supports `grant_type=authorization_code`
- Returns JSON token response with proxy-prefixed tokens:
  - `access_token`: `oauth2-bro-proxy-access-{sid}-{token}`
  - `refresh_token`: `oauth2-bro-proxy-refresh-{sid}-{token}`
  - `token_type`: `Bearer`
  - `expires_in`: token expiration in seconds

**Important Notes:**
- These tokens are **not used for actual authorization** in proxy mode
- The proxy intercepts all requests and replaces any Authorization header with a freshly generated JWT
- The OAuth2 endpoints exist solely to satisfy OAuth2 client expectations
- Token prefixes (`oauth2-bro-proxy-*`) clearly identify these as OAuth2-bro proxy tokens
- This allows OAuth2 clients to complete their flow while the proxy handles actual authentication 


### Prompt:
I want to add the proxy mode to the executable.
It works as the side-car of the orignal server, the base url (host and port) re receive in 
parameters.

The logic is the following:
- read Spec.md to learn more about the system details.
- the server generates access token keys (use the same environment variables)
- the server implements JWKS endpoint under the /oauth2-bro/jwks path
- the server proxies all requests that are coming to it to the target host:port (from environment variables), 
- it removes the Authorization header when proxy and replaces it with a freshly generated access JWT token from generated keys. 
- It should use user module to resolve the user and it should process the make me root token if it's set and not remove the cookie
- Reuse the code as much as you can, start server from the bro-server code, do not create unneeded entities or keys


We use `OAUTH2_BRO_PROXY_TARGET` to enable proxy mode
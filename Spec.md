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

`OAUTH2_BRO_BIND_PORT` (defaults to 8077) -- the server port to bind

`OAUTH2_BRO_BIND_HOST` (defaults to localhost) -- the server bind host address, for production, or Docker use the right network interface(s) to bind

`OAUTH2_BRO_HTTPS_CERT_FILE` -- if set, enabled HTTPS with the certificate, as a file with a PEM encoded certificate

`OAUTH2_BRO_HTTPS_CERT_KEY_FILE`  -- if set, enabled HTTPS with the server key-pair, as a file with a PEM encoded private key

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


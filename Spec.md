OAuth2-bro Specification
----------


The OAuth2 server is working as follows
- every JTW access and ID tokens are JWT
- refresh token is also JWT
- we keep list of public keys for access tokens
- we keep list of public keys for refresh tokens
- the service uses it's main private key for access/id tokens
- the server uses it's another main private key for refresh tokens
- all configuration parameters can be read from the configuration file or environment variables 
- the server lists all token public keys as JWKs
- additionally, we let the server list all refresh tokens as another JWKs
- the server can run HTTPS, given it receives the certificate and private keys to do so (we still recommend terminate HTTPS at a load balancer level)
- the server is built minimalistic to allow wide range of deployments, from docker to kubernetes and cloud providers


HTTP Server
---

`OAUTH2_BRO_ADDR` (defaults to localhost:8077) -- the server address to bind

`OAUTH2_BRO_HTTPS_CERT_FILE` -- if set, enabled HTTPS with the certificate, as file with PEM encoded certificate

`OAUTH2_BRO_HTTPS_CERT_KEY_FILE`  -- if set, enabled HTTPS with the server key-pair, as file with PEM encoded private key


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


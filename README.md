# OAuth2-bro
OAuth2 server implementation with implicit authentication and authorization. 

<img width="20%" alt="OAuth2-bro logo" src="https://github.com/user-attachments/assets/83601875-ba6f-4366-a775-a55e9384222e" />

License
-------

Apache 2.0, see [LICENSE](LICENSE) file in the repository

Why?
----

The main use case for this authentication server is to establish **implicit** authentication of users,
to allow more seamless integration with corporate authentication and authorization systems. 

Eugene is focused on establishing management, security, and governance of AI and Developer Tools at a scale of companies.
His main focus is on [JetBrains IDE Services](https://jetbrains.com/ide-services), and this server is created to
support customers' requests. 

The naming comes from 1984's Big Brother story 

Use Cases
---------

In environments where authentication is not needed or not yet needed. Examples of such environments are
* University classrooms (where computers are still reused by students)
* Remote machines, which are getting popular in remote development scenarios or regulated businesses
* Implicit auth* scenarios
* Integration with corporate-deployed authorization/authentication systems
* Means to authorize machines, instead of humans

The OAuth2-bro server is compatible with the on-premises and the SaaS version of JetBrains IDE Services. 

Eugene believes there are many more use cases for that authentication server, which can be later added. 

Environment Variables
--------------------

OAuth2-bro is configured using environment variables:

### HTTP Server Configuration
- `OAUTH2_BRO_BIND_PORT` - The server port to bind (default: 8077)
- `OAUTH2_BRO_BIND_HOST` - The server bind host address (default: localhost)
- `OAUTH2_BRO_HTTPS_CERT_FILE` - Path to PEM encoded certificate file for HTTPS (optional)
- `OAUTH2_BRO_HTTPS_CERT_KEY_FILE` - Path to PEM encoded private key file for HTTPS (optional)

### Token Configuration

If parameters are not set, the key is generated automatically, it will not work in
multi-node setup

- `OAUTH2_BRO_TOKEN_RSA_KEY_PEM_FILE` - Path to PEM encoded private key file for access tokens (optional)
- `OAUTH2_BRO_TOKEN_RSA_KEY_ID` - Key ID for access tokens (default: public key hash hex)
- `OAUTH2_BRO_TOKEN_EXPIRATION_SECONDS` - Access/ID token lifetime in seconds (default: 300)

- `OAUTH2_BRO_CODE_RSA_KEY_PEM_FILE` - Path to PEM encoded private key file for OAuth2 code responses (optional)
- `OAUTH2_BRO_CODE_RSA_KEY_ID` - Key ID for OAuth2 code responses (default: public key hash hex)
- `OAUTH2_BRO_CODE_EXPIRATION_SECONDS` - Expiration of code response in seconds (default: 5)

- `OAUTH2_BRO_REFRESH_RSA_KEY_PEM_FILE` - Path to PEM encoded private key file for OAuth2 refresh tokens (optional)
- `OAUTH2_BRO_REFRESH_RSA_KEY_ID` - Key ID for refresh tokens (default: public key hash hex)
- `OAUTH2_BRO_REFRESH_EXPIRATION_SECONDS` - Expiration of refresh tokens in seconds (default: 10 days)

### User Configuration
- `OAUTH2_BRO_EMAIL_DOMAIN` - Domain for email addresses created for IP address users, e.g. `ip-127-0-0-1@your-domain`
- `OAUTH2_BRO_ALLOWED_IP_MASKS` - Comma-separated list of IP address masks in CIDR notation
- `OAUTH2_BRO_CLIENT_CREDENTIALS` - List of clientId and clientSecret pairs (format: "client1=secret1,client2=secret2")
- `OAUTH2_BRO_MAKE_ROOT_SECRET` - Secret for Make me Root functionality

Docker Deployment
----------------

OAuth2-bro provides a Dockerfile for easy deployment.
You can use it to run the server locally or in production.

### Building the Docker Image

```bash
cd oauth2-bro
docker build -t oauth2-bro .
```

### Running Locally

```bash
docker run -p 8077:8077 \
  -e OAUTH2_BRO_EMAIL_DOMAIN=example.com \
  -e OAUTH2_BRO_MAKE_ROOT_SECRET=your-secret \
  oauth2-bro
```

### Production Deployment

For production use, you should configure all necessary environment variables:

```bash
docker run -p 8077:8077 \
  -e OAUTH2_BRO_EMAIL_DOMAIN=example.com \
  -e OAUTH2_BRO_MAKE_ROOT_SECRET=your-secret \
  -e OAUTH2_BRO_TOKEN_RSA_KEY_PEM_FILE=/path/to/token-key.pem \
  -e OAUTH2_BRO_REFRESH_RSA_KEY_PEM_FILE=/path/to/refresh-key.pem \
  -e OAUTH2_BRO_CLIENT_CREDENTIALS="client1=secret1,client2=secret2" \
  -v /path/to/keys:/path/to/keys \
  oauth2-bro
```

Multi-node Configuration
-----------------------

OAuth2-bro is designed to be stateless, making it suitable for multi-node deployments.
In a multi-node configuration:

1. All nodes should be configured with the same set of keys as environment variables
2. Each node can operate independently without a shared state
3. Load balancers can distribute requests across nodes without session affinity

Since the application is stateless, given the same keys, a multi-node
configuration is expected to work seamlessly. This allows for horizontal
scaling and high availability.


Make me Root
-----------

The "Make me Root" functionality allows you to authenticate as a specific 
user (typically an admin) instead of using your IP address for authentication.
This is particularly useful in scenarios where:

- You need admin access but don't want to rely on IP-based authentication
- You want to grant temporary admin privileges to specific browsers/sessions
- You need to test admin functionality in development environments
- You're working with IDE Services and need to specify admin users

### How it Works

When you access the special URL with the correct parameters, 
OAuth2-bro sets a cookie in your browser containing a refresh token with 
your specified identity. During the next regular login flow, this cookie 
is detected and used to authenticate you as the specified user instead of 
using your IP address. After successful login, the cookie is removed.

### Example Usage

To set the "Make me Root" cookie, access the following URL:

```
http://localhost:8077/login?cookieSecret=your-secret&sid=toolbox.admin&email=toolbox.admin@example.com
```

Parameters:
- `cookieSecret`: Must match the value set in the `OAUTH2_BRO_MAKE_ROOT_SECRET` environment variable
- `sid`: The subject ID you want to use (e.g., "toolbox.admin")
- `email`: The email address you want to use (e.g., "toolbox.admin@example.com")

After accessing this URL, you'll receive a confirmation message. You can then proceed with 
the normal login flow, and you'll be authenticated as the specified user.

### Security Considerations

- Keep your `OAUTH2_BRO_MAKE_ROOT_SECRET` secure, as anyone with this secret can set themselves as any user
- Use HTTPS in production to protect the cookie and request parameters
- The cookie is set with HttpOnly flag to prevent JavaScript access
- The cookie is limited to the /login path for security


JetBrains IDE Services Integration
-----------------------

OAuth2-bro can be easily integrated with JetBrains IDE Services. See
the `integration-test/ide-services-patch.yaml` file for an example configuration:

```yaml
tbe:
  auth:
    login-url: 'http://mock-auth:8085/login'
    token-url: 'http://mock-auth:8085/token'
    jwt-certs-url: 'http://mock-auth:8085/jwks'
    root-admin-emails:
      - 'toolbox.admin@example.com'
    root-admin-subjects:
      - '123'
```

This configuration tells IDE Services to use OAuth2-bro for authentication by pointing to
its login, token, and JWKs endpoints. Replace `mock-auth` with the
correct domain of OAuth2-bro deployment.

Distribution
------------

We use the Go language to implement the server. We believe it's easier to change/patch the program to
Implement the specific rules directly in the code (AI agents will help you!), compile, and deploy in Docker. 

We provide Docker builds and Docker images to simplify that work. 

Contribution
------------

Let's collect more scenarios and rules in this repository, and let's improve the missing parts of the
OAuth2-bro together. You are absolutely welcome to contribute. For big changes, please start with
an issue and a discussion. 

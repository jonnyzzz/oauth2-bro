# OAuth2-bro Proxy Mode

## Overview

Proxy mode allows OAuth2-bro to act as a side-car proxy that automatically authenticates requests by generating fresh JWT tokens and forwarding them to a target server. This is useful for scenarios where you want to add authentication to existing services without modifying them.

## How It Works

1. **Request Interception**: All incoming requests are intercepted by the proxy
2. **User Resolution**: The proxy resolves user information from the request (IP address, headers, etc.)
3. **Token Generation**: A fresh JWT access token is generated for the resolved user
4. **Header Replacement**: The original Authorization header (if any) is removed and replaced with the fresh token
5. **Request Forwarding**: The request is forwarded to the target server with the new Authorization header

## Features

- **Automatic User Resolution**: Uses the same user resolution logic as the main OAuth2-bro server
- **Make Me Root Support**: Processes "Make me Root" cookies to override user information
- **JWKS Endpoint**: Provides `/oauth2-bro/jwks` endpoint for token validation
- **Request Body Handling**: Properly handles POST requests with bodies
- **Header Preservation**: Preserves all original headers except Authorization

## Usage

### Command Line

```bash
# Start in proxy mode with target server
oauth2-bro --proxy --target http://localhost:8080

# Start in proxy mode with environment variable
export OAUTH2_BRO_PROXY_TARGET=http://localhost:8080
oauth2-bro --proxy
```

### Environment Variables

- `OAUTH2_BRO_PROXY_TARGET`: Target server URL (overrides --target flag)
- All standard OAuth2-bro environment variables for key management and configuration

### Endpoints

- `GET /oauth2-bro/jwks`: JSON Web Key Set for token validation
- `* /*`: All other requests are proxied to the target server

## Example Deployment

### Docker Compose Example

```yaml
version: '3.8'
services:
  target-app:
    image: your-app:latest
    ports:
      - "8080:8080"
  
  oauth2-proxy:
    image: oauth2-bro:latest
    command: ["--proxy", "--target", "http://target-app:8080"]
    ports:
      - "8077:8077"
    environment:
      - OAUTH2_BRO_BIND_HOST=0.0.0.0
      - OAUTH2_BRO_EMAIL_DOMAIN=example.com
      - OAUTH2_BRO_MAKE_ROOT_SECRET=your-secret
    depends_on:
      - target-app
```

### Kubernetes Sidecar Example

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
    spec:
      containers:
      - name: app
        image: your-app:latest
        ports:
        - containerPort: 8080
      - name: oauth2-proxy
        image: oauth2-bro:latest
        command: ["--proxy", "--target", "http://localhost:8080"]
        ports:
        - containerPort: 8077
        env:
        - name: OAUTH2_BRO_BIND_HOST
          value: "0.0.0.0"
        - name: OAUTH2_BRO_EMAIL_DOMAIN
          value: "example.com"
```

## Testing

Use the provided test script to verify proxy functionality:

```bash
# Start target server
python3 -m http.server 8080 &

# Start proxy
oauth2-bro --proxy --target http://localhost:8080 &

# Run tests
./test-proxy.sh
```

## Security Considerations

- The proxy generates fresh tokens for each request
- Original Authorization headers are always removed and replaced
- User resolution follows the same security rules as the main server
- IP filtering and other security features are preserved
- Make me Root functionality is supported for administrative access

## Troubleshooting

### Common Issues

1. **Target server unreachable**: Check the target URL and network connectivity
2. **User resolution fails**: Verify IP address configuration and allowed IP masks
3. **Token generation fails**: Check key configuration and environment variables

### Logs

The proxy logs all requests with the prefix "proxy request" for easy identification:

```
2025/08/01 19:13:39 proxy request /oauth2-bro/jwks
2025/08/01 19:13:39 proxy request /
``` 
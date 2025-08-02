# 🔐 Nginx JWT Proxy

Ultra-simple JWT proxy that automatically generates tokens for all requests and provides JWKS endpoint for backend verification.

## 🚀 Quick Start

```bash
# 1. Generate keys and configuration
./setup.sh

# 2. Deploy with Docker
docker-compose up -d

# 3. Verify everything works
./verify.sh
```

## 🎯 What It Does

- **Removes client authentication** - clients make regular HTTP requests
- **Generates JWT tokens** automatically based on client IP + User-Agent
- **Injects Authorization header** to backend requests
- **Provides JWKS endpoint** at `/.well-known/jwks.json`
- **Backend thinks requests are authenticated** - no login flows triggered

## 📁 Generated Files

After running `setup.sh`:

```
├── nginx.conf                 # Nginx configuration
├── jwks.json                 # Static JWKS file  
├── lua/
│   └── simple_jwt_generator.lua  # JWT generation script
├── docker-compose.yml        # Docker deployment
└── verify.sh                # Verification script
```

## 🔧 Configuration

Environment variables (optional):

```bash
BACKEND_HOST=your-backend     # Default: backend-app
BACKEND_PORT=8080            # Default: 8080
JWT_EXPIRY=3600             # Token expiry in seconds
JWT_ISSUER=nginx-jwt-proxy  # JWT issuer claim
JWT_AUDIENCE=internal-app   # JWT audience claim
```

## 🌐 Endpoints

- **Main Proxy**: `http://localhost/` - All requests get JWT tokens
- **JWKS**: `http://localhost/.well-known/jwks.json` - For backend verification
- **Health**: `http://localhost/health` - Health check

## 🔑 Backend Integration

Your backend needs to:

1. **Verify JWT tokens** using the JWKS endpoint
2. **Trust issuer**: `nginx-jwt-proxy`
3. **Expect audience**: `internal-app`
4. **Use the JWT secret** printed by setup script

See `examples/backend-config-examples.js` for implementation examples in Node.js, Python, Java, and Go.


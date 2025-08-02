#!/bin/bash
# setup.sh - Simple JWT proxy setup with automatic key generation

set -e

# Configuration
BACKEND_HOST="${BACKEND_HOST:-backend-app}"
BACKEND_PORT="${BACKEND_PORT:-8080}"
JWT_EXPIRY="${JWT_EXPIRY:-3600}"
JWT_ISSUER="${JWT_ISSUER:-nginx-jwt-proxy}"
JWT_AUDIENCE="${JWT_AUDIENCE:-internal-app}"
ALGORITHM="${ALGORITHM:-HS256}"

echo "🚀 Setting up JWT Proxy..."

# Create directories
mkdir -p lua examples

# Generate JWT secret and key ID
echo "🔐 Generating JWT secret and key..."
JWT_SECRET=$(openssl rand -base64 32)
KEY_ID="jwt-key-$(date +%s)"

echo "Generated JWT Secret: $JWT_SECRET"
echo "Key ID: $KEY_ID"

# Create JWKS file
echo "📝 Creating JWKS file..."
cat > jwks.json << EOF
{
  "keys": [
    {
      "kty": "oct",
      "kid": "$KEY_ID",
      "use": "sig",
      "alg": "$ALGORITHM"
    }
  ]
}
EOF

# Create Lua script from template
echo "🔧 Creating Lua script..."
sed "s/{{JWT_SECRET}}/$JWT_SECRET/g; \
     s/{{JWT_ALGORITHM}}/$ALGORITHM/g; \
     s/{{JWT_EXPIRY}}/$JWT_EXPIRY/g; \
     s/{{JWT_ISSUER}}/$JWT_ISSUER/g; \
     s/{{JWT_AUDIENCE}}/$JWT_AUDIENCE/g; \
     s/{{KEY_ID}}/$KEY_ID/g" lua/simple_jwt_generator.lua.template > lua/simple_jwt_generator.lua

# Create Nginx config from template
echo "📄 Creating Nginx configuration..."
sed "s/{{BACKEND_HOST}}/$BACKEND_HOST/g; \
     s/{{BACKEND_PORT}}/$BACKEND_PORT/g" nginx.conf.template > nginx.conf

# Create Docker Compose file from template
echo "🐳 Creating Docker Compose file..."
cp docker-compose.yml.template docker-compose.yml

# Create verification script
echo "🧪 Creating verification script..."
cat > verify.sh << 'EOF'
#!/bin/bash
echo "🔍 Verifying JWT Proxy setup..."

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 5

# Test health endpoint
echo "Testing health endpoint..."
if curl -s http://localhost/health | grep -q "OK"; then
    echo "✅ Health check passed"
else
    echo "❌ Health check failed"
    exit 1
fi

# Test JWKS endpoint
echo "Testing JWKS endpoint..."
if curl -s http://localhost/.well-known/jwks.json | grep -q "keys"; then
    echo "✅ JWKS endpoint working"
else
    echo "❌ JWKS endpoint failed"
    exit 1
fi

# Test JWT generation and proxy
echo "Testing JWT generation..."
response=$(curl -sI http://localhost/test 2>/dev/null | head -1)
if echo "$response" | grep -q "200\|404"; then
    echo "✅ JWT proxy is working"
    echo "🎯 Backend should receive Authorization: Bearer <jwt-token>"
else
    echo "❌ JWT proxy test failed"
    echo "Response: $response"
    exit 1
fi

echo ""
echo "🎉 All tests passed!"
echo "🌐 Your proxy is ready at: http://localhost"
echo "🔑 JWKS endpoint: http://localhost/.well-known/jwks.json"
echo ""
echo "💡 Next steps:"
echo "1. Replace the backend-app service in docker-compose.yml with your actual application"
echo "2. Configure your backend to verify JWT tokens using the JWKS endpoint"
echo "3. Use the JWT secret for verification (see examples/ directory)"
EOF

chmod +x verify.sh

# Copy backend examples
echo "📚 Creating backend integration examples..."
cp examples/backend-config-examples.js examples/

# Create environment file for easy configuration
cat > .env << EOF
# JWT Proxy Configuration
JWT_SECRET=$JWT_SECRET
KEY_ID=$KEY_ID
BACKEND_HOST=$BACKEND_HOST
BACKEND_PORT=$BACKEND_PORT
JWT_EXPIRY=$JWT_EXPIRY
JWT_ISSUER=$JWT_ISSUER
JWT_AUDIENCE=$JWT_AUDIENCE
EOF

echo ""
echo "✅ Setup complete!"
echo ""
echo "🔑 Your JWT Secret: $JWT_SECRET"
echo "🆔 Key ID: $KEY_ID"
echo ""
echo "📁 Files created:"
echo "  - nginx.conf (Nginx configuration)"
echo "  - jwks.json (JWKS endpoint data)"
echo "  - lua/simple_jwt_generator.lua (JWT generation script)"
echo "  - docker-compose.yml (Docker deployment)"
echo "  - verify.sh (Verification script)"
echo "  - .env (Environment configuration)"
echo "  - examples/ (Backend integration examples)"
echo ""
echo "🚀 To start:"
echo "  docker-compose up -d"
echo ""
echo "🧪 To verify:"
echo "  ./verify.sh"

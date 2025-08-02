// backend-config-examples.js
// Examples of how to configure your backend to verify JWT tokens

// ================================
// Node.js with Express Example
// ================================
const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();

// Your JWT secret (from setup.sh output)
const JWT_SECRET = 'your-jwt-secret-from-setup-script';

// JWT verification middleware
function verifyJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  const token = authHeader.substring(7);
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      audience: 'internal-app',
      issuer: 'nginx-jwt-proxy',
      algorithms: ['HS256']
    });
    
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token', details: err.message });
  }
}

// Protected route
app.get('/api/protected', verifyJWT, (req, res) => {
  res.json({
    message: 'Access granted!',
    user_id: req.user.sub,
    client_ip: req.user.client_ip,
    user_agent: req.user.user_agent,
    token_issued_at: new Date(req.user.iat * 1000),
    token_expires_at: new Date(req.user.exp * 1000)
  });
});

app.listen(8080, () => {
  console.log('Backend server running on port 8080');
});

// ================================
// Python Flask Example
// ================================
/*
from flask import Flask, request, jsonify
import jwt
from functools import wraps
from datetime import datetime

app = Flask(__name__)

# Your JWT secret (from setup.sh output)
JWT_SECRET = "your-jwt-secret-from-setup-script"

def verify_jwt(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'No token provided'}), 401
        
        token = auth_header[7:]  # Remove 'Bearer '
        
        try:
            payload = jwt.decode(
                token, 
                JWT_SECRET, 
                algorithms=['HS256'],
                audience='internal-app',
                issuer='nginx-jwt-proxy'
            )
            request.user = payload
            return f(*args, **kwargs)
        except jwt.InvalidTokenError as e:
            return jsonify({'error': 'Invalid token', 'details': str(e)}), 401
    
    return decorated

@app.route('/api/protected')
@verify_jwt
def protected_route():
    return jsonify({
        'message': 'Access granted!',
        'user_id': request.user['sub'],
        'client_ip': request.user['client_ip'],
        'user_agent': request.user['user_agent'],
        'token_issued_at': datetime.fromtimestamp(request.user['iat']).isoformat(),
        'token_expires_at': datetime.fromtimestamp(request.user['exp']).isoformat()
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
*/

// ================================
// Go Example
// ================================
/*
package main

import (
    "encoding/json"
    "net/http"
    "strings"
    "time"
    "github.com/golang-jwt/jwt/v4"
)

var jwtSecret = []byte("your-jwt-secret-from-setup-script")

type Claims struct {
    ClientIP  string `json:"client_ip"`
    UserAgent string `json:"user_agent"`
    jwt.RegisteredClaims
}

func verifyJWT(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        
        if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
            http.Error(w, "No token provided", http.StatusUnauthorized)
            return
        }
        
        tokenString := authHeader[7:] // Remove "Bearer "
        
        token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
            return jwtSecret, nil
        })

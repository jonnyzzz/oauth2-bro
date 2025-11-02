package bro_proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"jonnyzzz.com/oauth2-bro/keymanager"

	"jonnyzzz.com/oauth2-bro/user"
)

func TestProxyServer_JWKS(t *testing.T) {
	// Create test dependencies
	keyManager := keymanager.NewKeyManager()
	userManager := user.NewUserResolver()

	mux := http.NewServeMux()
	SetupServer(ServerConfig{
		KeyManager:   *keyManager,
		UserResolver: userManager,
		Version:      "test",
		TargetUrl:    "http://localhost:8080",
	}, mux)

	// Create test request
	req := httptest.NewRequest("GET", "/oauth2-bro/jwks", nil)
	w := httptest.NewRecorder()

	// Call the handler
	mux.ServeHTTP(w, req)

	// Check response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Check content type
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/jwk+json;charset=utf-8" {
		t.Errorf("Expected Content-Type application/jwk+json;charset=utf-8, got %s", contentType)
	}

	// Parse JWKS response
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Use string `json:"use"`
			Alg string `json:"alg"`
		} `json:"keys"`
	}

	if err := json.Unmarshal(w.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("Failed to parse JWKS response: %v", err)
	}

	if len(jwks.Keys) != 1 {
		t.Errorf("Expected 1 key, got %d", len(jwks.Keys))
	}

	if jwks.Keys[0].Kty != "RSA" {
		t.Errorf("Expected key type RSA, got %s", jwks.Keys[0].Kty)
	}

	if jwks.Keys[0].Use != "sig" {
		t.Errorf("Expected key use sig, got %s", jwks.Keys[0].Use)
	}

	if jwks.Keys[0].Alg != "RS512" {
		t.Errorf("Expected algorithm RS512, got %s", jwks.Keys[0].Alg)
	}
}

func TestProxyServer_ProxyHandler(t *testing.T) {
	// Create a test target server
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if Authorization header is present and has Bearer token
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			t.Error("Expected Authorization header to be present")
			http.Error(w, "No Authorization header", http.StatusUnauthorized)
			return
		}

		if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
			t.Errorf("Expected Bearer token, got: %s", authHeader)
			http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
			return
		}

		// Check if original Authorization header was removed
		if r.Header.Get("X-Original-Authorization") != "" {
			t.Error("Original Authorization header should have been removed")
		}

		// Return success with request info
		w.Header().Set("Content-Type", "application/json")
		response := map[string]string{
			"path":    r.URL.Path,
			"method":  r.Method,
			"auth":    authHeader,
			"success": "true",
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer targetServer.Close()

	// Create test dependencies
	keyManager := keymanager.NewKeyManager()
	userManager := user.NewUserResolver()

	mux := http.NewServeMux()
	SetupServer(ServerConfig{
		KeyManager:   *keyManager,
		UserResolver: userManager,
		Version:      "test",
		TargetUrl:    targetServer.URL,
	}, mux)

	// Test cases
	testCases := []struct {
		name           string
		method         string
		path           string
		headers        map[string]string
		body           string
		expectedStatus int
	}{
		{
			name:           "GET request without Authorization header",
			method:         "GET",
			path:           "/test",
			headers:        map[string]string{},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "GET request with Authorization header (should be replaced)",
			method: "GET",
			path:   "/test",
			headers: map[string]string{
				"Authorization": "Bearer old-token",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "POST request with body",
			method: "POST",
			path:   "/test",
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			body:           `{"test": "data"}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:   "Request with X-Forwarded-For header",
			method: "GET",
			path:   "/test",
			headers: map[string]string{
				"X-Forwarded-For": "192.168.1.100",
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create request
			var body io.Reader
			if tc.body != "" {
				body = bytes.NewReader([]byte(tc.body))
			}

			req := httptest.NewRequest(tc.method, tc.path, body)
			w := httptest.NewRecorder()

			// Add headers
			for key, value := range tc.headers {
				req.Header.Set(key, value)
			}

			// Call the handler
			mux.ServeHTTP(w, req)

			// Check status
			if w.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d", tc.expectedStatus, w.Code)
			}

			// For successful requests, check the response
			if w.Code == http.StatusOK {
				var response map[string]interface{}
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}

				if response["success"] != "true" {
					t.Errorf("Expected success=true, got %v", response["success"])
				}

				if response["path"] != tc.path {
					t.Errorf("Expected path %s, got %s", tc.path, response["path"])
				}

				if response["method"] != tc.method {
					t.Errorf("Expected method %s, got %s", tc.method, response["method"])
				}

				// Check that a new Bearer token was generated
				auth, ok := response["auth"].(string)
				if !ok {
					t.Error("Expected auth field in response")
				} else if len(auth) < 7 || auth[:7] != "Bearer " {
					t.Errorf("Expected Bearer token, got: %s", auth)
				}
			}
		})
	}
}

func TestProxyServer_ProxyHandler_ErrorCases(t *testing.T) {
	// Create test dependencies
	keyManager := keymanager.NewKeyManager()
	userManager := user.NewUserResolver()

	mux := http.NewServeMux()
	SetupServer(ServerConfig{
		KeyManager:   *keyManager,
		UserResolver: userManager,
		Version:      "test",
		TargetUrl:    "invalid-url",
	}, mux)

	// Test invalid target URL
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected status 502 for invalid target URL, got %d", w.Code)
	}
}

func TestProxyServer_ProxyHandler_UserResolution(t *testing.T) {
	// Create a test target server
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Just return success
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	}))
	defer targetServer.Close()

	// Create test dependencies
	keyManager := keymanager.NewKeyManager()
	userManager := user.NewUserResolver()

	mux := http.NewServeMux()
	SetupServer(ServerConfig{
		KeyManager:   *keyManager,
		UserResolver: userManager,
		Version:      "test",
		TargetUrl:    targetServer.URL,
	}, mux)

	// Test user resolution with different IP headers
	testCases := []struct {
		name           string
		headers        map[string]string
		expectedStatus int
	}{
		{
			name:           "No IP headers (should use RemoteAddr)",
			headers:        map[string]string{},
			expectedStatus: http.StatusOK,
		},
		{
			name: "X-Forwarded-For header",
			headers: map[string]string{
				"X-Forwarded-For": "10.0.0.1",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "X-Real-IP header",
			headers: map[string]string{
				"X-Real-IP": "192.168.1.1",
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()

			// Add headers
			for key, value := range tc.headers {
				req.Header.Set(key, value)
			}

			// Call the handler
			mux.ServeHTTP(w, req)

			// Check status
			if w.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d", tc.expectedStatus, w.Code)
			}
		})
	}
}

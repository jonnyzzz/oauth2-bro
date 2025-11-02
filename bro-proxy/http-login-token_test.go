package bro_proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	bsc "jonnyzzz.com/oauth2-bro/bro-server-common"
	"jonnyzzz.com/oauth2-bro/client"
	"jonnyzzz.com/oauth2-bro/keymanager"
	"jonnyzzz.com/oauth2-bro/user"
)

// TestOAuth2CodeFlow tests the complete OAuth2 authorization code flow in proxy mode
func TestOAuth2CodeFlow(t *testing.T) {
	// Create test dependencies
	keyManager := keymanager.NewKeyManager()
	userManager := user.NewUserResolver()
	clientManager := client.NewClientManager()

	mux := http.NewServeMux()
	SetupServer(ServerConfig{
		KeyManager:         *keyManager,
		UserResolver:       userManager,
		ClientInfoProvider: clientManager,
		Version:            "test",
		TargetUrl:          "http://localhost:8080",
	}, mux)

	// Step 1: Initiate OAuth2 authorization request
	authReq := httptest.NewRequest("GET", "/oauth2-bro/login?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&state=test-state", nil)
	authReq.Header.Set("X-Forwarded-For", "192.168.1.100")
	authW := httptest.NewRecorder()

	mux.ServeHTTP(authW, authReq)

	// Should redirect with authorization code
	if authW.Code != http.StatusFound {
		t.Fatalf("Expected status 302, got %d. Body: %s", authW.Code, authW.Body.String())
	}

	location := authW.Header().Get("Location")
	if location == "" {
		t.Fatal("Expected Location header to be set")
	}

	// Parse redirect URL to extract authorization code
	redirectUrl, err := url.Parse(location)
	if err != nil {
		t.Fatalf("Failed to parse redirect URL: %v", err)
	}

	code := redirectUrl.Query().Get("code")
	if code == "" {
		t.Fatal("Expected authorization code in redirect URL")
	}

	state := redirectUrl.Query().Get("state")
	if state != "test-state" {
		t.Errorf("Expected state=test-state, got %s", state)
	}

	t.Logf("Authorization code received: %s", code)

	// Step 2: Exchange authorization code for tokens
	formData := url.Values{}
	formData.Set("grant_type", "authorization_code")
	formData.Set("code", code)
	formData.Set("client_id", "test-client")
	formData.Set("client_secret", "test-secret")

	tokenReq := httptest.NewRequest("POST", "/oauth2-bro/token", strings.NewReader(formData.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenW := httptest.NewRecorder()

	mux.ServeHTTP(tokenW, tokenReq)

	if tokenW.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d. Body: %s", tokenW.Code, tokenW.Body.String())
	}

	// Parse token response
	var tokenResp bsc.TokenResponse
	if err := json.Unmarshal(tokenW.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("Failed to parse token response: %v", err)
	}

	// Validate response fields
	if tokenResp.AccessToken == "" {
		t.Error("Expected access_token in response")
	}
	if tokenResp.IdToken == "" {
		t.Error("Expected id_token in response")
	}
	if tokenResp.RefreshToken == "" {
		t.Error("Expected refresh_token in response")
	}
	if tokenResp.TokenType != "Bearer" {
		t.Errorf("Expected token_type=Bearer, got %s", tokenResp.TokenType)
	}
	if tokenResp.ExpiresIn <= 0 {
		t.Errorf("Expected expires_in > 0, got %d", tokenResp.ExpiresIn)
	}

	// Validate that tokens are JWTs (basic check - should have 3 parts)
	if len(strings.Split(tokenResp.AccessToken, ".")) != 3 {
		t.Error("Access token is not a valid JWT format (expected 3 parts)")
	}
	if len(strings.Split(tokenResp.IdToken, ".")) != 3 {
		t.Error("ID token is not a valid JWT format (expected 3 parts)")
	}

	t.Logf("Access token received: %s...", tokenResp.AccessToken[:50])

	// Step 3: Use refresh token to get new access token
	refreshFormData := url.Values{}
	refreshFormData.Set("grant_type", "refresh_token")
	refreshFormData.Set("refresh_token", tokenResp.RefreshToken)
	refreshFormData.Set("client_id", "test-client")
	refreshFormData.Set("client_secret", "test-secret")

	refreshReq := httptest.NewRequest("POST", "/oauth2-bro/token", strings.NewReader(refreshFormData.Encode()))
	refreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshW := httptest.NewRecorder()

	mux.ServeHTTP(refreshW, refreshReq)

	if refreshW.Code != http.StatusOK {
		t.Fatalf("Expected status 200 for refresh, got %d. Body: %s", refreshW.Code, refreshW.Body.String())
	}

	// Parse refresh response
	var refreshResp bsc.TokenResponse
	if err := json.Unmarshal(refreshW.Body.Bytes(), &refreshResp); err != nil {
		t.Fatalf("Failed to parse refresh response: %v", err)
	}

	if refreshResp.AccessToken == "" {
		t.Error("Expected new access_token from refresh")
	}
	if refreshResp.RefreshToken == "" {
		t.Error("Expected new refresh_token from refresh")
	}

	t.Logf("Refreshed access token received: %s...", refreshResp.AccessToken[:50])
}

func TestProxyLogin_ParameterValidation(t *testing.T) {
	keyManager := keymanager.NewKeyManager()
	userManager := user.NewUserResolver()
	clientManager := client.NewClientManager()

	mux := http.NewServeMux()
	SetupServer(ServerConfig{
		KeyManager:         *keyManager,
		UserResolver:       userManager,
		ClientInfoProvider: clientManager,
		Version:            "test",
		TargetUrl:          "http://localhost:8080",
	}, mux)

	testCases := []struct {
		name           string
		queryParams    string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "valid request",
			queryParams:    "response_type=code&client_id=test-client&redirect_uri=http://localhost/callback",
			expectedStatus: http.StatusFound,
		},
		{
			name:           "missing response_type",
			queryParams:    "client_id=test-client&redirect_uri=http://localhost/callback",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "response_type",
		},
		{
			name:           "invalid response_type",
			queryParams:    "response_type=token&client_id=test-client&redirect_uri=http://localhost/callback",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "response_type",
		},
		{
			name:           "missing client_id",
			queryParams:    "response_type=code&redirect_uri=http://localhost/callback",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "client_id",
		},
		{
			name:           "missing redirect_uri",
			queryParams:    "response_type=code&client_id=test-client",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "redirect_uri",
		},
		{
			name:           "invalid redirect_uri",
			queryParams:    "response_type=code&client_id=test-client&redirect_uri=::invalid::",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "redirect_uri",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/oauth2-bro/login?"+tc.queryParams, nil)
			req.Header.Set("X-Forwarded-For", "192.168.1.100")
			w := httptest.NewRecorder()

			mux.ServeHTTP(w, req)

			if w.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tc.expectedStatus, w.Code, w.Body.String())
			}

			if tc.expectedError != "" && !strings.Contains(w.Body.String(), tc.expectedError) {
				t.Errorf("Expected error containing '%s', got: %s", tc.expectedError, w.Body.String())
			}
		})
	}
}

func TestProxyToken_AuthorizationCodeGrant(t *testing.T) {
	keyManager := keymanager.NewKeyManager()
	userManager := user.NewUserResolver()
	clientManager := client.NewClientManager()

	mux := http.NewServeMux()
	SetupServer(ServerConfig{
		KeyManager:         *keyManager,
		UserResolver:       userManager,
		ClientInfoProvider: clientManager,
		Version:            "test",
		TargetUrl:          "http://localhost:8080",
	}, mux)

	// First, get a valid authorization code
	authReq := httptest.NewRequest("GET", "/oauth2-bro/login?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback", nil)
	authReq.Header.Set("X-Forwarded-For", "192.168.1.100")
	authW := httptest.NewRecorder()
	mux.ServeHTTP(authW, authReq)

	location := authW.Header().Get("Location")
	redirectUrl, _ := url.Parse(location)
	code := redirectUrl.Query().Get("code")

	testCases := []struct {
		name           string
		formData       map[string]string
		expectedStatus int
		expectedError  string
	}{
		{
			name: "valid authorization code exchange",
			formData: map[string]string{
				"grant_type":    "authorization_code",
				"code":          code,
				"client_id":     "test-client",
				"client_secret": "test-secret",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "missing code",
			formData: map[string]string{
				"grant_type":    "authorization_code",
				"client_id":     "test-client",
				"client_secret": "test-secret",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "code parameter is required",
		},
		{
			name: "invalid code",
			formData: map[string]string{
				"grant_type":    "authorization_code",
				"code":          "invalid-code-12345",
				"client_id":     "test-client",
				"client_secret": "test-secret",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Failed to validate code token",
		},
		{
			name: "missing client credentials",
			formData: map[string]string{
				"grant_type": "authorization_code",
				"code":       code,
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "client_id and client_secret parameters are required",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			formData := url.Values{}
			for key, value := range tc.formData {
				formData.Set(key, value)
			}

			req := httptest.NewRequest("POST", "/oauth2-bro/token", strings.NewReader(formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			mux.ServeHTTP(w, req)

			if w.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tc.expectedStatus, w.Code, w.Body.String())
			}

			if tc.expectedError != "" && !strings.Contains(w.Body.String(), tc.expectedError) {
				t.Errorf("Expected error containing '%s', got: %s", tc.expectedError, w.Body.String())
			}

			if tc.expectedStatus == http.StatusOK {
				var tokenResp bsc.TokenResponse
				if err := json.Unmarshal(w.Body.Bytes(), &tokenResp); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}

				if tokenResp.AccessToken == "" {
					t.Error("Expected access_token in response")
				}
				if tokenResp.RefreshToken == "" {
					t.Error("Expected refresh_token in response")
				}
			}
		})
	}
}

func TestProxyToken_RefreshTokenGrant(t *testing.T) {
	keyManager := keymanager.NewKeyManager()
	userManager := user.NewUserResolver()
	clientManager := client.NewClientManager()

	mux := http.NewServeMux()
	SetupServer(ServerConfig{
		KeyManager:         *keyManager,
		UserResolver:       userManager,
		ClientInfoProvider: clientManager,
		Version:            "test",
		TargetUrl:          "http://localhost:8080",
	}, mux)

	// Get a valid refresh token first
	testUserInfo := &user.UserInfo{
		Sid:       "test-sid",
		Sub:       "test-sub",
		UserName:  "test-user",
		UserEmail: "test@example.com",
	}
	refreshToken, err := keyManager.RefreshKeys.SignInnerToken(testUserInfo)
	if err != nil {
		t.Fatalf("Failed to create test refresh token: %v", err)
	}

	testCases := []struct {
		name           string
		formData       map[string]string
		expectedStatus int
		expectedError  string
	}{
		{
			name: "valid refresh token",
			formData: map[string]string{
				"grant_type":    "refresh_token",
				"refresh_token": refreshToken,
				"client_id":     "test-client",
				"client_secret": "test-secret",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "invalid refresh token",
			formData: map[string]string{
				"grant_type":    "refresh_token",
				"refresh_token": "invalid-token",
				"client_id":     "test-client",
				"client_secret": "test-secret",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Failed to validate refresh token",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			formData := url.Values{}
			for key, value := range tc.formData {
				formData.Set(key, value)
			}

			req := httptest.NewRequest("POST", "/oauth2-bro/token", strings.NewReader(formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			mux.ServeHTTP(w, req)

			if w.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tc.expectedStatus, w.Code, w.Body.String())
			}

			if tc.expectedError != "" && !strings.Contains(w.Body.String(), tc.expectedError) {
				t.Errorf("Expected error containing '%s', got: %s", tc.expectedError, w.Body.String())
			}

			if tc.expectedStatus == http.StatusOK {
				var tokenResp bsc.TokenResponse
				if err := json.Unmarshal(w.Body.Bytes(), &tokenResp); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}

				if tokenResp.AccessToken == "" {
					t.Error("Expected access_token in response")
				}
				if tokenResp.RefreshToken == "" {
					t.Error("Expected new refresh_token in response")
				}
			}
		})
	}
}

func TestProxyToken_ErrorCases(t *testing.T) {
	keyManager := keymanager.NewKeyManager()
	userManager := user.NewUserResolver()
	clientManager := client.NewClientManager()

	mux := http.NewServeMux()
	SetupServer(ServerConfig{
		KeyManager:         *keyManager,
		UserResolver:       userManager,
		ClientInfoProvider: clientManager,
		Version:            "test",
		TargetUrl:          "http://localhost:8080",
	}, mux)

	testCases := []struct {
		name           string
		method         string
		formData       map[string]string
		expectedStatus int
		expectedError  string
	}{
		{
			name:   "wrong HTTP method",
			method: "GET",
			formData: map[string]string{
				"grant_type": "authorization_code",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Only POST method is supported",
		},
		{
			name:   "unsupported grant_type",
			method: "POST",
			formData: map[string]string{
				"grant_type":    "client_credentials",
				"client_id":     "test-client",
				"client_secret": "test-secret",
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			formData := url.Values{}
			for key, value := range tc.formData {
				formData.Set(key, value)
			}

			var req *http.Request
			if tc.method == "GET" {
				req = httptest.NewRequest("GET", "/oauth2-bro/token?"+formData.Encode(), nil)
			} else {
				req = httptest.NewRequest("POST", "/oauth2-bro/token", strings.NewReader(formData.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}

			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if w.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tc.expectedStatus, w.Code, w.Body.String())
			}

			if tc.expectedError != "" && !strings.Contains(w.Body.String(), tc.expectedError) {
				t.Errorf("Expected error containing '%s', got: %s", tc.expectedError, w.Body.String())
			}
		})
	}
}

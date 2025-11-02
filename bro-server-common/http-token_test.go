package bro_server_common

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"jonnyzzz.com/oauth2-bro/client"
	"jonnyzzz.com/oauth2-bro/keymanager"
	"jonnyzzz.com/oauth2-bro/user"
)

// mockHandleToken implements HandleToken interface for testing
type mockHandleToken struct {
	keyManager         keymanager.KeyManager
	clientInfoProvider client.ClientInfoProvider
}

func (m *mockHandleToken) ClientInfoProvider() client.ClientInfoProvider {
	return m.clientInfoProvider
}

func (m *mockHandleToken) RefreshKeys() keymanager.BroInnerKeys {
	return m.keyManager.RefreshKeys
}

func (m *mockHandleToken) CodeKeys() keymanager.BroInnerKeys {
	return m.keyManager.CodeKeys
}

func (m *mockHandleToken) TokenKeys() keymanager.BroAccessKeys {
	return m.keyManager.TokenKeys
}

// mockClientInfoProviderWithCredentials implements ClientInfoProvider with specific credentials
type mockClientInfoProviderWithCredentials struct {
	credentials map[string]string // clientId -> clientSecret
}

func (m *mockClientInfoProviderWithCredentials) IsClientIdAllowed(clientId string) bool {
	_, exists := m.credentials[clientId]
	return exists
}

func (m *mockClientInfoProviderWithCredentials) IsClientAllowed(clientId, clientSecret string) bool {
	expectedSecret, exists := m.credentials[clientId]
	if !exists {
		return false
	}
	return expectedSecret == clientSecret
}

func TestToken_AuthorizationCodeGrant(t *testing.T) {
	// Create real key manager
	km := keymanager.NewKeyManager()

	handler := &mockHandleToken{
		keyManager:         *km,
		clientInfoProvider: client.NewClientManager(),
	}

	// Create a user and generate a valid code
	userInfo := &user.UserInfo{
		Sid:       "test-sid",
		Sub:       "test-sub",
		UserName:  "test-user",
		UserEmail: "test@example.com",
	}

	code, err := handler.CodeKeys().SignInnerToken(userInfo)
	if err != nil {
		t.Fatalf("Failed to create test code: %v", err)
	}

	t.Run("successful authorization code exchange", func(t *testing.T) {
		formData := url.Values{}
		formData.Set("grant_type", "authorization_code")
		formData.Set("code", code)
		formData.Set("client_id", "test-client")
		formData.Set("client_secret", "test-secret")

		req := httptest.NewRequest("POST", "/token", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		Token(handler, w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
		}

		// Parse response
		var tokenResp TokenResponse
		if err := json.Unmarshal(w.Body.Bytes(), &tokenResp); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
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
	})

	t.Run("missing code parameter", func(t *testing.T) {
		formData := url.Values{}
		formData.Set("grant_type", "authorization_code")
		formData.Set("client_id", "test-client")
		formData.Set("client_secret", "test-secret")

		req := httptest.NewRequest("POST", "/token", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		Token(handler, w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}

		if !strings.Contains(w.Body.String(), "code parameter is required") {
			t.Errorf("Expected error about missing code, got: %s", w.Body.String())
		}
	})

	t.Run("invalid code", func(t *testing.T) {
		formData := url.Values{}
		formData.Set("grant_type", "authorization_code")
		formData.Set("code", "invalid-code-12345")
		formData.Set("client_id", "test-client")
		formData.Set("client_secret", "test-secret")

		req := httptest.NewRequest("POST", "/token", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		Token(handler, w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}

		if !strings.Contains(w.Body.String(), "Failed to validate code token") {
			t.Errorf("Expected error about invalid code, got: %s", w.Body.String())
		}
	})
}

func TestToken_RefreshTokenGrant(t *testing.T) {
	// Create a real key manager
	km := keymanager.NewKeyManager()

	handler := &mockHandleToken{
		keyManager:         *km,
		clientInfoProvider: client.NewClientManager(),
	}

	// Create a user and generate a valid refresh token
	userInfo := &user.UserInfo{
		Sid:       "test-sid",
		Sub:       "test-sub",
		UserName:  "test-user",
		UserEmail: "test@example.com",
	}

	refreshToken, err := handler.RefreshKeys().SignInnerToken(userInfo)
	if err != nil {
		t.Fatalf("Failed to create test refresh token: %v", err)
	}

	t.Run("successful refresh token exchange", func(t *testing.T) {
		formData := url.Values{}
		formData.Set("grant_type", "refresh_token")
		formData.Set("refresh_token", refreshToken)
		formData.Set("client_id", "test-client")
		formData.Set("client_secret", "test-secret")

		req := httptest.NewRequest("POST", "/token", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		Token(handler, w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
		}

		// Parse response
		var tokenResp TokenResponse
		if err := json.Unmarshal(w.Body.Bytes(), &tokenResp); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		// Validate response fields
		if tokenResp.AccessToken == "" {
			t.Error("Expected access_token in response")
		}
		if tokenResp.RefreshToken == "" {
			t.Error("Expected new refresh_token in response")
		}
	})

	t.Run("invalid refresh token", func(t *testing.T) {
		formData := url.Values{}
		formData.Set("grant_type", "refresh_token")
		formData.Set("refresh_token", "invalid-token")
		formData.Set("client_id", "test-client")
		formData.Set("client_secret", "test-secret")

		req := httptest.NewRequest("POST", "/token", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		Token(handler, w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}

		if !strings.Contains(w.Body.String(), "Failed to validate refresh token") {
			t.Errorf("Expected error about invalid refresh token, got: %s", w.Body.String())
		}
	})
}

func TestToken_ClientAuthentication(t *testing.T) {
	// Create real key manager
	km := keymanager.NewKeyManager()

	// Create a user and valid code
	userInfo := &user.UserInfo{
		Sid:       "test-sid",
		Sub:       "test-sub",
		UserName:  "test-user",
		UserEmail: "test@example.com",
	}

	t.Run("missing client credentials", func(t *testing.T) {
		handler := &mockHandleToken{
			keyManager:         *km,
			clientInfoProvider: client.NewClientManager(),
		}

		code, _ := handler.CodeKeys().SignInnerToken(userInfo)

		formData := url.Values{}
		formData.Set("grant_type", "authorization_code")
		formData.Set("code", code)

		req := httptest.NewRequest("POST", "/token", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		Token(handler, w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}

		if !strings.Contains(w.Body.String(), "client_id and client_secret parameters are required") {
			t.Errorf("Expected error about missing credentials, got: %s", w.Body.String())
		}
	})

	t.Run("valid client credentials", func(t *testing.T) {
		// Configure client credentials
		handler := &mockHandleToken{
			keyManager: *km,
			clientInfoProvider: &mockClientInfoProviderWithCredentials{
				credentials: map[string]string{
					"test-client": "test-secret",
				},
			},
		}

		code, _ := handler.CodeKeys().SignInnerToken(userInfo)

		formData := url.Values{}
		formData.Set("grant_type", "authorization_code")
		formData.Set("code", code)
		formData.Set("client_id", "test-client")
		formData.Set("client_secret", "test-secret")

		req := httptest.NewRequest("POST", "/token", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		Token(handler, w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
		}
	})

	t.Run("invalid client credentials", func(t *testing.T) {
		// Configure client credentials - only "test-client" with "test-secret" is valid
		handler := &mockHandleToken{
			keyManager: *km,
			clientInfoProvider: &mockClientInfoProviderWithCredentials{
				credentials: map[string]string{
					"test-client": "test-secret",
				},
			},
		}

		code, _ := handler.CodeKeys().SignInnerToken(userInfo)

		formData := url.Values{}
		formData.Set("grant_type", "authorization_code")
		formData.Set("code", code)
		formData.Set("client_id", "wrong-client")
		formData.Set("client_secret", "wrong-secret")

		req := httptest.NewRequest("POST", "/token", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		Token(handler, w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}

		if !strings.Contains(w.Body.String(), "client_id and client_secret parameters are not allowed") {
			t.Errorf("Expected error about invalid credentials, got: %s", w.Body.String())
		}
	})

	t.Run("invalid client secret", func(t *testing.T) {
		// Configure client credentials - only "test-client" with "test-secret" is valid
		handler := &mockHandleToken{
			keyManager: *km,
			clientInfoProvider: &mockClientInfoProviderWithCredentials{
				credentials: map[string]string{
					"test-client": "test-secret",
				},
			},
		}

		code, _ := handler.CodeKeys().SignInnerToken(userInfo)

		formData := url.Values{}
		formData.Set("grant_type", "authorization_code")
		formData.Set("code", code)
		formData.Set("client_id", "test-client")
		formData.Set("client_secret", "wrong-secret")

		req := httptest.NewRequest("POST", "/token", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		Token(handler, w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}

		if !strings.Contains(w.Body.String(), "client_id and client_secret parameters are not allowed") {
			t.Errorf("Expected error about invalid credentials, got: %s", w.Body.String())
		}
	})
}

func TestToken_ErrorCases(t *testing.T) {
	// Create real key manager
	km := keymanager.NewKeyManager()

	handler := &mockHandleToken{
		keyManager:         *km,
		clientInfoProvider: client.NewClientManager(),
	}

	t.Run("wrong HTTP method", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/token?grant_type=authorization_code&code=test", nil)
		w := httptest.NewRecorder()

		Token(handler, w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}

		if !strings.Contains(w.Body.String(), "Only POST method is supported") {
			t.Errorf("Expected POST method error, got: %s", w.Body.String())
		}
	})

	t.Run("unsupported grant_type", func(t *testing.T) {
		formData := url.Values{}
		formData.Set("grant_type", "client_credentials")
		formData.Set("client_id", "test-client")
		formData.Set("client_secret", "test-secret")

		req := httptest.NewRequest("POST", "/token", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		Token(handler, w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected status 500, got %d", w.Code)
		}
	})

	t.Run("invalid form data", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/token", strings.NewReader("%invalid"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		Token(handler, w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}

		if !strings.Contains(w.Body.String(), "Failed to parse form parameters") {
			t.Errorf("Expected form parse error, got: %s", w.Body.String())
		}
	})
}

func TestToken_ContentType(t *testing.T) {
	// Create real key manager
	km := keymanager.NewKeyManager()

	handler := &mockHandleToken{
		keyManager:         *km,
		clientInfoProvider: client.NewClientManager(),
	}

	// Create a valid code for successful token exchange
	userInfo := &user.UserInfo{
		Sid:       "test-sid",
		Sub:       "test-sub",
		UserName:  "test-user",
		UserEmail: "test@example.com",
	}
	code, _ := handler.CodeKeys().SignInnerToken(userInfo)

	formData := url.Values{}
	formData.Set("grant_type", "authorization_code")
	formData.Set("code", code)
	formData.Set("client_id", "test-client")
	formData.Set("client_secret", "test-secret")

	req := httptest.NewRequest("POST", "/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	Token(handler, w, req)

	// Check that successful response has JSON content type
	contentType := w.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("Expected Content-Type to contain application/json, got: %s", contentType)
	}
}

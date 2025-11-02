package bro_server_common

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"jonnyzzz.com/oauth2-bro/client"
	"jonnyzzz.com/oauth2-bro/keymanager"
	"jonnyzzz.com/oauth2-bro/user"
)

// mockHandleLoginServer implements HandleLoginServer for testing
type mockHandleLoginServer struct {
	clientInfoProvider client.ClientInfoProvider
	codeKeys           keymanager.BroInnerKeys
}

func (m *mockHandleLoginServer) ClientInfoProvider() client.ClientInfoProvider {
	return m.clientInfoProvider
}

func (m *mockHandleLoginServer) CodeKeys() keymanager.BroInnerKeys {
	if m.codeKeys != nil {
		return m.codeKeys
	}
	// Return default keymanager if not specified
	km := keymanager.NewKeyManager()
	return km.CodeKeys
}

// mockClientInfoProvider implements ClientInfoProvider for testing
type mockClientInfoProvider struct {
	allowedClients map[string]bool
}

func (m *mockClientInfoProvider) IsClientIdAllowed(clientId string) bool {
	if m.allowedClients == nil {
		return true // Allow all if not specified
	}
	return m.allowedClients[clientId]
}

func (m *mockClientInfoProvider) IsClientAllowed(clientId, _ string) bool {
	return m.IsClientIdAllowed(clientId)
}

func TestHandleNormalLogin_Success(t *testing.T) {
	t.Run("valid OAuth2 authorization request", func(t *testing.T) {
		server := &mockHandleLoginServer{
			clientInfoProvider: &mockClientInfoProvider{},
		}

		userInfo := &user.UserInfo{
			Sid:       "test-sid",
			Sub:       "test-sub",
			UserName:  "test-user",
			UserEmail: "test@example.com",
		}

		reqURL := "/login?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&state=test-state"
		req := httptest.NewRequest("GET", reqURL, nil)
		w := httptest.NewRecorder()

		HandleNormalLogin(server, w, req, userInfo)

		// Should redirect
		if w.Code != http.StatusFound {
			t.Errorf("Expected status 302, got %d. Body: %s", w.Code, w.Body.String())
		}

		// Check redirect location
		location := w.Header().Get("Location")
		if location == "" {
			t.Fatal("Expected Location header to be set")
		}

		parsedLocation, err := url.Parse(location)
		if err != nil {
			t.Fatalf("Failed to parse redirect location: %v", err)
		}

		// Verify code is in redirect
		code := parsedLocation.Query().Get("code")
		if code == "" {
			t.Error("Expected code parameter in redirect")
		}

		// Verify state is preserved
		state := parsedLocation.Query().Get("state")
		if state != "test-state" {
			t.Errorf("Expected state=test-state, got %s", state)
		}
	})

	t.Run("redirect preserves existing query parameters", func(t *testing.T) {
		server := &mockHandleLoginServer{
			clientInfoProvider: &mockClientInfoProvider{},
		}

		userInfo := &user.UserInfo{
			Sid:       "test-sid",
			Sub:       "test-sub",
			UserName:  "test-user",
			UserEmail: "test@example.com",
		}

		reqURL := "/login?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback?existing=param&state=test-state"
		req := httptest.NewRequest("GET", reqURL, nil)
		w := httptest.NewRecorder()

		HandleNormalLogin(server, w, req, userInfo)

		location := w.Header().Get("Location")
		parsedLocation, err := url.Parse(location)
		if err != nil {
			t.Fatalf("Failed to parse redirect location: %v", err)
		}

		// Verify the existing param is preserved
		existing := parsedLocation.Query().Get("existing")
		if existing != "param" {
			t.Errorf("Expected existing=param, got %s", existing)
		}

		// Verify code and state are added
		code := parsedLocation.Query().Get("code")
		if code == "" {
			t.Error("Expected code to be added")
		}

		state := parsedLocation.Query().Get("state")
		if state != "test-state" {
			t.Errorf("Expected state to be added")
		}
	})
}

func TestHandleNormalLogin_ResponseType(t *testing.T) {
	server := &mockHandleLoginServer{
		clientInfoProvider: &mockClientInfoProvider{},
	}

	userInfo := &user.UserInfo{
		Sid:       "test-sid",
		Sub:       "test-sub",
		UserName:  "test-user",
		UserEmail: "test@example.com",
	}

	testCases := []struct {
		name         string
		responseType string
		shouldError  bool
		errorText    string
	}{
		{
			name:         "valid response_type=code",
			responseType: "code",
			shouldError:  false,
		},
		{
			name:         "invalid response_type=token",
			responseType: "token",
			shouldError:  true,
			errorText:    "response_type parameter is token but 'code' is only supported",
		},
		{
			name:         "missing response_type",
			responseType: "",
			shouldError:  true,
			errorText:    "response_type parameter is  but 'code' is only supported",
		},
		{
			name:         "invalid response_type=implicit",
			responseType: "implicit",
			shouldError:  true,
			errorText:    "response_type parameter is implicit but 'code' is only supported",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqURL := fmt.Sprintf("/login?response_type=%s&client_id=test-client&redirect_uri=http://localhost/callback", tc.responseType)
			req := httptest.NewRequest("GET", reqURL, nil)
			w := httptest.NewRecorder()

			HandleNormalLogin(server, w, req, userInfo)

			if tc.shouldError {
				if w.Code != http.StatusBadRequest {
					t.Errorf("Expected status 400, got %d", w.Code)
				}
				if !strings.Contains(w.Body.String(), tc.errorText) {
					t.Errorf("Expected error text '%s', got: %s", tc.errorText, w.Body.String())
				}
			} else {
				if w.Code != http.StatusFound {
					t.Errorf("Expected status 302, got %d", w.Code)
				}
			}
		})
	}
}

func TestHandleNormalLogin_ClientId(t *testing.T) {
	userInfo := &user.UserInfo{
		Sid:       "test-sid",
		Sub:       "test-sub",
		UserName:  "test-user",
		UserEmail: "test@example.com",
	}

	t.Run("missing client_id", func(t *testing.T) {
		server := &mockHandleLoginServer{
			clientInfoProvider: &mockClientInfoProvider{},
		}

		reqURL := "/login?response_type=code&redirect_uri=http://localhost/callback"
		req := httptest.NewRequest("GET", reqURL, nil)
		w := httptest.NewRecorder()

		HandleNormalLogin(server, w, req, userInfo)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}

		if !strings.Contains(w.Body.String(), "client_id parameter is missing") {
			t.Errorf("Expected error about missing client_id, got: %s", w.Body.String())
		}
	})

	t.Run("disallowed client_id", func(t *testing.T) {
		server := &mockHandleLoginServer{
			clientInfoProvider: &mockClientInfoProvider{
				allowedClients: map[string]bool{
					"allowed-client": true,
				},
			},
		}

		reqURL := "/login?response_type=code&client_id=blocked-client&redirect_uri=http://localhost/callback"
		req := httptest.NewRequest("GET", reqURL, nil)
		w := httptest.NewRecorder()

		HandleNormalLogin(server, w, req, userInfo)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}

		if !strings.Contains(w.Body.String(), "client_id 'blocked-client' parameter is not allowed") {
			t.Errorf("Expected error about disallowed client_id, got: %s", w.Body.String())
		}
	})

	t.Run("allowed client_id", func(t *testing.T) {
		server := &mockHandleLoginServer{
			clientInfoProvider: &mockClientInfoProvider{
				allowedClients: map[string]bool{
					"allowed-client": true,
				},
			},
		}

		reqURL := "/login?response_type=code&client_id=allowed-client&redirect_uri=http://localhost/callback"
		req := httptest.NewRequest("GET", reqURL, nil)
		w := httptest.NewRecorder()

		HandleNormalLogin(server, w, req, userInfo)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status 302 (redirect), got %d. Body: %s", w.Code, w.Body.String())
		}
	})
}

func TestHandleNormalLogin_RedirectUri(t *testing.T) {
	server := &mockHandleLoginServer{
		clientInfoProvider: &mockClientInfoProvider{},
	}

	userInfo := &user.UserInfo{
		Sid:       "test-sid",
		Sub:       "test-sub",
		UserName:  "test-user",
		UserEmail: "test@example.com",
	}

	t.Run("missing redirect_uri", func(t *testing.T) {
		reqURL := "/login?response_type=code&client_id=test-client"
		req := httptest.NewRequest("GET", reqURL, nil)
		w := httptest.NewRecorder()

		HandleNormalLogin(server, w, req, userInfo)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}

		if !strings.Contains(w.Body.String(), "redirect_uri parameter is missing") {
			t.Errorf("Expected error about missing redirect_uri, got: %s", w.Body.String())
		}
	})

	t.Run("invalid redirect_uri URL", func(t *testing.T) {
		reqURL := "/login?response_type=code&client_id=test-client&redirect_uri=::invalid::"
		req := httptest.NewRequest("GET", reqURL, nil)
		w := httptest.NewRecorder()

		HandleNormalLogin(server, w, req, userInfo)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}

		if !strings.Contains(w.Body.String(), "redirect_uri") && !strings.Contains(w.Body.String(), "not a valid URL") {
			t.Errorf("Expected error about invalid redirect_uri, got: %s", w.Body.String())
		}
	})

	t.Run("valid redirect_uri with port", func(t *testing.T) {
		reqURL := "/login?response_type=code&client_id=test-client&redirect_uri=http://localhost:8080/callback"
		req := httptest.NewRequest("GET", reqURL, nil)
		w := httptest.NewRecorder()

		HandleNormalLogin(server, w, req, userInfo)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status 302, got %d. Body: %s", w.Code, w.Body.String())
		}

		location := w.Header().Get("Location")
		if !strings.Contains(location, "localhost:8080") {
			t.Errorf("Expected location to contain localhost:8080, got: %s", location)
		}
	})

	t.Run("valid redirect_uri with https", func(t *testing.T) {
		reqURL := "/login?response_type=code&client_id=test-client&redirect_uri=https://example.com/callback"
		req := httptest.NewRequest("GET", reqURL, nil)
		w := httptest.NewRecorder()

		HandleNormalLogin(server, w, req, userInfo)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status 302, got %d", w.Code)
		}

		location := w.Header().Get("Location")
		if !strings.HasPrefix(location, "https://example.com") {
			t.Errorf("Expected https location, got: %s", location)
		}
	})
}

func TestHandleNormalLogin_State(t *testing.T) {
	server := &mockHandleLoginServer{
		clientInfoProvider: &mockClientInfoProvider{},
	}

	userInfo := &user.UserInfo{
		Sid:       "test-sid",
		Sub:       "test-sub",
		UserName:  "test-user",
		UserEmail: "test@example.com",
	}

	t.Run("state parameter preserved", func(t *testing.T) {
		reqURL := "/login?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&state=my-state-value"
		req := httptest.NewRequest("GET", reqURL, nil)
		w := httptest.NewRecorder()

		HandleNormalLogin(server, w, req, userInfo)

		location := w.Header().Get("Location")
		parsedLocation, _ := url.Parse(location)
		state := parsedLocation.Query().Get("state")

		if state != "my-state-value" {
			t.Errorf("Expected state=my-state-value, got %s", state)
		}
	})

	t.Run("missing state parameter (optional)", func(t *testing.T) {
		reqURL := "/login?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback"
		req := httptest.NewRequest("GET", reqURL, nil)
		w := httptest.NewRecorder()

		HandleNormalLogin(server, w, req, userInfo)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status 302 even without state, got %d", w.Code)
		}

		location := w.Header().Get("Location")
		parsedLocation, _ := url.Parse(location)
		state := parsedLocation.Query().Get("state")

		if state != "" {
			t.Errorf("Expected empty state when not provided, got %s", state)
		}
	})
}

func TestHandleNormalLogin_CodeGeneration(t *testing.T) {
	server := &mockHandleLoginServer{
		clientInfoProvider: &mockClientInfoProvider{},
	}

	t.Run("nil userInfo error", func(t *testing.T) {
		reqURL := "/login?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback"
		req := httptest.NewRequest("GET", reqURL, nil)
		w := httptest.NewRecorder()

		HandleNormalLogin(server, w, req, nil)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}

		if !strings.Contains(w.Body.String(), "Failed to sign code token") {
			t.Errorf("Expected error about code signing, got: %s", w.Body.String())
		}
	})

	t.Run("successful code generation with userInfo", func(t *testing.T) {
		userInfo := &user.UserInfo{
			Sid:       "test-sid",
			Sub:       "test-sub",
			UserName:  "test-user",
			UserEmail: "test@example.com",
		}

		reqURL := "/login?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback"
		req := httptest.NewRequest("GET", reqURL, nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.100")
		w := httptest.NewRecorder()

		HandleNormalLogin(server, w, req, userInfo)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status 302, got %d. Body: %s", w.Code, w.Body.String())
		}

		location := w.Header().Get("Location")
		if location == "" {
			t.Fatal("Expected Location header to be set")
		}

		parsedLocation, _ := url.Parse(location)
		code := parsedLocation.Query().Get("code")
		if code == "" {
			t.Error("Expected code parameter in redirect")
		}
	})
}

package broserver

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/rakutentech/jwk-go/jwk"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"jonnyzzz.com/oauth2-bro/client"
	"jonnyzzz.com/oauth2-bro/keymanager"
	"jonnyzzz.com/oauth2-bro/user"
)

type Keys struct {
	// Keys is an array of JSON web keys.
	Keys []*jwk.JWK `json:"keys"`
}

func TestOAuth2CodeFlow(t *testing.T) {
	// Set up environment for testing
	os.Setenv("OAUTH2_BRO_CLIENT_CREDENTIALS", "tbe-server=bacd3019-c3b9-4b31-98d5-d3c410a1098e")
	defer os.Unsetenv("OAUTH2_BRO_CLIENT_CREDENTIALS")

	// Create key manager for testing
	keyManager := keymanager.NewKeyManager()

	// Create user manager for testing
	userManager := user.NewUserManager()

	// Create client manager for testing
	clientManager := client.NewClientManager()

	// Create server configuration
	config := ServerConfig{
		RefreshKeys:        keyManager.RefreshKeys,
		CodeKeys:           keyManager.CodeKeys,
		TokenKeys:          keyManager.TokenKeys,
		UserManager:        userManager,
		ClientInfoProvider: clientManager,
		UserInfoProvider:   userManager,
		Version:            "test",
	}

	// Create server instance and setup routes on a new mux
	serverInstance := NewServer(config)
	mux := http.NewServeMux()
	serverInstance.setupRoutesOnMux(mux)

	// Create a test server
	server := httptest.NewServer(mux)
	defer server.Close()

	// Test the login endpoint to get a code
	t.Run("Login endpoint", func(t *testing.T) {
		// Create a client with redirect following disabled
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		// Set up the login request parameters
		loginURL := fmt.Sprintf("%s/login?response_type=code&client_id=tbe-server&redirect_uri=%s&state=test-state",
			server.URL, url.QueryEscape(server.URL+"/callback"))

		// Make the request to the login endpoint
		resp, err := client.Get(loginURL)
		if err != nil {
			t.Fatalf("Failed to make request to login endpoint: %v", err)
		}
		defer resp.Body.Close()

		// Check that the response is a redirect
		if resp.StatusCode != http.StatusFound {
			t.Errorf("Expected status code %d, got %d", http.StatusFound, resp.StatusCode)
		}

		// Get the redirect URL
		redirectURL := resp.Header.Get("Location")
		if redirectURL == "" {
			t.Fatalf("No redirect URL in response")
		}

		// Parse the redirect URL to extract the code
		parsedURL, err := url.Parse(redirectURL)
		if err != nil {
			t.Fatalf("Failed to parse redirect URL: %v", err)
		}

		// Extract the code and state from the query parameters
		queryParams := parsedURL.Query()
		code := queryParams.Get("code")
		state := queryParams.Get("state")

		if code == "" {
			t.Fatalf("No code in redirect URL")
		}

		if state != "test-state" {
			t.Errorf("Expected state 'test-state', got '%s'", state)
		}

		// Test the token endpoint with the code
		t.Run("Token endpoint", func(t *testing.T) {
			// Set up the token request parameters
			tokenData := url.Values{}
			tokenData.Set("grant_type", "authorization_code")
			tokenData.Set("client_id", "tbe-server")
			tokenData.Set("client_secret", "bacd3019-c3b9-4b31-98d5-d3c410a1098e") // Using a dummy client secret
			tokenData.Set("code", code)
			tokenData.Set("redirect_uri", server.URL+"/callback")

			// Make the request to the token endpoint
			resp, err := http.PostForm(server.URL+"/token", tokenData)
			if err != nil {
				t.Fatalf("Failed to make request to token endpoint: %v", err)
			}
			defer resp.Body.Close()

			// Check that the response is successful
			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("Expected status code %d, got %d. Response: %s", http.StatusOK, resp.StatusCode, string(body))
			}

			// Parse the response body
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Failed to read response body: %v", err)
			}

			var tokenResponse TokenResponse
			err = json.Unmarshal(body, &tokenResponse)
			if err != nil {
				t.Fatalf("Failed to parse token response: %v", err)
			}

			// Dump the response JSON as part of the test
			prettyJSON, err := json.MarshalIndent(tokenResponse, "", "  ")
			if err != nil {
				t.Fatalf("Failed to marshal token response to pretty JSON: %v", err)
			}
			t.Logf("Token Response JSON:\n%s", string(prettyJSON))

			// Fetch JWKS data from the server
			jwksResp, err := http.Get(server.URL + "/jwks")
			if err != nil {
				t.Fatalf("Failed to fetch JWKS data: %v", err)
			}
			defer jwksResp.Body.Close()

			jwksBody, err := io.ReadAll(jwksResp.Body)
			if err != nil {
				t.Fatalf("Failed to read JWKS response body: %v", err)
			}

			// Parse JWKS data
			var keys Keys
			err = json.Unmarshal(jwksBody, &keys)
			if err != nil {
				t.Fatalf("Failed to parse JWKS data: %v", err)
			}

			if len(keys.Keys) == 0 {
				t.Fatal("No keys found in JWKS data")
			}

			// Extract public key from JWKS
			key := keys.Keys[0]
			keySpec, err := key.ParseKeySpec()
			if err != nil {
				t.Fatalf("Failed to parse key spec from JWK: %v", err)
			}

			rsaPublicKey, ok := keySpec.Key.(*rsa.PublicKey)
			if !ok {
				t.Fatal("Failed to cast public key to RSA public key")
			}

			// Validate ID token
			idToken, err := jwt.Parse(tokenResponse.IdToken, func(token *jwt.Token) (interface{}, error) {
				// Validate signing method
				if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return rsaPublicKey, nil
			})
			if err != nil {
				t.Fatalf("Failed to validate ID token: %v", err)
			}
			if !idToken.Valid {
				t.Error("ID token is not valid")
			}
			t.Logf("ID token validated successfully")

			// Validate access token (same as ID token in this implementation)
			accessToken, err := jwt.Parse(tokenResponse.AccessToken, func(token *jwt.Token) (interface{}, error) {
				// Validate signing method
				if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return rsaPublicKey, nil
			})
			if err != nil {
				t.Fatalf("Failed to validate access token: %v", err)
			}
			if !accessToken.Valid {
				t.Error("Access token is not valid")
			}
			t.Logf("Access token validated successfully")

			// Test refresh token flow
			t.Run("Refresh token flow", func(t *testing.T) {
				// Set up the refresh token request parameters
				refreshData := url.Values{}
				refreshData.Set("grant_type", "refresh_token")
				refreshData.Set("client_id", "tbe-server")
				refreshData.Set("client_secret", "bacd3019-c3b9-4b31-98d5-d3c410a1098e")
				refreshData.Set("refresh_token", tokenResponse.RefreshToken)

				// Make the request to the token endpoint
				refreshResp, err := http.PostForm(server.URL+"/token", refreshData)
				if err != nil {
					t.Fatalf("Failed to make request to token endpoint with refresh token: %v", err)
				}
				defer refreshResp.Body.Close()

				// Check that the response is successful
				if refreshResp.StatusCode != http.StatusOK {
					body, _ := io.ReadAll(refreshResp.Body)
					t.Fatalf("Expected status code %d, got %d. Response: %s", http.StatusOK, refreshResp.StatusCode, string(body))
				}

				// Parse the response body
				refreshBody, err := io.ReadAll(refreshResp.Body)
				if err != nil {
					t.Fatalf("Failed to read refresh response body: %v", err)
				}

				var refreshTokenResponse TokenResponse
				err = json.Unmarshal(refreshBody, &refreshTokenResponse)
				if err != nil {
					t.Fatalf("Failed to parse refresh token response: %v", err)
				}

				// Dump the response JSON as part of the test
				refreshPrettyJSON, err := json.MarshalIndent(refreshTokenResponse, "", "  ")
				if err != nil {
					t.Fatalf("Failed to marshal refresh token response to pretty JSON: %v", err)
				}
				t.Logf("Refresh Token Response JSON:\n%s", string(refreshPrettyJSON))

				// Verify that the response contains the expected tokens
				if refreshTokenResponse.AccessToken == "" {
					t.Error("No access token in refresh response")
				}

				if refreshTokenResponse.IdToken == "" {
					t.Error("No ID token in refresh response")
				}

				if refreshTokenResponse.RefreshToken == "" {
					t.Error("No refresh token in refresh response")
				}

				if refreshTokenResponse.TokenType != "Bearer" {
					t.Errorf("Expected token type 'Bearer', got '%s'", refreshTokenResponse.TokenType)
				}

				if refreshTokenResponse.ExpiresIn <= 0 {
					t.Errorf("Expected expires_in > 0, got %d", refreshTokenResponse.ExpiresIn)
				}

				// Validate the refreshed tokens with JWKS
				refreshedIdToken, err := jwt.Parse(refreshTokenResponse.IdToken, func(token *jwt.Token) (interface{}, error) {
					// Validate signing method
					if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
						return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
					}
					return rsaPublicKey, nil
				})
				if err != nil {
					t.Fatalf("Failed to validate refreshed ID token: %v", err)
				}
				if !refreshedIdToken.Valid {
					t.Error("Refreshed ID token is not valid")
				}
				t.Logf("Refreshed ID token validated successfully")

				// Validate refreshed access token
				refreshedAccessToken, err := jwt.Parse(refreshTokenResponse.AccessToken, func(token *jwt.Token) (interface{}, error) {
					// Validate signing method
					if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
						return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
					}
					return rsaPublicKey, nil
				})
				if err != nil {
					t.Fatalf("Failed to validate refreshed access token: %v", err)
				}
				if !refreshedAccessToken.Valid {
					t.Error("Refreshed access token is not valid")
				}
				t.Logf("Refreshed access token validated successfully")
			})

			// Verify that the response contains the expected tokens
			if tokenResponse.AccessToken == "" {
				t.Error("No access token in response")
			}

			if tokenResponse.IdToken == "" {
				t.Error("No ID token in response")
			}

			if tokenResponse.RefreshToken == "" {
				t.Error("No refresh token in response")
			}

			if tokenResponse.TokenType != "Bearer" {
				t.Errorf("Expected token type 'Bearer', got '%s'", tokenResponse.TokenType)
			}

			if tokenResponse.ExpiresIn <= 0 {
				t.Errorf("Expected expires_in > 0, got %d", tokenResponse.ExpiresIn)
			}
		})
	})
}

func TestMakeRootFunctionality(t *testing.T) {
	// Set up environment for testing
	os.Setenv("OAUTH2_BRO_CLIENT_CREDENTIALS", "tbe-server=bacd3019-c3b9-4b31-98d5-d3c410a1098e")
	defer os.Unsetenv("OAUTH2_BRO_CLIENT_CREDENTIALS")

	// Create key manager for testing
	keyManager := keymanager.NewKeyManager()

	// Create user manager for testing
	userManager := user.NewUserManager()

	// Create client manager for testing
	clientManager := client.NewClientManager()

	// Create server configuration
	config := ServerConfig{
		RefreshKeys:        keyManager.RefreshKeys,
		CodeKeys:           keyManager.CodeKeys,
		TokenKeys:          keyManager.TokenKeys,
		UserManager:        userManager,
		ClientInfoProvider: clientManager,
		UserInfoProvider:   userManager,
		Version:            "test",
	}

	// Create server instance and setup routes on a new mux
	serverInstance := NewServer(config)
	mux := http.NewServeMux()
	serverInstance.setupRoutesOnMux(mux)

	// Set up environment variables for the test
	os.Setenv("OAUTH2_BRO_MAKE_ROOT_SECRET", "test-secret")
	defer os.Unsetenv("OAUTH2_BRO_MAKE_ROOT_SECRET")

	// Create a test server
	server := httptest.NewServer(mux)
	defer server.Close()

	// Test setting the Make me Root cookie
	t.Run("Set Make me Root cookie", func(t *testing.T) {
		// Create a client that doesn't follow redirects
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		// Set up the Make me Root request parameters
		makeRootURL := fmt.Sprintf("%s/login?cookieSecret=test-secret&sid=admin-user&email=admin@example.com",
			server.URL)

		// Make the request to set the Make me Root cookie
		resp, err := client.Get(makeRootURL)
		if err != nil {
			t.Fatalf("Failed to make request to set Make me Root cookie: %v", err)
		}
		defer resp.Body.Close()

		// Check that the response is successful
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("Expected status code %d, got %d. Response: %s", http.StatusOK, resp.StatusCode, string(body))
		}

		// Check that the response contains the success message
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}
		if !strings.Contains(string(body), "Make me Root cookie set successfully") {
			t.Errorf("Expected success message, got: %s", string(body))
		}

		// Check that the cookie was set
		cookies := resp.Cookies()
		var makeRootCookie *http.Cookie
		cookieName := "oauth2-bro-make-me-root" // Default value
		for _, cookie := range cookies {
			if cookie.Name == cookieName {
				makeRootCookie = cookie
				break
			}
		}
		if makeRootCookie == nil {
			t.Fatal("Make me Root cookie not set")
		}

		// Test using the Make me Root cookie for login
		t.Run("Use Make me Root cookie for login", func(t *testing.T) {
			// Create a client with redirect following disabled
			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			// Set up the login request parameters
			loginURL := fmt.Sprintf("%s/login?response_type=code&client_id=tbe-server&redirect_uri=%s&state=test-state",
				server.URL, url.QueryEscape(server.URL+"/callback"))

			// Create a request with the Make me Root cookie
			req, err := http.NewRequest("GET", loginURL, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.AddCookie(makeRootCookie)

			// Make the request to the login endpoint
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Failed to make request to login endpoint: %v", err)
			}
			defer resp.Body.Close()

			// Check that the response is a redirect
			if resp.StatusCode != http.StatusFound {
				t.Errorf("Expected status code %d, got %d", http.StatusFound, resp.StatusCode)
			}

			// Get the redirect URL
			redirectURL := resp.Header.Get("Location")
			if redirectURL == "" {
				t.Fatalf("No redirect URL in response")
			}

			// Parse the redirect URL to extract the code
			parsedURL, err := url.Parse(redirectURL)
			if err != nil {
				t.Fatalf("Failed to parse redirect URL: %v", err)
			}

			// Extract the code and state from the query parameters
			queryParams := parsedURL.Query()
			code := queryParams.Get("code")
			state := queryParams.Get("state")

			if code == "" {
				t.Fatalf("No code in redirect URL")
			}

			if state != "test-state" {
				t.Errorf("Expected state 'test-state', got '%s'", state)
			}

			// Check that the Make me Root cookie was removed
			cookies := resp.Cookies()
			cookieName := "oauth2-bro-make-me-root" // Default value
			for _, cookie := range cookies {
				if cookie.Name == cookieName {
					if cookie.MaxAge != -1 {
						t.Errorf("Expected Make me Root cookie to be removed, but it was not")
					}
				}
			}

			// Test that the user info is correctly set in the access token
			t.Run("Verify user info in access token", func(t *testing.T) {
				// Set up the token request parameters
				tokenData := url.Values{}
				tokenData.Set("grant_type", "authorization_code")
				tokenData.Set("client_id", "tbe-server")
				tokenData.Set("client_secret", "bacd3019-c3b9-4b31-98d5-d3c410a1098e") // Using a dummy client secret
				tokenData.Set("code", code)
				tokenData.Set("redirect_uri", server.URL+"/callback")

				// Make the request to the token endpoint
				tokenResp, err := http.PostForm(server.URL+"/token", tokenData)
				if err != nil {
					t.Fatalf("Failed to make request to token endpoint: %v", err)
				}
				defer tokenResp.Body.Close()

				// Check that the response is successful
				if tokenResp.StatusCode != http.StatusOK {
					body, _ := io.ReadAll(tokenResp.Body)
					t.Fatalf("Expected status code %d, got %d. Response: %s", http.StatusOK, tokenResp.StatusCode, string(body))
				}

				// Parse the response body
				tokenBody, err := io.ReadAll(tokenResp.Body)
				if err != nil {
					t.Fatalf("Failed to read token response body: %v", err)
				}

				var tokenResponse TokenResponse
				err = json.Unmarshal(tokenBody, &tokenResponse)
				if err != nil {
					t.Fatalf("Failed to parse token response: %v", err)
				}

				// Fetch JWKS data from the server
				jwksResp, err := http.Get(server.URL + "/jwks")
				if err != nil {
					t.Fatalf("Failed to fetch JWKS data: %v", err)
				}
				defer jwksResp.Body.Close()

				jwksBody, err := io.ReadAll(jwksResp.Body)
				if err != nil {
					t.Fatalf("Failed to read JWKS response body: %v", err)
				}

				// Parse JWKS data
				var keys Keys
				err = json.Unmarshal(jwksBody, &keys)
				if err != nil {
					t.Fatalf("Failed to parse JWKS data: %v", err)
				}

				if len(keys.Keys) == 0 {
					t.Fatal("No keys found in JWKS data")
				}

				// Extract public key from JWKS
				key := keys.Keys[0]
				keySpec, err := key.ParseKeySpec()
				if err != nil {
					t.Fatalf("Failed to parse key spec from JWK: %v", err)
				}

				rsaPublicKey, ok := keySpec.Key.(*rsa.PublicKey)
				if !ok {
					t.Fatal("Failed to cast public key to RSA public key")
				}

				// Define a struct for the token claims
				type TokenClaims struct {
					Sid   string `json:"sid"`
					Sub   string `json:"sub"`
					Name  string `json:"name"`
					Email string `json:"email"`
					jwt.RegisteredClaims
				}

				// Parse the access token to extract the claims
				var claims TokenClaims
				_, err = jwt.ParseWithClaims(tokenResponse.AccessToken, &claims, func(token *jwt.Token) (interface{}, error) {
					// Validate signing method
					if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
						return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
					}
					return rsaPublicKey, nil
				})
				if err != nil {
					t.Fatalf("Failed to parse access token claims: %v", err)
				}

				// Verify that the claims match the user info set in the cookie
				if claims.Sid != "admin-user" {
					t.Errorf("Expected sid 'admin-user', got '%s'", claims.Sid)
				}
				if claims.Sub != "admin-user" {
					t.Errorf("Expected sub 'admin-user', got '%s'", claims.Sub)
				}
				// Name is set to email when name is not explicitly provided
				if claims.Name != "admin@example.com" {
					t.Errorf("Expected name 'admin@example.com', got '%s'", claims.Name)
				}
				if claims.Email != "admin@example.com" {
					t.Errorf("Expected email 'admin@example.com', got '%s'", claims.Email)
				}

				t.Logf("User info in access token verified successfully")
			})
		})
	})

	// Test with invalid cookieSecret
	t.Run("Invalid cookieSecret", func(t *testing.T) {
		// Create a client that doesn't follow redirects
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		// Set up the Make me Root request parameters with invalid cookieSecret
		makeRootURL := fmt.Sprintf("%s/login?cookieSecret=invalid-secret&sid=admin-user&email=admin@example.com&response_type=code&client_id=tbe-server&redirect_uri=%s&state=test-state",
			server.URL, url.QueryEscape(server.URL+"/callback"))

		// Make the request to set the Make me Root cookie
		resp, err := client.Get(makeRootURL)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		// Check that the request was redirected (normal login flow)
		if resp.StatusCode != http.StatusFound {
			t.Errorf("Expected status code %d, got %d", http.StatusFound, resp.StatusCode)
		}
	})

	// Test with missing user info parameters
	t.Run("Missing user info parameters", func(t *testing.T) {
		// Set up the Make me Root request parameters without user info
		makeRootURL := fmt.Sprintf("%s/login?cookieSecret=test-secret",
			server.URL)

		// Make the request to set the Make me Root cookie
		resp, err := http.Get(makeRootURL)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		// Check that the response is a bad request
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected status code %d, got %d", http.StatusBadRequest, resp.StatusCode)
		}

		// Check that the response contains the error message
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}
		if !strings.Contains(string(body), "At least one of sid, sub, name, or email must be provided") {
			t.Errorf("Expected error message about missing user info, got: %s", string(body))
		}
	})
}

func TestOAuth2CodeFlowInvalidParameters(t *testing.T) {
	// Set up environment for testing
	os.Setenv("OAUTH2_BRO_CLIENT_CREDENTIALS", "tbe-server=bacd3019-c3b9-4b31-98d5-d3c410a1098e")
	defer os.Unsetenv("OAUTH2_BRO_CLIENT_CREDENTIALS")

	// Create key manager for testing
	keyManager := keymanager.NewKeyManager()

	// Create user manager for testing
	userManager := user.NewUserManager()

	// Create client manager for testing
	clientManager := client.NewClientManager()

	// Create server configuration
	config := ServerConfig{
		RefreshKeys:        keyManager.RefreshKeys,
		CodeKeys:           keyManager.CodeKeys,
		TokenKeys:          keyManager.TokenKeys,
		UserManager:        userManager,
		ClientInfoProvider: clientManager,
		UserInfoProvider:   userManager,
		Version:            "test",
	}

	// Create server instance and setup routes on a new mux
	serverInstance := NewServer(config)
	mux := http.NewServeMux()
	serverInstance.setupRoutesOnMux(mux)

	// Create a test server
	server := httptest.NewServer(mux)
	defer server.Close()

	// Test the login endpoint with invalid response_type
	t.Run("Invalid response_type", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("%s/login?response_type=invalid&client_id=tbe-server&redirect_uri=%s",
			server.URL, url.QueryEscape(server.URL+"/callback")))
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected status code %d, got %d", http.StatusBadRequest, resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "response_type parameter is invalid") {
			t.Errorf("Expected error message about invalid response_type, got: %s", string(body))
		}
	})

	// Test the login endpoint with missing client_id
	t.Run("Missing client_id", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("%s/login?response_type=code&redirect_uri=%s",
			server.URL, url.QueryEscape(server.URL+"/callback")))
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected status code %d, got %d", http.StatusBadRequest, resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "client_id parameter is missing") {
			t.Errorf("Expected error message about missing client_id, got: %s", string(body))
		}
	})

	// Test the login endpoint with missing redirect_uri
	t.Run("Missing redirect_uri", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("%s/login?response_type=code&client_id=tbe-server",
			server.URL))
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected status code %d, got %d", http.StatusBadRequest, resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "redirect_uri parameter is missing") {
			t.Errorf("Expected error message about missing redirect_uri, got: %s", string(body))
		}
	})

	// Test the token endpoint with invalid grant_type
	t.Run("Invalid grant_type", func(t *testing.T) {
		tokenData := url.Values{}
		tokenData.Set("grant_type", "invalid")
		tokenData.Set("client_id", "tbe-server")
		tokenData.Set("client_secret", "bacd3019-c3b9-4b31-98d5-d3c410a1098e")

		resp, err := http.PostForm(server.URL+"/token", tokenData)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("Expected status code %d, got %d", http.StatusInternalServerError, resp.StatusCode)
		}
	})

	// Test the token endpoint with invalid code
	t.Run("Invalid code", func(t *testing.T) {
		tokenData := url.Values{}
		tokenData.Set("grant_type", "authorization_code")
		tokenData.Set("client_id", "tbe-server")
		tokenData.Set("client_secret", "bacd3019-c3b9-4b31-98d5-d3c410a1098e")
		tokenData.Set("code", "invalid-code")

		resp, err := http.PostForm(server.URL+"/token", tokenData)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected status code %d, got %d", http.StatusBadRequest, resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "Failed to validate code token") {
			t.Errorf("Expected error message about invalid code, got: %s", string(body))
		}
	})
}

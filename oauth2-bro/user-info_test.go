package main

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"os"
	"testing"
)

// Helper function to create the expected hash for testing
func createExpectedHash(ip string) string {
	hash := sha256.Sum256([]byte(ip))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func TestIsIPAllowed(t *testing.T) {
	// Save original environment variable
	oldIPMasks := os.Getenv("OAUTH2_BRO_ALLOWED_IP_MASKS")
	defer os.Setenv("OAUTH2_BRO_ALLOWED_IP_MASKS", oldIPMasks)

	tests := []struct {
		name      string
		ipMasks   string
		testIP    string
		wantMatch bool
	}{
		{
			name:      "No masks configured",
			ipMasks:   "",
			testIP:    "192.168.1.1",
			wantMatch: true, // All IPs allowed when no masks configured
		},
		{
			name:      "IPv4 exact match",
			ipMasks:   "192.168.1.1/32",
			testIP:    "192.168.1.1",
			wantMatch: true,
		},
		{
			name:      "IPv4 subnet match",
			ipMasks:   "192.168.1.0/24",
			testIP:    "192.168.1.100",
			wantMatch: true,
		},
		{
			name:      "IPv4 no match",
			ipMasks:   "192.168.1.0/24",
			testIP:    "192.168.2.1",
			wantMatch: false,
		},
		{
			name:      "IPv6 exact match",
			ipMasks:   "2001:db8::1/128",
			testIP:    "2001:db8::1",
			wantMatch: true,
		},
		{
			name:      "IPv6 subnet match",
			ipMasks:   "2001:db8::/32",
			testIP:    "2001:db8:1111:2222:3333:4444:5555:6666",
			wantMatch: true,
		},
		{
			name:      "IPv6 no match",
			ipMasks:   "2001:db8::/32",
			testIP:    "2001:db9::1",
			wantMatch: false,
		},
		{
			name:      "Multiple masks, match first",
			ipMasks:   "192.168.1.0/24,10.0.0.0/8",
			testIP:    "192.168.1.100",
			wantMatch: true,
		},
		{
			name:      "Multiple masks, match second",
			ipMasks:   "192.168.1.0/24,10.0.0.0/8",
			testIP:    "10.10.10.10",
			wantMatch: true,
		},
		{
			name:      "Multiple masks, no match",
			ipMasks:   "192.168.1.0/24,10.0.0.0/8",
			testIP:    "172.16.0.1",
			wantMatch: false,
		},
		{
			name:      "Invalid IP",
			ipMasks:   "192.168.1.0/24",
			testIP:    "not-an-ip",
			wantMatch: false,
		},
		{
			name:      "Invalid mask format",
			ipMasks:   "invalid-mask",
			testIP:    "192.168.1.1",
			wantMatch: true, // Invalid masks are ignored, so all IPs allowed
		},
		{
			name:      "Mixed IPv4 and IPv6 masks, IPv4 match",
			ipMasks:   "192.168.1.0/24,2001:db8::/32",
			testIP:    "192.168.1.100",
			wantMatch: true,
		},
		{
			name:      "Mixed IPv4 and IPv6 masks, IPv6 match",
			ipMasks:   "192.168.1.0/24,2001:db8::/32",
			testIP:    "2001:db8::1",
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable for this test
			os.Setenv("OAUTH2_BRO_ALLOWED_IP_MASKS", tt.ipMasks)

			// Initialize IP masks for this test
			init_ip_masks()

			// Test if IP is allowed
			got := isIPAllowed(tt.testIP)
			if got != tt.wantMatch {
				t.Errorf("isIPAllowed(%q) with masks %q = %v, want %v",
					tt.testIP, tt.ipMasks, got, tt.wantMatch)
			}
		})
	}
}

func TestResolveUserInfoFromRequestWithIPFiltering(t *testing.T) {
	// Save original environment variables
	oldEmailDomain := os.Getenv("OAUTH2_BRO_EMAIL_DOMAIN")
	oldIPMasks := os.Getenv("OAUTH2_BRO_ALLOWED_IP_MASKS")

	// Restore environment variables after test
	defer func() {
		os.Setenv("OAUTH2_BRO_EMAIL_DOMAIN", oldEmailDomain)
		os.Setenv("OAUTH2_BRO_ALLOWED_IP_MASKS", oldIPMasks)
	}()

	// Set email domain for test
	os.Setenv("OAUTH2_BRO_EMAIL_DOMAIN", "example.com")

	tests := []struct {
		name           string
		ipMasks        string
		setupRequest   func() *http.Request
		requestIP      string
		expectUserInfo bool
	}{
		{
			name:    "No masks configured - all IPs allowed",
			ipMasks: "",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("X-Forwarded-For", "192.168.1.1")
				return req
			},
			requestIP:      "192.168.1.1",
			expectUserInfo: true,
		},
		{
			name:    "IP matches configured mask",
			ipMasks: "192.168.1.0/24",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("X-Forwarded-For", "192.168.1.100")
				return req
			},
			requestIP:      "192.168.1.100",
			expectUserInfo: true,
		},
		{
			name:    "IP doesn't match configured mask",
			ipMasks: "192.168.1.0/24",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("X-Forwarded-For", "10.0.0.1")
				return req
			},
			requestIP:      "10.0.0.1",
			expectUserInfo: false,
		},
		{
			name:    "IPv6 matches configured mask",
			ipMasks: "2001:db8::/32",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("X-Forwarded-For", "2001:db8::1")
				return req
			},
			requestIP:      "2001:db8::1",
			expectUserInfo: true,
		},
		{
			name:    "IPv6 doesn't match configured mask",
			ipMasks: "2001:db8::/32",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("X-Forwarded-For", "2001:db9::1")
				return req
			},
			requestIP:      "2001:db9::1",
			expectUserInfo: false,
		},
		{
			name:    "Multiple masks, IP matches one",
			ipMasks: "192.168.1.0/24,10.0.0.0/8",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("X-Forwarded-For", "10.10.10.10")
				return req
			},
			requestIP:      "10.10.10.10",
			expectUserInfo: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set IP masks for this test
			os.Setenv("OAUTH2_BRO_ALLOWED_IP_MASKS", tt.ipMasks)

			// Initialize IP masks for this test
			init_ip_masks()

			// Create request and resolve user info
			req := tt.setupRequest()
			userInfo := ResolveUserInfoFromRequest(req)

			if tt.expectUserInfo {
				if userInfo == nil {
					t.Errorf("Expected user info for IP %s with masks %s, but got nil",
						tt.requestIP, tt.ipMasks)
					return
				}

				// Calculate expected hash
				expectedHash := createExpectedHash(tt.requestIP)

				// Verify user info fields
				if userInfo.Sid != expectedHash {
					t.Errorf("Expected Sid to be %s, got %s", expectedHash, userInfo.Sid)
				}

				expectedUsername := createUsernameFromIP(tt.requestIP)
				if userInfo.UserName != expectedUsername {
					t.Errorf("Expected UserName to be %s, got %s", expectedUsername, userInfo.UserName)
				}
			} else {
				if userInfo != nil {
					t.Errorf("Expected nil user info for IP %s with masks %s, but got %+v",
						tt.requestIP, tt.ipMasks, userInfo)
				}
			}
		})
	}
}

func TestResolveUserInfoFromRequest(t *testing.T) {
	oldEmailDomain := os.Getenv("OAUTH2_BRO_EMAIL_DOMAIN")
	oldIPMasks := os.Getenv("OAUTH2_BRO_ALLOWED_IP_MASKS")
	os.Setenv("OAUTH2_BRO_EMAIL_DOMAIN", "example.com")
	os.Setenv("OAUTH2_BRO_ALLOWED_IP_MASKS", "") // Allow all IPs for this test
	defer func() {
		os.Setenv("OAUTH2_BRO_EMAIL_DOMAIN", oldEmailDomain)
		os.Setenv("OAUTH2_BRO_ALLOWED_IP_MASKS", oldIPMasks)
	}()

	tests := []struct {
		name           string
		setupRequest   func() *http.Request
		expectedIP     string
		expectedPrefix string
	}{
		{
			name: "X-Forwarded-For header",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("X-Forwarded-For", "192.168.1.1, 10.0.0.1")
				return req
			},
			expectedIP:     "192.168.1.1",
			expectedPrefix: "ip-192-168-1-1",
		},
		{
			name: "X-Real-IP header",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("X-Real-IP", "192.168.1.2")
				return req
			},
			expectedIP:     "192.168.1.2",
			expectedPrefix: "ip-192-168-1-2",
		},
		{
			name: "Forwarded header",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("Forwarded", "for=192.168.1.3;proto=https")
				return req
			},
			expectedIP:     "192.168.1.3",
			expectedPrefix: "ip-192-168-1-3",
		},
		{
			name: "IPv6 address",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("X-Forwarded-For", "2001:db8::1")
				return req
			},
			expectedIP:     "2001:db8::1",
			expectedPrefix: "ip-2001-db8--1",
		},
		{
			name: "RemoteAddr fallback",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				req.RemoteAddr = "192.168.1.4:12345"
				return req
			},
			expectedIP:     "192.168.1.4",
			expectedPrefix: "ip-192-168-1-4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupRequest()
			userInfo := ResolveUserInfoFromRequest(req)

			if userInfo == nil {
				t.Fatal("ResolveUserInfoFromRequest returned nil")
			}

			// Calculate expected hash for Sid and Sub
			expectedHash := createExpectedHash(tt.expectedIP)

			// Check that Sid and Sub are populated with the expected hash
			if userInfo.Sid != expectedHash {
				t.Errorf("Expected Sid to be %s, got %s", expectedHash, userInfo.Sid)
			}
			if userInfo.Sub != expectedHash {
				t.Errorf("Expected Sub to be %s, got %s", expectedHash, userInfo.Sub)
			}

			// Check that UserName and UserEmail are still populated with the expected username
			if userInfo.UserName != tt.expectedPrefix {
				t.Errorf("Expected UserName to be %s, got %s", tt.expectedPrefix, userInfo.UserName)
			}
			if userInfo.UserEmail != tt.expectedPrefix+"@example.com" {
				t.Errorf("Expected UserEmail to be %s@example.com, got %s", tt.expectedPrefix, userInfo.UserEmail)
			}
		})
	}
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		name         string
		setupRequest func() *http.Request
		expectedIP   string
	}{
		{
			name: "X-Forwarded-For with multiple IPs",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("X-Forwarded-For", "192.168.1.1, 10.0.0.1, 172.16.0.1")
				return req
			},
			expectedIP: "192.168.1.1",
		},
		{
			name: "X-Forwarded-For with spaces",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("X-Forwarded-For", " 192.168.1.2 ")
				return req
			},
			expectedIP: "192.168.1.2",
		},
		{
			name: "Forwarded header with quoted value",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("Forwarded", "for=\"192.168.1.3\";proto=https")
				return req
			},
			expectedIP: "192.168.1.3",
		},
		{
			name: "Forwarded header with IPv6",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("Forwarded", "for=[2001:db8::1];proto=https")
				return req
			},
			expectedIP: "2001:db8::1",
		},
		{
			name: "Priority order test",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("X-Forwarded-For", "192.168.1.1")
				req.Header.Set("X-Real-IP", "192.168.1.2")
				req.Header.Set("Forwarded", "for=192.168.1.3")
				req.RemoteAddr = "192.168.1.4:12345"
				return req
			},
			expectedIP: "192.168.1.1", // X-Forwarded-For has highest priority
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupRequest()
			ip := extractIP(req)

			if ip != tt.expectedIP {
				t.Errorf("Expected IP to be %s, got %s", tt.expectedIP, ip)
			}
		})
	}
}

func TestNormalizeIP(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		expectedIP string
	}{
		{
			name:       "IPv4 with port",
			input:      "192.168.1.1:8080",
			expectedIP: "192.168.1.1",
		},
		{
			name:       "IPv4 without port",
			input:      "192.168.1.2",
			expectedIP: "192.168.1.2",
		},
		{
			name:       "IPv6 with port",
			input:      "[2001:db8::1]:8080",
			expectedIP: "2001:db8::1",
		},
		{
			name:       "IPv6 without port",
			input:      "2001:db8::2",
			expectedIP: "2001:db8::2",
		},
		{
			name:       "Invalid IP",
			input:      "not-an-ip",
			expectedIP: "not-an-ip", // Returns original if not valid
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalizedIP := normalizeIP(tt.input)

			if normalizedIP != tt.expectedIP {
				t.Errorf("Expected normalized IP to be %s, got %s", tt.expectedIP, normalizedIP)
			}
		})
	}
}

func TestCreateUsernameFromIP(t *testing.T) {
	tests := []struct {
		name           string
		ip             string
		expectedResult string
	}{
		{
			name:           "IPv4 address",
			ip:             "192.168.1.1",
			expectedResult: "ip-192-168-1-1",
		},
		{
			name:           "IPv6 address",
			ip:             "2001:db8::1",
			expectedResult: "ip-2001-db8--1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			username := createUsernameFromIP(tt.ip)

			if username != tt.expectedResult {
				t.Errorf("Expected username to be %s, got %s", tt.expectedResult, username)
			}
		})
	}
}

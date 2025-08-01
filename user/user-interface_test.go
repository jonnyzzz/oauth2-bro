package user

import (
	"net/http"
	"os"
	"testing"
)

func TestUserInfoProviderInterface(t *testing.T) {
	// Test with userResolverImpl implementation
	t.Run("userResolverImpl Implementation", func(t *testing.T) {
		// Set up environment for userResolverImpl test
		originalIPMasks := os.Getenv("OAUTH2_BRO_ALLOWED_IP_MASKS")
		defer os.Setenv("OAUTH2_BRO_ALLOWED_IP_MASKS", originalIPMasks)

		// Allow all IPs for testing
		os.Setenv("OAUTH2_BRO_ALLOWED_IP_MASKS", "")

		userManager := NewUserResolver()
		testUserInfoProvider(t, userManager)
	})
}

func testUserInfoProvider(t *testing.T, provider UserResolver) {
	// Create a simple HTTP request for testing
	req, err := http.NewRequest("GET", "/test", nil)
	if err != nil {
		t.Fatal("Failed to create test request:", err)
	}

	// Test user info resolution
	userInfo := provider.ResolveUserInfoFromRequest(req)
	if userInfo == nil {
		t.Error("Expected user info to be resolved")
		return
	}

	// Verify user info structure
	if userInfo.Sid == "" {
		t.Error("Expected Sid to be set")
	}
	if userInfo.Sub == "" {
		t.Error("Expected Sub to be set")
	}
	if userInfo.UserName == "" {
		t.Error("Expected UserName to be set")
	}
}

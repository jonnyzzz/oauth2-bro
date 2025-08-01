package client

import (
	"os"
	"testing"
)

func TestClientIdValidation(t *testing.T) {
	// Save original environment variables
	origClientCreds := os.Getenv("OAUTH2_BRO_CLIENT_CREDENTIALS")

	// Restore environment variables after test
	defer func() {
		os.Setenv("OAUTH2_BRO_CLIENT_CREDENTIALS", origClientCreds)
	}()

	// Test 1: Default behavior - all clients allowed
	os.Setenv("OAUTH2_BRO_CLIENT_CREDENTIALS", "")
	clientManager := NewClientManager()

	if !clientManager.IsClientIdAllowed("any-client") {
		t.Error("Expected all client IDs to be allowed when no client credentials are configured")
	}

	if !clientManager.IsClientAllowed("any-client", "any-secret") {
		t.Error("Expected all client ID and secret pairs to be allowed when no client credentials are configured")
	}

	// Test 2: Client ID validation
	os.Setenv("OAUTH2_BRO_CLIENT_CREDENTIALS", "client1=secret1,client2=secret2,client3=secret3")
	clientManager = NewClientManager()

	if !clientManager.IsClientIdAllowed("client1") {
		t.Error("Expected client1 to be allowed")
	}

	if !clientManager.IsClientIdAllowed("client2") {
		t.Error("Expected client2 to be allowed")
	}

	if !clientManager.IsClientIdAllowed("client3") {
		t.Error("Expected client3 to be allowed")
	}

	if clientManager.IsClientIdAllowed("client4") {
		t.Error("Expected client4 to be denied")
	}

	// Test 3: Client ID and secret validation
	os.Setenv("OAUTH2_BRO_CLIENT_CREDENTIALS", "client1=secret1,client2=secret2")
	clientManager = NewClientManager()

	if !clientManager.IsClientAllowed("client1", "secret1") {
		t.Error("Expected client1 with secret1 to be allowed")
	}

	if !clientManager.IsClientAllowed("client2", "secret2") {
		t.Error("Expected client2 with secret2 to be allowed")
	}

	if clientManager.IsClientAllowed("client1", "wrong-secret") {
		t.Error("Expected client1 with wrong-secret to be denied")
	}

	if clientManager.IsClientAllowed("client3", "any-secret") {
		t.Error("Expected client3 to be denied regardless of secret")
	}

	// Test 4: Malformed client credentials
	os.Setenv("OAUTH2_BRO_CLIENT_CREDENTIALS", "client1=secret1,invalid-format,client2=secret2")
	clientManager = NewClientManager()

	if !clientManager.IsClientAllowed("client1", "secret1") {
		t.Error("Expected client1 with secret1 to be allowed despite malformed entry in credentials")
	}

	if !clientManager.IsClientAllowed("client2", "secret2") {
		t.Error("Expected client2 with secret2 to be allowed despite malformed entry in credentials")
	}

	if clientManager.IsClientAllowed("invalid-format", "any-secret") {
		t.Error("Expected invalid-format to be denied")
	}
}

func TestClientInfoProviderInterface(t *testing.T) {
	// Test with ClientManager implementation
	t.Run("ClientManager Implementation", func(t *testing.T) {
		// Set up environment for ClientManager test
		originalCreds := os.Getenv("OAUTH2_BRO_CLIENT_CREDENTIALS")
		defer os.Setenv("OAUTH2_BRO_CLIENT_CREDENTIALS", originalCreds)

		os.Setenv("OAUTH2_BRO_CLIENT_CREDENTIALS", "test-client=test-secret")
		clientManager := NewClientManager()
		testClientInfoProvider(t, clientManager)
	})

	// Test with MockClientInfoProvider implementation
	t.Run("MockClientInfoProvider Implementation", func(t *testing.T) {
		mockProvider := NewMockClientInfoProvider()
		mockProvider.AddClient("test-client", "test-secret")
		testClientInfoProvider(t, mockProvider)
	})
}

func testClientInfoProvider(t *testing.T, provider ClientInfoProvider) {
	// Test client ID validation
	if !provider.IsClientIdAllowed("test-client") {
		t.Error("Expected test-client to be allowed")
	}

	if provider.IsClientIdAllowed("unknown-client") {
		t.Error("Expected unknown-client to be denied")
	}

	// Test client ID and secret validation
	if !provider.IsClientAllowed("test-client", "test-secret") {
		t.Error("Expected test-client with test-secret to be allowed")
	}

	if provider.IsClientAllowed("test-client", "wrong-secret") {
		t.Error("Expected test-client with wrong-secret to be denied")
	}

	if provider.IsClientAllowed("unknown-client", "any-secret") {
		t.Error("Expected unknown-client to be denied regardless of secret")
	}
}

package main

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
	init_client_id()

	if !isClientIdAllowed("any-client") {
		t.Error("Expected all client IDs to be allowed when no client credentials are configured")
	}

	if !isClientAllowed("any-client", "any-secret") {
		t.Error("Expected all client ID and secret pairs to be allowed when no client credentials are configured")
	}

	// Test 2: Client ID validation
	os.Setenv("OAUTH2_BRO_CLIENT_CREDENTIALS", "client1=secret1,client2=secret2,client3=secret3")
	init_client_id()

	if !isClientIdAllowed("client1") {
		t.Error("Expected client1 to be allowed")
	}

	if !isClientIdAllowed("client2") {
		t.Error("Expected client2 to be allowed")
	}

	if !isClientIdAllowed("client3") {
		t.Error("Expected client3 to be allowed")
	}

	if isClientIdAllowed("client4") {
		t.Error("Expected client4 to be denied")
	}

	// Test 3: Client ID and secret validation
	os.Setenv("OAUTH2_BRO_CLIENT_CREDENTIALS", "client1=secret1,client2=secret2")
	init_client_id()

	if !isClientAllowed("client1", "secret1") {
		t.Error("Expected client1 with secret1 to be allowed")
	}

	if !isClientAllowed("client2", "secret2") {
		t.Error("Expected client2 with secret2 to be allowed")
	}

	if isClientAllowed("client1", "wrong-secret") {
		t.Error("Expected client1 with wrong-secret to be denied")
	}

	if isClientAllowed("client3", "any-secret") {
		t.Error("Expected client3 to be denied regardless of secret")
	}

	// Test 4: Malformed client credentials
	os.Setenv("OAUTH2_BRO_CLIENT_CREDENTIALS", "client1=secret1,invalid-format,client2=secret2")
	init_client_id()

	if !isClientAllowed("client1", "secret1") {
		t.Error("Expected client1 with secret1 to be allowed despite malformed entry in credentials")
	}

	if !isClientAllowed("client2", "secret2") {
		t.Error("Expected client2 with secret2 to be allowed despite malformed entry in credentials")
	}

	if isClientAllowed("invalid-format", "any-secret") {
		t.Error("Expected invalid-format to be denied")
	}
}

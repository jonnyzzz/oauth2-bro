package main

import (
	"log"
	"os"
	"strings"
)

// Data structures to store client credentials (clientId -> clientSecret)
var clientCredentials map[string]string

// init_client_id initializes the client ID and secret validation
// by reading from environment variables
func init_client_id() {
	clientCredentials = make(map[string]string)

	// Read client credentials from environment variable
	clientCredsStr := os.Getenv("OAUTH2_BRO_CLIENT_CREDENTIALS")
	if len(clientCredsStr) > 0 {
		credPairs := strings.Split(clientCredsStr, ",")
		for _, pair := range credPairs {
			pair = strings.TrimSpace(pair)
			if len(pair) == 0 {
				continue
			}

			parts := strings.SplitN(pair, "=", 2)
			if len(parts) != 2 {
				log.Printf("Invalid client credential format: %s, expected clientId=clientSecret", pair)
				continue
			}

			clientId := strings.TrimSpace(parts[0])
			clientSecret := strings.TrimSpace(parts[1])

			if len(clientId) > 0 && len(clientSecret) > 0 {
				clientCredentials[clientId] = clientSecret
				log.Printf("Registered credentials for client ID: %s", clientId)
			}
		}
	} else {
		log.Printf("No client credentials specified, allowing all clients")
	}
}

// isClientIdAllowed checks if the given client ID is allowed
// If no client IDs are configured, all clients are allowed
func isClientIdAllowed(clientId string) bool {
	if len(clientCredentials) == 0 {
		return true
	}
	_, exists := clientCredentials[clientId]
	return exists
}

// isClientAllowed checks if the given client ID and secret are allowed
// If no client credentials are configured, all clients are allowed
func isClientAllowed(clientId string, clientSecret string) bool {
	// First check if the client ID is allowed
	if !isClientIdAllowed(clientId) {
		return false
	}

	// If no credentials are configured, allow all clients
	if len(clientCredentials) == 0 {
		return true
	}

	// Check if the provided secret matches the stored secret
	storedSecret, exists := clientCredentials[clientId]
	if !exists {
		return false
	}

	return storedSecret == clientSecret
}

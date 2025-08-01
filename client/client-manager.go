package client

import (
	"log"
	"os"
	"strings"
)

// clientManagerImpl holds all client-related state and provides methods for client operations
type clientManagerImpl struct {
	clientCredentials map[string]string
}

// NewClientManager creates a new clientManagerImpl instance with all dependencies
func NewClientManager() ClientInfoProvider {
	cm := &clientManagerImpl{
		clientCredentials: initClientCredentials(),
	}
	return cm
}

// initClientCredentials initializes the client ID and secret validation
func initClientCredentials() map[string]string {

	clientCredentials := make(map[string]string)

	env := os.Getenv("OAUTH2_BRO_CLIENT_CREDENTIALS")
	if len(env) > 0 {
		credPairs := strings.Split(env, ",")
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

	return clientCredentials
}

// IsClientIdAllowed checks if the given client ID is allowed
func (cm *clientManagerImpl) IsClientIdAllowed(clientId string) bool {
	if len(cm.clientCredentials) == 0 {
		return true
	}
	_, exists := cm.clientCredentials[clientId]
	return exists
}

// IsClientAllowed checks if the given client ID and secret are allowed
func (cm *clientManagerImpl) IsClientAllowed(clientId string, clientSecret string) bool {
	// First check if the client ID is allowed
	if !cm.IsClientIdAllowed(clientId) {
		return false
	}

	// If no credentials are configured, allow all clients
	if len(cm.clientCredentials) == 0 {
		return true
	}

	// Check if the provided secret matches the stored secret
	storedSecret, exists := cm.clientCredentials[clientId]
	if !exists {
		return false
	}

	return storedSecret == clientSecret
}

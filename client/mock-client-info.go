package client

// MockClientInfoProvider is a simple mock implementation for testing
type MockClientInfoProvider struct {
	allowedClients map[string]string
}

// NewMockClientInfoProvider creates a new mock client info provider
func NewMockClientInfoProvider() *MockClientInfoProvider {
	return &MockClientInfoProvider{
		allowedClients: make(map[string]string),
	}
}

// AddClient adds a client to the allowed list
func (m *MockClientInfoProvider) AddClient(clientId, clientSecret string) {
	m.allowedClients[clientId] = clientSecret
}

// IsClientIdAllowed checks if the given client ID is allowed
func (m *MockClientInfoProvider) IsClientIdAllowed(clientId string) bool {
	_, exists := m.allowedClients[clientId]
	return exists
}

// IsClientAllowed checks if the given client ID and secret are allowed
func (m *MockClientInfoProvider) IsClientAllowed(clientId string, clientSecret string) bool {
	storedSecret, exists := m.allowedClients[clientId]
	if !exists {
		return false
	}
	return storedSecret == clientSecret
}

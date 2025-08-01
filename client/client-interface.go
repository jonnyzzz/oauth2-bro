package client

// ClientInfoProvider defines the interface for client authentication functionality
type ClientInfoProvider interface {
	// IsClientIdAllowed checks if the given client ID is allowed
	IsClientIdAllowed(clientId string) bool

	// IsClientAllowed checks if the given client ID and secret are allowed
	IsClientAllowed(clientId string, clientSecret string) bool
}

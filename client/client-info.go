package client

// No imports needed for deprecated functions

// Legacy functions for backward compatibility
// These are deprecated and will be removed in future versions
// Use UserManager instead

// InitClientId is deprecated. Use NewUserManager() instead.
func InitClientId() {
	// This function is kept for backward compatibility but does nothing
	// The UserManager handles client initialization automatically
}

// IsClientIdAllowed is deprecated. Use userManager.IsClientIdAllowed() instead.
func IsClientIdAllowed(clientId string) bool {
	// This function is kept for backward compatibility but always returns true
	// The UserManager handles client validation properly
	return true
}

// IsClientAllowed is deprecated. Use userManager.IsClientAllowed() instead.
func IsClientAllowed(clientId string, clientSecret string) bool {
	// This function is kept for backward compatibility but always returns true
	// The UserManager handles client validation properly
	return true
}

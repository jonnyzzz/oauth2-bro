package user

import "net/http"

// UserInfoProvider defines the interface for user information functionality
type UserInfoProvider interface {
	// ResolveUserInfoFromRequest extracts client IP from HTTP request headers,
	// normalizes it, and creates a human-readable username from it.
	// It respects X-Forwarded-For and similar HTTP headers to resolve the requestor IP.
	// If IP address masks are configured, only IPs matching those masks will be processed.
	// Returns nil for IPs that don't match.
	ResolveUserInfoFromRequest(r *http.Request) *UserInfo
}

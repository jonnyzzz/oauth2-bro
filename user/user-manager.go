package user

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

// userResolverImpl holds all user-related state and provides methods for user operations
type userResolverImpl struct {
	ipMaskCache []*net.IPNet
	emailDomain string
}

// Ensure userResolverImpl implements UserResolver interface
var _ UserResolver = (*userResolverImpl)(nil)

// NewUserResolver creates a new UserResolver instance with all dependencies
func NewUserResolver() UserResolver {
	um := &userResolverImpl{
		ipMaskCache: initIpMasks(),
		emailDomain: os.Getenv("OAUTH2_BRO_EMAIL_DOMAIN"),
	}

	return um
}

// initIpMasks initializes the IP masks from the environment variable
func initIpMasks() []*net.IPNet {
	masksStr := os.Getenv("OAUTH2_BRO_ALLOWED_IP_MASKS")
	if strings.TrimSpace(masksStr) == "" {
		return nil // No masks specified, all IPs are allowed
	}

	var ipMaskCache []*net.IPNet
	for _, maskStr := range strings.Split(masksStr, ",") {
		maskStr = strings.TrimSpace(maskStr)
		if maskStr == "" {
			continue
		}

		_, ipNet, err := net.ParseCIDR(maskStr)
		if err != nil {
			log.Printf("Warning: Invalid IP mask format '%s': %v", maskStr, err)
			continue
		}

		ipMaskCache = append(ipMaskCache, ipNet)
	}

	return ipMaskCache
}

func (um *userResolverImpl) isIPAllowed(ipStr string) bool {
	if len(um.ipMaskCache) == 0 {
		return true // No masks specified, all IPs are allowed
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false // Not a valid IP
	}

	for _, mask := range um.ipMaskCache {
		if mask.Contains(ip) {
			return true
		}
	}

	return false
}

// GetEmailDomain returns the configured email domain
func (um *userResolverImpl) GetEmailDomain() string {
	return um.emailDomain
}

// ResolveUserInfoFromRequest extracts client IP from HTTP request headers,
// normalizes it, and creates a human-readable username from it.
// It respects X-Forwarded-For and similar HTTP headers to resolve the requestor IP.
// If IP address masks are configured via OAUTH2_BRO_ALLOWED_IP_MASKS environment variable,
// only IPs matching those masks will be processed. Returns nil for IPs that don't match.
func (um *userResolverImpl) ResolveUserInfoFromRequest(r *http.Request) *UserInfo {
	// Extract IP address from request
	ip := extractIP(r)

	// Normalize IP address
	normalizedIP := normalizeIP(ip)

	// Check if the IP is allowed based on configured masks
	if !um.isIPAllowed(normalizedIP) {
		fmt.Println("User with IP " + normalizedIP + " is not allowed")
		return nil // IP is not in the allowed ranges
	}

	username := createUsernameFromIP(normalizedIP)

	// Create hash from IP for Sid and Sub
	// Create and return UserInfo
	email := ""
	emailDomain := um.GetEmailDomain()
	if len(emailDomain) > 0 {
		email = fmt.Sprintf("%s@%s", username, emailDomain)
	}

	return &UserInfo{
		Sid:       username,
		Sub:       username,
		UserName:  username,
		UserEmail: email,
	}
}

// extractIP extracts the client IP address from the request,
// respecting various headers that might contain the original client IP.
func extractIP(r *http.Request) string {
	// Check X-Forwarded-For header (most common)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs (client, proxy1, proxy2, ...)
		// The leftmost IP is the original client
		ips := strings.Split(xff, ",")
		clientIP := strings.TrimSpace(ips[0])
		return clientIP
	}

	// Check X-Real-IP header (often used by Nginx)
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return strings.TrimSpace(xrip)
	}

	// Check Forwarded header (RFC 7239)
	if forwarded := r.Header.Get("Forwarded"); forwarded != "" {
		// Parse the Forwarded header
		parts := strings.Split(forwarded, ";")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "for=") {
				// Extract the IP from for=
				forValue := strings.TrimPrefix(part, "for=")
				// Remove quotes if present
				forValue = strings.Trim(forValue, "\"")
				// Remove IPv6 brackets if present
				forValue = strings.Trim(forValue, "[]")
				return forValue
			}
		}
	}

	// Check other common headers
	if clientIP := r.Header.Get("X-Client-IP"); clientIP != "" {
		return strings.TrimSpace(clientIP)
	}
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
		return strings.TrimSpace(cfIP)
	}
	if trueClientIP := r.Header.Get("True-Client-IP"); trueClientIP != "" {
		return strings.TrimSpace(trueClientIP)
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If SplitHostPort fails, use RemoteAddr as is
		return r.RemoteAddr
	}
	return ip
}

// normalizeIP normalizes the IP address by removing port information
// and ensuring it's a valid IP address.
func normalizeIP(ipStr string) string {
	// Remove port if present
	ip, _, err := net.SplitHostPort(ipStr)
	if err == nil {
		ipStr = ip
	}

	// Parse IP to validate and normalize
	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		// If not a valid IP, return the original string
		return ipStr
	}

	// Return the normalized IP string
	return strings.ToLower(parsedIP.String())
}

// createUsernameFromIP creates a human-readable username from the IP address.
func createUsernameFromIP(ip string) string {
	// Replace dots and colons with hyphens
	username := strings.ReplaceAll(ip, ".", "-")
	username = strings.ReplaceAll(username, ":", "-")

	// Add a prefix
	username = "ip-" + username

	return username
}

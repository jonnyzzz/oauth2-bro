package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
)

type UserInfo struct {
	Sid       string
	Sub       string
	UserName  string
	UserEmail string //can be empty!
}

// ipMaskCache stores the parsed IP masks from the environment variable
var ipMaskCache []*net.IPNet

// init_ip_masks initializes the IP masks from the environment variable.
// This function should be called at startup and in tests when needed.
func init_ip_masks() {
	// Reset the cache
	ipMaskCache = nil

	masksStr := os.Getenv("OAUTH2_BRO_ALLOWED_IP_MASKS")
	if masksStr == "" {
		return // No masks specified, all IPs are allowed
	}

	masksList := strings.Split(masksStr, ",")
	for _, maskStr := range masksList {
		maskStr = strings.TrimSpace(maskStr)
		if maskStr == "" {
			continue
		}

		_, ipNet, err := net.ParseCIDR(maskStr)
		if err != nil {
			fmt.Printf("Warning: Invalid IP mask format '%s': %v\n", maskStr, err)
			continue
		}

		ipMaskCache = append(ipMaskCache, ipNet)
	}
}

// getAllowedIPMasks returns the list of IP networks.
// If no masks are configured, it returns nil, which means all IPs are allowed.
func getAllowedIPMasks() []*net.IPNet {
	return ipMaskCache
}

// isIPAllowed checks if the given IP is allowed based on the configured IP masks.
// If no masks are configured, all IPs are allowed.
func isIPAllowed(ipStr string) bool {
	masks := getAllowedIPMasks()
	if len(masks) == 0 {
		return true // No masks specified, all IPs are allowed
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false // Not a valid IP
	}

	for _, mask := range masks {
		if mask.Contains(ip) {
			return true
		}
	}

	return false
}

// ResolveUserInfoFromRequest extracts client IP from HTTP request headers,
// normalizes it, and creates a human-readable username from it.
// It respects X-Forwarded-For and similar HTTP headers to resolve the requestor IP.
// If IP address masks are configured via OAUTH2_BRO_ALLOWED_IP_MASKS environment variable,
// only IPs matching those masks will be processed. Returns nil for IPs that don't match.
func ResolveUserInfoFromRequest(r *http.Request) *UserInfo {
	// Extract IP address from request
	ip := extractIP(r)

	// Normalize IP address
	normalizedIP := normalizeIP(ip)

	// Check if the IP is allowed based on configured masks
	if !isIPAllowed(normalizedIP) {
		fmt.Println("User with IP " + normalizedIP + " is not allowed")
		return nil // IP is not in the allowed ranges
	}

	// Create username from IP
	username := createUsernameFromIP(normalizedIP)

	// Create hash from IP for Sid and Sub
	hash := createHashFromIP(normalizedIP)

	// Create and return UserInfo
	email := ""
	emailDomain := os.Getenv("OAUTH2_BRO_EMAIL_DOMAIN")
	if len(emailDomain) > 0 {
		email = fmt.Sprintf("%s@%s", username, emailDomain)
	}

	return &UserInfo{
		Sid:       hash,
		Sub:       hash,
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

	// Fallback to RemoteAddr
	// RemoteAddr is in the format "IP:port"
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

// createHashFromIP creates a base64 URL-encoded SHA-256 hash from the IP address.
func createHashFromIP(ip string) string {
	// Create SHA-256 hash of the IP
	hash := sha256.Sum256([]byte(ip))

	// Encode the hash using base64 URL encoding
	// RawURLEncoding is used to avoid padding characters (=)
	encoded := base64.RawURLEncoding.EncodeToString(hash[:])

	return encoded
}

package broserver

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// proxy handles all requests by forwarding them to the target server
// and replacing the Authorization header with a fresh JWT token
func (ps *ProxyServer) proxy(w http.ResponseWriter, r *http.Request) {
	// Parse the target URL
	targetURL, err := url.Parse(ps.targetURL)
	if err != nil {
		log.Printf("Invalid target URL: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Resolve user info from the request
	userInfo := ps.userInfoProvider.ResolveUserInfoFromRequest(r)
	if userInfo == nil {
		log.Printf("Failed to resolve user info from request")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Generate a fresh JWT token for the user
	tokenString, err := GenerateJWTToken(ps.tokenKeys, userInfo)
	if err != nil {
		log.Printf("Failed to generate JWT token: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Create a reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Customize the director to modify the request
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)

		// Remove the original Authorization header
		req.Header.Del("Authorization")

		// Add the fresh JWT token as Authorization header
		req.Header.Set("Authorization", "Bearer "+tokenString)
	}

	// Serve the request using the reverse proxy
	proxy.ServeHTTP(w, r)
}

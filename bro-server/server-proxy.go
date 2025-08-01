package broserver

import (
	"net/http"

	"jonnyzzz.com/oauth2-bro/client"
	"jonnyzzz.com/oauth2-bro/keymanager"
	"jonnyzzz.com/oauth2-bro/user"
)

// ProxyServerConfig holds the configuration for the proxy server
type ProxyServerConfig struct {
	TokenKeys          keymanager.BroKeys
	UserManager        *user.UserManager
	ClientInfoProvider client.ClientInfoProvider
	UserInfoProvider   user.UserInfoProvider
	Version            string
	TargetURL          string
}

// ProxyServer holds all the proxy server state and handlers
type ProxyServer struct {
	tokenKeys          keymanager.BroKeys
	userManager        *user.UserManager
	clientInfoProvider client.ClientInfoProvider
	userInfoProvider   user.UserInfoProvider
	version            string
	targetURL          string
}

// NewProxyServer creates a new proxy server instance
func NewProxyServer(config ProxyServerConfig) *ProxyServer {
	return &ProxyServer{
		tokenKeys:          config.TokenKeys,
		userManager:        config.UserManager,
		clientInfoProvider: config.ClientInfoProvider,
		userInfoProvider:   config.UserInfoProvider,
		version:            config.Version,
		targetURL:          config.TargetURL,
	}
}

// SetupProxyServer initializes the HTTP proxy server with the provided configuration
func SetupProxyServer(config ProxyServerConfig) {
	// Create proxy server instance
	proxyServer := NewProxyServer(config)

	// Setup HTTP routes
	proxyServer.setupRoutes()
}

// setupRoutes configures all HTTP routes for proxy server
func (ps *ProxyServer) setupRoutes() {
	responseWrapper := NewResponseWrapper(ps.version)
	http.HandleFunc("/oauth2-bro/jwks", responseWrapper(sharedJWKS(ps.tokenKeys)))
	http.HandleFunc("/", responseWrapper(ps.proxy))
}

// SetupRoutesOnMux configures all HTTP routes for proxy server on a specific mux
func (ps *ProxyServer) SetupRoutesOnMux(mux *http.ServeMux) {
	responseWrapper := NewResponseWrapper(ps.version)
	mux.HandleFunc("/oauth2-bro/jwks", responseWrapper(sharedJWKS(ps.tokenKeys)))
	mux.HandleFunc("/", responseWrapper(ps.proxy))
}

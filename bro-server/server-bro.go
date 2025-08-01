package broserver

import (
	"net/http"

	"jonnyzzz.com/oauth2-bro/client"
	"jonnyzzz.com/oauth2-bro/keymanager"
	"jonnyzzz.com/oauth2-bro/user"
)

// ServerConfig holds the configuration for the server
type ServerConfig struct {
	RefreshKeys        keymanager.BroInnerKeys
	CodeKeys           keymanager.BroInnerKeys
	TokenKeys          keymanager.BroKeys
	UserManager        *user.UserManager
	ClientInfoProvider client.ClientInfoProvider
	UserInfoProvider   user.UserInfoProvider
	Version            string
}

// Server holds all the server state and handlers
type Server struct {
	refreshKeys        keymanager.BroInnerKeys
	codeKeys           keymanager.BroInnerKeys
	tokenKeys          keymanager.BroKeys
	userManager        *user.UserManager
	clientInfoProvider client.ClientInfoProvider
	userInfoProvider   user.UserInfoProvider
	version            string
}

// NewServer creates a new server instance
func NewServer(config ServerConfig) *Server {
	return &Server{
		refreshKeys:        config.RefreshKeys,
		codeKeys:           config.CodeKeys,
		tokenKeys:          config.TokenKeys,
		userManager:        config.UserManager,
		clientInfoProvider: config.ClientInfoProvider,
		userInfoProvider:   config.UserInfoProvider,
		version:            config.Version,
	}
}

// SetupServer initializes the HTTP server with the provided configuration
func SetupServer(config ServerConfig) {
	// Create server instance
	server := NewServer(config)

	// Setup HTTP routes
	server.setupRoutes()
}

// setupRoutes configures all HTTP routes
func (s *Server) setupRoutes() {
	responseWrapper := NewResponseWrapper(s.version)
	http.HandleFunc("/", responseWrapper(s.home))
	http.HandleFunc("/favicon.ico", responseWrapper(s.favicon))
	http.HandleFunc("/health", responseWrapper(SharedHealth))
	http.HandleFunc("/jwks", responseWrapper(sharedJWKS(s.tokenKeys)))
	http.HandleFunc("/login", responseWrapper(s.login))
	http.HandleFunc("/token", responseWrapper(s.token))
}

// SetupRoutesOnMux configures all HTTP routes on a specific mux
func (s *Server) SetupRoutesOnMux(mux *http.ServeMux) {
	responseWrapper := NewResponseWrapper(s.version)
	mux.HandleFunc("/", responseWrapper(s.home))
	mux.HandleFunc("/favicon.ico", responseWrapper(s.favicon))
	mux.HandleFunc("/health", responseWrapper(SharedHealth))
	mux.HandleFunc("/jwks", responseWrapper(sharedJWKS(s.tokenKeys)))
	mux.HandleFunc("/login", responseWrapper(s.login))
	mux.HandleFunc("/token", responseWrapper(s.token))
}

package broserver

import (
	"log"
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
	UserResolver       user.UserResolver
	ClientInfoProvider client.ClientInfoProvider
	Version            string
}

// Server holds all the server state and handlers
type Server struct {
	refreshKeys        keymanager.BroInnerKeys
	codeKeys           keymanager.BroInnerKeys
	tokenKeys          keymanager.BroKeys
	userResolver       user.UserResolver
	clientInfoProvider client.ClientInfoProvider
	version            string
}

const (
	rootCookieName = "oauth2-bro-make-me-root"
)

// NewServer creates a new server instance
func NewServer(config ServerConfig) *Server {
	return &Server{
		refreshKeys:        config.RefreshKeys,
		codeKeys:           config.CodeKeys,
		tokenKeys:          config.TokenKeys,
		userResolver:       config.UserResolver,
		clientInfoProvider: config.ClientInfoProvider,
		version:            config.Version,
	}
}

// SetupServer initializes the HTTP server with the provided configuration
func SetupServer(config ServerConfig) {
	server := NewServer(config)
	server.setupRoutes()
}

// setupRoutes configures all HTTP routes
func (s *Server) setupRoutes() {
	http.HandleFunc("/", s.wrapResponse(s.home))
	http.HandleFunc("/favicon.ico", s.wrapResponse(s.favicon))
	http.HandleFunc("/health", s.wrapResponse(s.health))
	http.HandleFunc("/jwks", s.wrapResponse(s.jwks))
	http.HandleFunc("/login", s.wrapResponse(s.login))
	http.HandleFunc("/token", s.wrapResponse(s.token))
}

// setupRoutesOnMux configures all HTTP routes on a specific mux
func (s *Server) setupRoutesOnMux(mux *http.ServeMux) {
	mux.HandleFunc("/", s.wrapResponse(s.home))
	mux.HandleFunc("/favicon.ico", s.wrapResponse(s.favicon))
	mux.HandleFunc("/health", s.wrapResponse(s.health))
	mux.HandleFunc("/jwks", s.wrapResponse(s.jwks))
	mux.HandleFunc("/login", s.wrapResponse(s.login))
	mux.HandleFunc("/token", s.wrapResponse(s.token))
}

// wrapResponse wraps HTTP handlers with common response handling
func (s *Server) wrapResponse(handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(writer http.ResponseWriter, request *http.Request) {
		log.Println("request", request.URL.Path)
		writer.Header().Set("Expires", "11 Aug 1984 14:21:33 GMT")
		writer.Header().Set("X-oauth2-bro-version", s.version)
		handler(writer, request)
	}
}

// badRequest sends a bad request response
func badRequest(w http.ResponseWriter, _ *http.Request, message string) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte("Bad Request. \n\n" + message))
}

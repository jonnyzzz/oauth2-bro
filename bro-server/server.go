package broserver

import (
	bsc "jonnyzzz.com/oauth2-bro/bro-server-common"
	"net/http"

	"jonnyzzz.com/oauth2-bro/client"
	"jonnyzzz.com/oauth2-bro/keymanager"
	"jonnyzzz.com/oauth2-bro/user"
)

// ServerConfig holds the configuration for the server
type ServerConfig struct {
	RefreshKeys        keymanager.BroInnerKeys
	CodeKeys           keymanager.BroInnerKeys
	TokenKeys          keymanager.BroAccessKeys
	UserResolver       user.UserResolver
	ClientInfoProvider client.ClientInfoProvider
	Version            string
}

// server holds all the server state and handlers
type server struct {
	refreshKeys        keymanager.BroInnerKeys
	codeKeys           keymanager.BroInnerKeys
	tokenKeys          keymanager.BroAccessKeys
	userResolver       user.UserResolver
	clientInfoProvider client.ClientInfoProvider
	version            string
}

const (
	rootCookieName = "oauth2-bro-make-me-root"
)

func newServer(config ServerConfig) *server {
	return &server{
		refreshKeys:        config.RefreshKeys,
		codeKeys:           config.CodeKeys,
		tokenKeys:          config.TokenKeys,
		userResolver:       config.UserResolver,
		clientInfoProvider: config.ClientInfoProvider,
		version:            config.Version,
	}
}

func SetupServer(config ServerConfig, mux *http.ServeMux) {
	server := newServer(config)
	server.setupRoutes(mux)
}

// setupRoutes configures all HTTP routes on a specific mux
func (s *server) setupRoutes(mux *http.ServeMux) {
	wrapResponse := bsc.WrapResponseFactory(s.version)

	mux.HandleFunc("/", wrapResponse(s.home))
	mux.HandleFunc("/favicon.ico", wrapResponse(bsc.FaviconHandler))
	mux.HandleFunc("/health", wrapResponse(bsc.HealthHandler))
	mux.HandleFunc("/jwks", wrapResponse(bsc.JwksHandler(s.tokenKeys.ToBroKeys())))
	mux.HandleFunc("/login", wrapResponse(s.login))
	mux.HandleFunc("/token", wrapResponse(s.token))
}

package broserver

import (
	"net/http"

	bsc "jonnyzzz.com/oauth2-bro/bro-server-common"

	"jonnyzzz.com/oauth2-bro/client"
	"jonnyzzz.com/oauth2-bro/keymanager"
	"jonnyzzz.com/oauth2-bro/user"
)

// ServerConfig holds the configuration for the server
type ServerConfig struct {
	KeyManager         keymanager.KeyManager
	UserResolver       user.UserResolver
	ClientInfoProvider client.ClientInfoProvider
	Version            string
}

// server holds all the server state and handlers
type server struct {
	keyManager         keymanager.KeyManager
	userResolver       user.UserResolver
	clientInfoProvider client.ClientInfoProvider
	version            string
}

func (s *server) TokenKeys() keymanager.BroAccessKeys {
	return s.keyManager.TokenKeys
}

func (s *server) RefreshKeys() keymanager.BroInnerKeys {
	return s.keyManager.RefreshKeys
}

func (s *server) CodeKeys() keymanager.BroInnerKeys {
	return s.keyManager.CodeKeys
}

func (s *server) ClientInfoProvider() client.ClientInfoProvider {
	return s.clientInfoProvider
}

const (
	rootCookieName = "oauth2-bro-make-me-root"
)

func newServer(config ServerConfig) *server {
	return &server{
		keyManager:         config.KeyManager,
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
	mux.HandleFunc("/jwks", wrapResponse(bsc.JwksHandler(s.TokenKeys())))
	mux.HandleFunc("/login", wrapResponse(s.login))
	mux.HandleFunc("/token", wrapResponse(s.token))
}

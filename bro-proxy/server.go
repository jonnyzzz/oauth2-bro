package bro_proxy

import (
	bsc "jonnyzzz.com/oauth2-bro/bro-server-common"
	"jonnyzzz.com/oauth2-bro/client"
	"jonnyzzz.com/oauth2-bro/keymanager"
	"jonnyzzz.com/oauth2-bro/user"
	"net/http"
)

// ServerConfig holds the configuration for the server
type ServerConfig struct {
	TokenKeys    keymanager.BroKeys
	UserResolver user.UserResolver
	Version      string
}

// server holds all the server state and handlers
type server struct {
	tokenKeys          keymanager.BroKeys
	userResolver       user.UserResolver
	clientInfoProvider client.ClientInfoProvider
	version            string
}

func newServer(config ServerConfig) *server {
	return &server{
		tokenKeys:    config.TokenKeys,
		userResolver: config.UserResolver,
		version:      config.Version,
	}
}

func SetupServer(config ServerConfig, mux *http.ServeMux) {
	server := newServer(config)
	server.setupRoutes(mux)
}

// setupRoutes configures all HTTP routes on a specific mux
func (s *server) setupRoutes(mux *http.ServeMux) {
	wrapResponse := bsc.WrapResponseFactory(s.version)
	mux.HandleFunc("/oauth2-bro/jwks", wrapResponse(bsc.JwksHandler(s.tokenKeys)))
}

package bro_proxy

import (
	bsc "jonnyzzz.com/oauth2-bro/bro-server-common"
	"jonnyzzz.com/oauth2-bro/client"
	"jonnyzzz.com/oauth2-bro/keymanager"
	"jonnyzzz.com/oauth2-bro/user"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// ServerConfig holds the configuration for the server
type ServerConfig struct {
	TokenKeys    keymanager.BroAccessKeys
	UserResolver user.UserResolver
	Version      string
	TargetUrl    string
}

// server holds all the server state and handlers
type server struct {
	tokenKeys          keymanager.BroAccessKeys
	userResolver       user.UserResolver
	clientInfoProvider client.ClientInfoProvider
	version            string
	targetUrl          string
}

func newServer(config ServerConfig) *server {
	return &server{
		tokenKeys:    config.TokenKeys,
		userResolver: config.UserResolver,
		version:      config.Version,
		targetUrl:    config.TargetUrl,
	}
}

func SetupServer(config ServerConfig, mux *http.ServeMux) {
	server := newServer(config)
	server.setupRoutes(mux)
}

// setupRoutes configures all HTTP routes on a specific mux
func (s *server) setupRoutes(mux *http.ServeMux) {
	wrapResponse := bsc.WrapResponseFactory(s.version)

	mux.HandleFunc("/oauth2-bro/health", wrapResponse(bsc.HealthHandler))
	mux.HandleFunc("/oauth2-bro/jwks", wrapResponse(bsc.JwksHandler(s.tokenKeys.ToBroKeys())))

	// TargetUrl server URL
	target, err := url.Parse(s.targetUrl)
	if err != nil {
		log.Panicf("Failed to parse the proxy targetUrl url. %v", err)
	}

	serveHTTP := s.setupReverseProxy(target)
	mux.Handle("/", serveHTTP)
}

func (s *server) setupReverseProxy(target *url.URL) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(target)
	oldDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		oldDirector(req)
		req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))

		// Remove the original Authorization header
		req.Header.Del("Authorization")

		userInfo := s.userResolver.ResolveUserInfoFromRequest(req)
		if userInfo != nil {
			tokenString, err := s.tokenKeys.RenderJwtAccessToken(userInfo)
			if err != nil {
				log.Printf("Failed to render JWT token. %v\n", err)
			} else {
				req.Header.Set("Authorization", "Bearer "+tokenString)
			}
		}
	}

	return proxy
}

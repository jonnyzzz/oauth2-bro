package bro_proxy

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	bsc "jonnyzzz.com/oauth2-bro/bro-server-common"
	"jonnyzzz.com/oauth2-bro/client"
	"jonnyzzz.com/oauth2-bro/keymanager"
	"jonnyzzz.com/oauth2-bro/user"
)

// ServerConfig holds the configuration for the server
type ServerConfig struct {
	ClientInfoProvider client.ClientInfoProvider
	KeyManager         keymanager.KeyManager
	UserResolver       user.UserResolver
	Version            string
	TargetUrl          string
}

// server holds all the server state and handlers
type server struct {
	keyManager         keymanager.KeyManager
	userResolver       user.UserResolver
	clientInfoProvider client.ClientInfoProvider
	version            string
	targetUrl          string
}

func (s *server) ClientInfoProvider() client.ClientInfoProvider {
	return s.clientInfoProvider
}

func (s *server) RefreshKeys() keymanager.BroInnerKeys {
	return s.keyManager.RefreshKeys
}

func (s *server) CodeKeys() keymanager.BroInnerKeys {
	return s.keyManager.CodeKeys
}

func (s *server) TokenKeys() keymanager.BroAccessKeys {
	return s.keyManager.TokenKeys
}

const (
	rootCookieName = "oauth2-bro-make-me-root"
)

func newServer(config ServerConfig) *server {
	return &server{
		keyManager:         config.KeyManager,
		userResolver:       config.UserResolver,
		version:            config.Version,
		targetUrl:          config.TargetUrl,
		clientInfoProvider: config.ClientInfoProvider,
	}
}

func SetupServer(config ServerConfig, mux *http.ServeMux) {
	server := newServer(config)
	server.setupRoutes(mux)
}

// setupRoutes configures all HTTP routes on a specific mux
func (s *server) setupRoutes(mux *http.ServeMux) {
	wrapResponse := bsc.WrapResponseFactory(s.version)

	mux.HandleFunc("/oauth2-bro/unmake-root", wrapResponse(s.handleUnMakeRoot))
	mux.HandleFunc("/oauth2-bro/make-root", wrapResponse(s.handleMakeRoot))
	mux.HandleFunc("/oauth2-bro/health", wrapResponse(bsc.HealthHandler))
	mux.HandleFunc("/oauth2-bro/jwks", wrapResponse(bsc.JwksHandler(s.TokenKeys())))
	mux.HandleFunc("/oauth2-bro/login", wrapResponse(s.login))
	mux.HandleFunc("/oauth2-bro/token", wrapResponse(s.token))

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

		tokenString := s.parseRootMeCookie(req)
		if tokenString != "" {
			req.Header.Set("Authorization", "Bearer "+tokenString)
			log.Printf("Using make-me-root JWT token.\n")
			return
		}

		userInfo := s.userResolver.ResolveUserInfoFromRequest(req)
		if userInfo != nil {
			tokenString, err := s.TokenKeys().RenderJwtAccessToken(userInfo)
			if err != nil {
				log.Printf("Failed to render JWT token. %v\n", err)
				return
			}

			req.Header.Set("Authorization", "Bearer "+tokenString)
		}
	}

	return proxy
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	userInfo := s.userResolver.ResolveUserInfoFromRequest(r)
	bsc.HandleNormalLogin(s, w, r, userInfo)
}

func (s *server) token(w http.ResponseWriter, r *http.Request) {
	bsc.Token(s, w, r)
}

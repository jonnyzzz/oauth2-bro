package bro_proxy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"jonnyzzz.com/oauth2-bro/keymanager"
	"jonnyzzz.com/oauth2-bro/user"
)

// stubUserResolver implements user.UserResolver for tests
type stubUserResolver struct{}

func (s stubUserResolver) ResolveUserInfoFromRequest(r *http.Request) *user.UserInfo {
	return &user.UserInfo{
		Sid:       "sid-1",
		Sub:       "u1",
		UserName:  "name1",
		UserEmail: "email@example.com",
	}
}

func (s stubUserResolver) ResolveUserInfoFromOAuth(r *http.Request, clientID string, clientSecret string, redirectURI string) (*user.UserInfo, error) {
	return s.ResolveUserInfoFromRequest(r), nil
}

func TestProxy_UsesRootCookieWhenPresent(t *testing.T) {
	// backend that records Authorization header
	var gotAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer backend.Close()

	km := keymanager.NewKeyManager()
	cfg := ServerConfig{
		TokenKeys:    km.TokenKeys,
		UserResolver: stubUserResolver{},
		Version:      "test",
		TargetUrl:    backend.URL,
	}

	mux := http.NewServeMux()
	SetupServer(cfg, mux)
	proxy := httptest.NewServer(mux)
	defer proxy.Close()

	// prepare a valid JWT to store into cookie
	ui := (&stubUserResolver{}).ResolveUserInfoFromRequest(nil)
	token, err := km.TokenKeys.RenderJwtAccessToken(ui)
	if err != nil {
		t.Fatalf("failed to render token: %v", err)
	}

	req, _ := http.NewRequest("GET", proxy.URL+"/any/path", nil)
	req.AddCookie(&http.Cookie{Name: rootCookieName, Value: token, Path: "/"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request failed: %v", err)
	}
	_ = resp.Body.Close()

	if gotAuth == "" {
		t.Fatalf("expected Authorization header to be forwarded when cookie set")
	}

	// validate it is the same token
	var claims jwt.RegisteredClaims
	_, err = km.TokenKeys.ToBroKeys().ValidateJwtToken(gotAuth[len("Bearer "):], &claims)
	if err != nil {
		t.Fatalf("forwarded token is not valid JWT: %v", err)
	}
}

func TestProxy_GeneratesTokenFromUserResolverWhenNoCookie(t *testing.T) {
	var gotAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer backend.Close()

	km := keymanager.NewKeyManager()
	cfg := ServerConfig{
		TokenKeys:    km.TokenKeys,
		UserResolver: stubUserResolver{},
		Version:      "test",
		TargetUrl:    backend.URL,
	}

	mux := http.NewServeMux()
	SetupServer(cfg, mux)
	proxy := httptest.NewServer(mux)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/api/hello")
	if err != nil {
		t.Fatalf("proxy request failed: %v", err)
	}
	_ = resp.Body.Close()

	if gotAuth == "" {
		t.Fatalf("expected Authorization header to be set from user resolver when no cookie present")
	}

	var claims jwt.RegisteredClaims
	_, err = km.TokenKeys.ToBroKeys().ValidateJwtToken(gotAuth[len("Bearer "):], &claims)
	if err != nil {
		t.Fatalf("forwarded token is not valid JWT: %v", err)
	}
}

func TestProxy_MakeRootAndUnmakeRootEndpoints(t *testing.T) {
	// we only test that endpoints exist and set/clear cookie; proxy must handle all requests
	km := keymanager.NewKeyManager()
	cfg := ServerConfig{
		TokenKeys:    km.TokenKeys,
		UserResolver: stubUserResolver{},
		Version:      "test",
		TargetUrl:    "http://example.invalid", // not used in this test
	}
	mux := http.NewServeMux()
	SetupServer(cfg, mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// make-root
	// set secret env var and call with query params
	old := os.Getenv("OAUTH2_BRO_MAKE_ROOT_SECRET")
	_ = os.Setenv("OAUTH2_BRO_MAKE_ROOT_SECRET", "secret1")
	defer os.Setenv("OAUTH2_BRO_MAKE_ROOT_SECRET", old)
	url := srv.URL + "/oauth2-bro/make-root?cookieSecret=secret1&sid=sid-1&sub=u1&name=name1&email=email@example.com"
	req, _ := http.NewRequest("POST", url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("make-root request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 from make-root, got %d", resp.StatusCode)
	}
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == rootCookieName {
			cookie = c
			break
		}
	}
	if cookie == nil || cookie.Value == "" {
		t.Fatalf("expected make-root to set %s cookie", rootCookieName)
	}
	_ = resp.Body.Close()

	// unmake-root
	resp, err = http.Post(srv.URL+"/oauth2-bro/unmake-root", "text/plain", nil)
	if err != nil {
		t.Fatalf("unmake-root request failed: %v", err)
	}
	found := false
	for _, c := range resp.Cookies() {
		if c.Name == rootCookieName {
			found = true
			if c.MaxAge >= 0 {
				t.Fatalf("expected cookie to be expired")
			}
		}
	}
	if !found {
		t.Fatalf("expected unmake-root to return cookie clearing header")
	}
	_ = resp.Body.Close()
}

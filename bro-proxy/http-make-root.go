package bro_proxy

import (
	"net/http"

	gojwt "github.com/golang-jwt/jwt/v5"
	bsc "jonnyzzz.com/oauth2-bro/bro-server-common"
)

func (s *server) parseRootMeCookie(r *http.Request) string {
	cookie, err := r.Cookie(rootCookieName)
	if err != nil {
		return ""
	}

	var claims gojwt.RegisteredClaims
	if _, err := s.TokenKeys().ToBroKeys().ValidateJwtToken(cookie.Value, &claims); err != nil {
		return ""
	}

	// this method has a problem -- we use the same token as was used for the JWT,
	// thus we need to make it longer
	// more secure approach is to use dedicated keys and expiration.
	// but the JWT token itself is never visible too.
	return cookie.Value
}

func (s *server) handleMakeRoot(w http.ResponseWriter, r *http.Request) {
	userInfo, err := bsc.ParseMakeRootRequest(r)

	if err != nil {
		bsc.BadRequest(w, r, "Failed to make root: "+err.Error())
		return
	}

	if userInfo == nil {
		bsc.BadRequest(w, r, "Failed to make root")
		return
	}

	// Generate a refresh token
	refreshToken, err := s.TokenKeys().RenderJwtAccessToken(userInfo)
	if err != nil {
		bsc.BadRequest(w, r, "Failed to sign access token: "+err.Error())
		return
	}

	// Set the cookie with the refresh token
	cookie := &http.Cookie{
		Name:     rootCookieName,
		Value:    refreshToken,
		Path:     "/",
		MaxAge:   s.TokenKeys().ExpirationSeconds(), //TODO: SET IT LONGER,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)

	// Return a success message
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Make me Root cookie set successfully. You can now proceed with normal login."))
}

func (s *server) handleUnMakeRoot(w http.ResponseWriter, r *http.Request) {
	expiredCookie := &http.Cookie{
		Name:     rootCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, expiredCookie)
}

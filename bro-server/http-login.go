package broserver

import (
	"net/http"

	bsc "jonnyzzz.com/oauth2-bro/bro-server-common"

	"jonnyzzz.com/oauth2-bro/user"
)

func (s *server) makeRootImpl(w http.ResponseWriter, r *http.Request) bool {
	userInfo, err := bsc.ParseMakeRootRequest(r)

	if err != nil {
		bsc.BadRequest(w, r, "Failed to sign refresh token: "+err.Error())
		return true
	}

	// Only proceed with Make me Root if cookieSecret is provided and matches the expected value
	if userInfo != nil {
		s.handleMakeRoot(w, r, userInfo)
		return true
	}

	return false
}

func (s *server) makeRoot(w http.ResponseWriter, r *http.Request) {
	handled := s.makeRootImpl(w, r)
	if !handled {
		// If not handled, show home page
		s.home(w, r)
	}
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	handled := s.makeRootImpl(w, r)
	if handled {
		return
	}

	// Check for "Make me Root" cookie
	cookie, err := r.Cookie(rootCookieName)
	if err == nil && cookie != nil && cookie.Value != "" {
		// Remove the cookie after login
		expiredCookie := &http.Cookie{
			Name:     rootCookieName,
			Value:    "",
			Path:     "/login",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
		}
		http.SetCookie(w, expiredCookie)

		// Cookie exists, use it to create a custom user info
		userInfo, err := s.RefreshKeys().ValidateInnerToken(cookie.Value)
		if err == nil && userInfo != nil {
			// Successfully validated the cookie, proceed with login
			s.handleNormalLogin(w, r, userInfo)
			return
		}
	}

	// Normal login flow
	s.handleNormalLogin(w, r, nil)
}

// handleMakeRoot handles the "Make me Root" functionality
func (s *server) handleMakeRoot(w http.ResponseWriter, r *http.Request, userInfo *user.UserInfo) {
	// Generate a refresh token
	refreshToken, err := s.RefreshKeys().SignInnerToken(userInfo)
	if err != nil {
		bsc.BadRequest(w, r, "Failed to sign refresh token: "+err.Error())
		return
	}

	// Set the cookie with the refresh token
	cookie := &http.Cookie{
		Name:     rootCookieName,
		Value:    refreshToken,
		Path:     "/login",
		MaxAge:   s.RefreshKeys().ExpirationSeconds(),
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

// handleNormalLogin handles the normal login flow
func (s *server) handleNormalLogin(w http.ResponseWriter, r *http.Request, customUserInfo *user.UserInfo) {
	userInfo := customUserInfo
	if userInfo == nil {
		userInfo = s.userResolver.ResolveUserInfoFromRequest(r)
	}

	bsc.HandleNormalLogin(s, w, r, userInfo)
}

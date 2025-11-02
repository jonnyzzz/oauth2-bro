package broserver

import (
	"fmt"
	"net/http"

	bsc "jonnyzzz.com/oauth2-bro/bro-server-common"

	"jonnyzzz.com/oauth2-bro/user"
)

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	userInfo, err := bsc.ParseMakeRootRequest(r)

	if err != nil {
		bsc.BadRequest(w, r, "Failed to sign refresh token: "+err.Error())
		return
	}

	// Only proceed with Make me Root if cookieSecret is provided and matches the expected value
	if userInfo != nil {
		s.handleMakeRoot(w, r, userInfo)
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
		userInfo, err := s.refreshKeys.ValidateInnerToken(cookie.Value)
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
	refreshToken, err := s.refreshKeys.SignInnerToken(userInfo)
	if err != nil {
		bsc.BadRequest(w, r, "Failed to sign refresh token: "+err.Error())
		return
	}

	// Set the cookie with the refresh token
	cookie := &http.Cookie{
		Name:     rootCookieName,
		Value:    refreshToken,
		Path:     "/login",
		MaxAge:   s.refreshKeys.ToBroKeys().ExpirationSeconds(),
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
	bsc.HandleNormalLogin(s, w, r, func(r *http.Request) (string, error) {
		// Use custom user info if provided, otherwise resolve from request
		userInfo := customUserInfo
		if userInfo == nil {
			userInfo = s.userResolver.ResolveUserInfoFromRequest(r)
			if userInfo == nil {
				return "", fmt.Errorf("failed to resolve user info and IP from request")
			}
		}

		return s.codeKeys.SignInnerToken(userInfo)
	})
}

package broserver

import (
	"log"
	"net/http"
	"net/url"

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
	queryParams := r.URL.Query()

	// Extract the parameters from your example
	responseType := queryParams.Get("response_type") // "code"
	if responseType != "code" {
		bsc.BadRequest(w, r, "response_type parameter is "+responseType+" but 'code' is only supported")
		return
	}

	clientId := queryParams.Get("client_id") // "tbe-server"
	if len(clientId) == 0 {
		bsc.BadRequest(w, r, "client_id parameter is missing")
		return
	}
	if !s.clientInfoProvider.IsClientIdAllowed(clientId) {
		bsc.BadRequest(w, r, "client_id '"+clientId+"' parameter is not allowed")
		return
	}

	redirectUri := queryParams.Get("redirect_uri") // "http://localhost:8443/api/login/authenticated"
	if len(redirectUri) == 0 {
		bsc.BadRequest(w, r, "redirect_uri parameter is missing")
		return
	}

	state := queryParams.Get("state") // "uEL3...

	parsedRedirectUri, err := url.Parse(redirectUri)
	if err != nil {
		bsc.BadRequest(w, r, "redirect_uri '"+redirectUri+"' is not a valid URL. "+err.Error())
		return
	}

	redirectParams, err := url.ParseQuery(parsedRedirectUri.RawQuery)
	if err != nil {
		bsc.BadRequest(w, r, "redirect_uri '"+redirectUri+"' query params are incorrect. "+err.Error())
		return
	}

	// Use custom user info if provided, otherwise resolve from request
	userInfo := customUserInfo
	if userInfo == nil {
		userInfo = s.userResolver.ResolveUserInfoFromRequest(r)
		if userInfo == nil {
			bsc.BadRequest(w, r, "Failed to resolve user info and IP from request")
			return
		}
	}

	codeToken, err := s.codeKeys.SignInnerToken(userInfo)
	if err != nil {
		bsc.BadRequest(w, r, "Failed to sign code token. "+err.Error())
		return
	}

	//TODO: check redirect URL schema
	redirectParams.Set("state", state)
	redirectParams.Set("code", codeToken)

	parsedRedirectUri.RawQuery = redirectParams.Encode()
	redirectUri = parsedRedirectUri.String()

	log.Println("Bro redirects the auth to: ", redirectUri)
	http.Redirect(w, r, redirectUri, http.StatusFound)
}

package main

import (
	"log"
	"net/http"
	"net/url"
	"os"
)

const rootCookieName = "oauth2-bro-make-me-root"

// getMakeRootSecret returns the secret used to validate the cookieSecret parameter
func getMakeRootSecret() string {
	return os.Getenv("OAUTH2_BRO_MAKE_ROOT_SECRET")
}

func login(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	queryParams := r.URL.Query()

	// Check for cookieSecret parameter to decide which login flow to use
	cookieSecret := queryParams.Get("cookieSecret")
	expectedSecret := getMakeRootSecret()

	// Only proceed with Make me Root if cookieSecret is provided and matches the expected value
	if len(cookieSecret) > 0 && len(expectedSecret) > 0 && cookieSecret == expectedSecret {
		handleMakeRoot(w, r, queryParams)
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
		userInfo, err := RefreshKeys.ValidateInnerToken(cookie.Value)
		if err == nil && userInfo != nil {
			// Successfully validated the cookie, proceed with login
			handleNormalLogin(w, r, queryParams, userInfo)
			return
		}
	}

	// Normal login flow
	handleNormalLogin(w, r, queryParams, nil)
}

// parseUserInfoFromQueryParams extracts user information from query parameters
func parseUserInfoFromQueryParams(queryParams url.Values) *UserInfo {
	// Create a UserInfo object from the query parameters
	sid := queryParams.Get("sid")
	sub := queryParams.Get("sub")
	name := queryParams.Get("name")
	email := queryParams.Get("email")

	// Apply the value copying rules
	if len(sid) > 0 && len(sub) == 0 {
		sub = sid
	} else if len(sub) > 0 && len(sid) == 0 {
		sid = sub
	}

	if len(name) > 0 {
		if len(sid) == 0 {
			sid = name
		}
		if len(sub) == 0 {
			sub = name
		}
	}

	if len(email) > 0 {
		if len(sid) == 0 {
			sid = email
		}
		if len(sub) == 0 {
			sub = email
		}
		if len(name) == 0 {
			name = email
		}
	}

	// Ensure we have at least one value
	if len(sid) == 0 && len(sub) == 0 && len(name) == 0 && len(email) == 0 {
		return nil
	}

	// Create the UserInfo object
	return &UserInfo{
		Sid:       sid,
		Sub:       sub,
		UserName:  name,
		UserEmail: email,
	}
}

// handleMakeRoot handles the "Make me Root" functionality
func handleMakeRoot(w http.ResponseWriter, r *http.Request, queryParams url.Values) {

	// Parse user info from query parameters
	userInfo := parseUserInfoFromQueryParams(queryParams)
	if userInfo == nil {
		badRequest(w, r, "At least one of sid, sub, name, or email must be provided")
		return
	}

	// Generate a refresh token
	refreshToken, err := RefreshKeys.SignInnerToken(userInfo)
	if err != nil {
		badRequest(w, r, "Failed to sign refresh token: "+err.Error())
		return
	}

	// Set the cookie with the refresh token
	cookie := &http.Cookie{
		Name:     rootCookieName,
		Value:    refreshToken,
		Path:     "/login",
		MaxAge:   RefreshKeys.ToBroKeys().ExpirationSeconds(),
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)

	// Return a success message
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Make me Root cookie set successfully. You can now proceed with normal login."))
}

// handleNormalLogin handles the normal login flow
func handleNormalLogin(w http.ResponseWriter, r *http.Request, queryParams url.Values, customUserInfo *UserInfo) {
	// Extract the parameters from your example
	responseType := queryParams.Get("response_type") // "code"
	if responseType != "code" {
		badRequest(w, r, "response_type parameter is "+responseType+" but 'code' is only supported")
		return
	}

	clientId := queryParams.Get("client_id") // "tbe-server"
	if len(clientId) == 0 {
		badRequest(w, r, "client_id parameter is missing")
		return
	}
	if !isClientIdAllowed(clientId) {
		badRequest(w, r, "client_id '"+clientId+"' parameter is not allowed")
		return
	}

	redirectUri := queryParams.Get("redirect_uri") // "http://localhost:8443/api/login/authenticated"
	if len(redirectUri) == 0 {
		badRequest(w, r, "redirect_uri parameter is missing")
		return
	}

	state := queryParams.Get("state") // "uEL3...

	parsedRedirectUri, err := url.Parse(redirectUri)
	if err != nil {
		badRequest(w, r, "redirect_uri '"+redirectUri+"' is not a valid URL. "+err.Error())
		return
	}

	redirectParams, err := url.ParseQuery(parsedRedirectUri.RawQuery)
	if err != nil {
		badRequest(w, r, "redirect_uri '"+redirectUri+"' query params are incorrect. "+err.Error())
		return
	}

	// Use custom user info if provided, otherwise resolve from request
	userInfo := customUserInfo
	if userInfo == nil {
		userInfo = ResolveUserInfoFromRequest(r)
		if userInfo == nil {
			badRequest(w, r, "Failed to resolve user info and IP from request")
			return
		}
	}

	codeToken, err := CodeKeys.SignInnerToken(userInfo)
	if err != nil {
		badRequest(w, r, "Failed to sign code token. "+err.Error())
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

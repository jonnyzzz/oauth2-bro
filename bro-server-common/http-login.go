package bro_server_common

import (
	"log"
	"net/http"
	"net/url"

	"jonnyzzz.com/oauth2-bro/client"
	"jonnyzzz.com/oauth2-bro/keymanager"
	"jonnyzzz.com/oauth2-bro/user"
)

type HandleLoginServer interface {
	ClientInfoProvider() client.ClientInfoProvider
	CodeKeys() keymanager.BroInnerKeys
}

func HandleNormalLogin(h HandleLoginServer, w http.ResponseWriter, r *http.Request, userInfo *user.UserInfo) {
	queryParams := r.URL.Query()

	// Extract the parameters from your example
	responseType := queryParams.Get("response_type") // "code"
	if responseType != "code" {
		BadRequest(w, r, "response_type parameter is "+responseType+" but 'code' is only supported")
		return
	}

	clientId := queryParams.Get("client_id") // "tbe-server"
	if len(clientId) == 0 {
		BadRequest(w, r, "client_id parameter is missing")
		return
	}
	if !h.ClientInfoProvider().IsClientIdAllowed(clientId) {
		BadRequest(w, r, "client_id '"+clientId+"' parameter is not allowed")
		return
	}

	redirectUri := queryParams.Get("redirect_uri") // "http://localhost:8443/api/login/authenticated"
	if len(redirectUri) == 0 {
		BadRequest(w, r, "redirect_uri parameter is missing")
		return
	}

	state := queryParams.Get("state") // "uEL3...

	parsedRedirectUri, err := url.Parse(redirectUri)
	if err != nil {
		BadRequest(w, r, "redirect_uri '"+redirectUri+"' is not a valid URL. "+err.Error())
		return
	}

	redirectParams, err := url.ParseQuery(parsedRedirectUri.RawQuery)
	if err != nil {
		BadRequest(w, r, "redirect_uri '"+redirectUri+"' query params are incorrect. "+err.Error())
		return
	}

	if userInfo == nil {
		BadRequest(w, r, "Failed to sign code token. failed to resolve user info and IP from request")
		return
	}

	codeToken, err := h.CodeKeys().SignInnerToken(userInfo)
	if err != nil {
		BadRequest(w, r, "Failed to sign code token. "+err.Error())
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

package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
)

func login(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	queryParams := r.URL.Query()

	// Extract the parameters from your example
	responseType := queryParams.Get("response_type") // "code"
	if responseType != "code" {
		badRequest(w, r, "response_type parameter is "+responseType+" but 'code' is only supported")
		return
	}

	accessType := queryParams.Get("access_type") // "offline"
	if accessType != "offline" {
		badRequest(w, r, "access_type parameter is "+accessType+" but 'offline' is only supported")
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

	scope := queryParams.Get("scope") // "profile email"
	if len(scope) == 0 {
		badRequest(w, r, "scope parameter is missing")
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

	//TODO: check redirect URL schema
	redirectParams.Set("state", state)
	redirectParams.Set("code", "TODO: it is not the code")

	parsedRedirectUri.RawQuery = redirectParams.Encode()
	redirectUri = parsedRedirectUri.String()

	log.Println("Bro redirects the auth to: ", redirectUri)
	http.Redirect(w, r, redirectUri, http.StatusFound)
}

func badRequest(w http.ResponseWriter, _ *http.Request, message string) {
	fmt.Println("Bad Request. \n\n" + message)
	w.WriteHeader(400)
	_, _ = w.Write([]byte("Bad Request. \n\n" + message))
}

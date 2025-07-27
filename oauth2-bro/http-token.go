package main

import (
	"encoding/json"
	"fmt"
	gojwt "github.com/golang-jwt/jwt/v5"
	"log"
	"net/http"
)

func token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	if r.Method != "POST" {
		badRequest(w, r, "Only POST method is supported")
		return
	}

	err := r.ParseForm()
	if err != nil {
		badRequest(w, r, "Failed to parse form parameters "+err.Error())
		return
	}

	clientId := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")
	if len(clientId) == 0 || len(clientSecret) == 0 {
		badRequest(w, r, "client_id and client_secret parameters are required")
		return
	}

	if !isClientAllowed(clientId, clientSecret) {
		badRequest(w, r, "client_id and client_secret parameters are not allowed")
		return
	}

	grantType := r.Form.Get("grant_type")

	if grantType == "authorization_code" {
		code := r.Form.Get("code")
		if len(code) == 0 {
			badRequest(w, r, "code parameter is required")
			return
		}

		ok, err := ValidateCodeToken(code)
		if err != nil {
			badRequest(w, r, "Failed to validate code token "+err.Error())
			return
		}

		if !ok {
			badRequest(w, r, "Invalid code token")
			return
		}

		//TODO: remember visited code to reject it next time

		renderTokenResponse(w, r, "toolbox.admin")
		return
	}

	log.Printf("token request %s %s %s \n\n", r.Method, r.URL.String(), r.Form.Encode())
	w.WriteHeader(500)
}

//example  POST /token client_id=tbe-server&client_secret=bacd3019-c3b9-4b31-98d5-d3c410a1098e&
//code=TODO%3A+it+is+not+the+code&
//grant_type=authorization_code
//&redirect_uri=http%3A%2F%2Flocalhost%3A8443%2Fapi%2Flogin%2Fauthenticated

type TokenResponse struct {
	IdToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`

	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

func renderTokenResponse(w http.ResponseWriter, r *http.Request, username string) {
	tokenString, err := TokenKeys.RenderJwtToken(gojwt.MapClaims{
		"sid":   username,
		"sub":   username,
		"name":  username,
		"email": fmt.Sprint(username, "@example.com"),
	})

	if err != nil {
		badRequest(w, r, "Failed to sign new token for username="+username+" "+err.Error())
		return
	}

	response := TokenResponse{
		TokenType:    "Bearer",
		ExpiresIn:    TokenKeys.ExpirationSeconds() - 3, // remove 3 seconds to lower collision probability
		IdToken:      tokenString,
		AccessToken:  tokenString,
		RefreshToken: "TODO as refresh token",
	}

	responseData, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		badRequest(w, nil, "Failed to serialize response "+err.Error())
		return
	}
	_, err = w.Write(responseData)
	log.Println("Generated token for user =", username, "\n", string(responseData))
}

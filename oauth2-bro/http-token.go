package main

import (
	"encoding/json"
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

	if grantType == "refresh_token" {
		refreshTokenString := r.Form.Get("refresh_token")

		ok, err := RefreshKeys.ValidateInnerToken(refreshTokenString)
		if err != nil {
			badRequest(w, r, "Failed to validate refresh token "+err.Error())
			return
		}

		renderTokenResponse(w, r, ok)
		return
	}

	if grantType == "authorization_code" {
		code := r.Form.Get("code")
		if len(code) == 0 {
			badRequest(w, r, "code parameter is required")
			return
		}

		ok, err := CodeKeys.ValidateInnerToken(code)
		if err != nil {
			badRequest(w, r, "Failed to validate code token "+err.Error())
			return
		}

		//TODO: remember visited code to reject it next time
		renderTokenResponse(w, r, ok)
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

func renderTokenResponse(w http.ResponseWriter, r *http.Request, userInfo *UserInfo) {
	claims := gojwt.MapClaims{
		"sid":  userInfo.Sid,
		"sub":  userInfo.Sub,
		"name": userInfo.UserName,
	}

	if len(userInfo.UserEmail) > 0 {
		claims["email"] = userInfo.UserEmail
	}

	tokenString, err := TokenKeys.RenderJwtToken(claims)

	if err != nil {
		badRequest(w, r, "Failed to sign new token for username="+userInfo.String()+" "+err.Error())
		return
	}

	refreshTokenString, err := RefreshKeys.SignInnerToken(userInfo)
	if err != nil {
		badRequest(w, r, "Failed to sign new refresh token for username="+userInfo.String()+" "+err.Error())
		return
	}

	log.Println("Generated refresh token for user =", userInfo, "\n", refreshTokenString)
	response := TokenResponse{
		TokenType:    "Bearer",
		ExpiresIn:    TokenKeys.ExpirationSeconds() - 3, // remove 3 seconds to lower collision probability
		IdToken:      tokenString,
		AccessToken:  tokenString,
		RefreshToken: refreshTokenString,
	}

	responseData, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		badRequest(w, nil, "Failed to serialize response "+err.Error())
		return
	}
	_, err = w.Write(responseData)
	log.Println("Generated token for user =", userInfo, "\n", string(responseData))
}

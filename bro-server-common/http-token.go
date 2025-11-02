package bro_server_common

import (
	"encoding/json"
	"log"
	"net/http"

	"jonnyzzz.com/oauth2-bro/client"
	"jonnyzzz.com/oauth2-bro/keymanager"
	"jonnyzzz.com/oauth2-bro/user"
)

//example  POST /token client_id=tbe-server&client_secret=bacsdf234e&
//code=TODO%3A+iwwwt+is+!code&
//grant_type=authorization_code
//&redirect_uri=http%3A%2F%2Flocalhost%3A8443%2Fapi%2Flogin%2Fauthenticated

type TokenResponse struct {
	IdToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`

	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

type HandleToken interface {
	ClientInfoProvider() client.ClientInfoProvider
	RefreshKeys() keymanager.BroInnerKeys
	CodeKeys() keymanager.BroInnerKeys
	TokenKeys() keymanager.BroAccessKeys
}

func Token(s HandleToken, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	if r.Method != "POST" {
		BadRequest(w, r, "Only POST method is supported")
		return
	}

	err := r.ParseForm()
	if err != nil {
		BadRequest(w, r, "Failed to parse form parameters "+err.Error())
		return
	}

	clientId := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")
	if len(clientId) == 0 || len(clientSecret) == 0 {
		BadRequest(w, r, "client_id and client_secret parameters are required")
		return
	}

	if !s.ClientInfoProvider().IsClientAllowed(clientId, clientSecret) {
		BadRequest(w, r, "client_id and client_secret parameters are not allowed")
		return
	}

	grantType := r.Form.Get("grant_type")

	if grantType == "refresh_token" {
		refreshTokenString := r.Form.Get("refresh_token")

		userInfo, err := s.RefreshKeys().ValidateInnerToken(refreshTokenString)
		if err != nil {
			BadRequest(w, r, "Failed to validate refresh token "+err.Error())
			return
		}

		RenderTokenResponse(s, w, r, userInfo)
		return
	}

	if grantType == "authorization_code" {
		code := r.Form.Get("code")
		if len(code) == 0 {
			BadRequest(w, r, "code parameter is required")
			return
		}

		userInfo, err := s.CodeKeys().ValidateInnerToken(code)
		if err != nil {
			BadRequest(w, r, "Failed to validate code token "+err.Error())
			return
		}

		RenderTokenResponse(s, w, r, userInfo)
		return
	}

	log.Printf("token request %s %s %s \n\n", r.Method, r.URL.String(), r.Form.Encode())
	w.WriteHeader(500)
}

func RenderTokenResponse(s HandleToken, w http.ResponseWriter, r *http.Request, userInfo *user.UserInfo) {
	//TODO: remember visited code to reject it next time
	tokenString, err := s.TokenKeys().RenderJwtAccessToken(userInfo)

	if err != nil {
		BadRequest(w, r, "Failed to sign new token for username="+userInfo.String()+" "+err.Error())
		return
	}

	refreshTokenString, err := s.RefreshKeys().SignInnerToken(userInfo)
	if err != nil {
		BadRequest(w, r, "Failed to sign new refresh token for username="+userInfo.String()+" "+err.Error())
		return
	}

	log.Println("Generated refresh token for user =", userInfo, "\n", refreshTokenString)
	response := TokenResponse{
		TokenType:    "Bearer",
		ExpiresIn:    s.TokenKeys().ExpirationSeconds() - 3, // remove 3 seconds to lower collision probability
		IdToken:      tokenString,
		AccessToken:  tokenString,
		RefreshToken: refreshTokenString,
	}

	responseData, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		BadRequest(w, nil, "Failed to serialize response "+err.Error())
		return
	}
	_, err = w.Write(responseData)
	log.Println("Generated token for user =", userInfo, "\n", string(responseData))
}

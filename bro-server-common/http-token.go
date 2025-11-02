package bro_server_common

import (
	"encoding/json"
	"log"
	"net/http"

	"jonnyzzz.com/oauth2-bro/keymanager"
	"jonnyzzz.com/oauth2-bro/user"
)

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

type HandleTokenResponse interface {
	TokenKeys() keymanager.BroAccessKeys
	RefreshKeys() keymanager.BroInnerKeys
}

func RenderTokenResponse(s HandleTokenResponse, w http.ResponseWriter, r *http.Request, userInfo *user.UserInfo) {
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

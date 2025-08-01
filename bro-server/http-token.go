package broserver

import (
	"encoding/json"
	"log"
	"net/http"

	"jonnyzzz.com/oauth2-bro/user"
)

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
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

	if !s.clientInfoProvider.IsClientAllowed(clientId, clientSecret) {
		badRequest(w, r, "client_id and client_secret parameters are not allowed")
		return
	}

	grantType := r.Form.Get("grant_type")

	if grantType == "refresh_token" {
		refreshTokenString := r.Form.Get("refresh_token")

		keymanagerUserInfo, err := s.refreshKeys.ValidateInnerToken(refreshTokenString)
		if err != nil {
			badRequest(w, r, "Failed to validate refresh token "+err.Error())
			return
		}

		// Convert keymanager UserInfo to user module UserInfo
		userInfo := &user.UserInfo{
			Sid:       keymanagerUserInfo.Sid,
			Sub:       keymanagerUserInfo.Sub,
			UserName:  keymanagerUserInfo.UserName,
			UserEmail: keymanagerUserInfo.UserEmail,
		}

		s.renderTokenResponse(w, r, userInfo)
		return
	}

	if grantType == "authorization_code" {
		code := r.Form.Get("code")
		if len(code) == 0 {
			badRequest(w, r, "code parameter is required")
			return
		}

		keymanagerUserInfo, err := s.codeKeys.ValidateInnerToken(code)
		if err != nil {
			badRequest(w, r, "Failed to validate code token "+err.Error())
			return
		}

		// Convert keymanager UserInfo to user module UserInfo
		userInfo := &user.UserInfo{
			Sid:       keymanagerUserInfo.Sid,
			Sub:       keymanagerUserInfo.Sub,
			UserName:  keymanagerUserInfo.UserName,
			UserEmail: keymanagerUserInfo.UserEmail,
		}

		//TODO: remember visited code to reject it next time
		s.renderTokenResponse(w, r, userInfo)
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

func (s *Server) renderTokenResponse(w http.ResponseWriter, r *http.Request, userInfo *user.UserInfo) {
	tokenString, err := GenerateJWTToken(s.tokenKeys, userInfo)
	if err != nil {
		badRequest(w, r, "Failed to sign new token for username="+userInfo.String()+" "+err.Error())
		return
	}

	refreshTokenString, err := s.refreshKeys.SignInnerToken(userInfo)
	if err != nil {
		badRequest(w, r, "Failed to sign new refresh token for username="+userInfo.String()+" "+err.Error())
		return
	}

	log.Println("Generated refresh token for user =", userInfo, "\n", refreshTokenString)
	response := TokenResponse{
		TokenType:    "Bearer",
		ExpiresIn:    s.tokenKeys.ExpirationSeconds() - 3, // remove 3 seconds to lower collision probability
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

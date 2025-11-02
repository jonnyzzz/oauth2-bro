package broserver

import (
	"log"
	"net/http"

	bsc "jonnyzzz.com/oauth2-bro/bro-server-common"

	"jonnyzzz.com/oauth2-bro/user"
)

func (s *server) token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	if r.Method != "POST" {
		bsc.BadRequest(w, r, "Only POST method is supported")
		return
	}

	err := r.ParseForm()
	if err != nil {
		bsc.BadRequest(w, r, "Failed to parse form parameters "+err.Error())
		return
	}

	clientId := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")
	if len(clientId) == 0 || len(clientSecret) == 0 {
		bsc.BadRequest(w, r, "client_id and client_secret parameters are required")
		return
	}

	if !s.clientInfoProvider.IsClientAllowed(clientId, clientSecret) {
		bsc.BadRequest(w, r, "client_id and client_secret parameters are not allowed")
		return
	}

	grantType := r.Form.Get("grant_type")

	if grantType == "refresh_token" {
		refreshTokenString := r.Form.Get("refresh_token")

		keymanagerUserInfo, err := s.refreshKeys.ValidateInnerToken(refreshTokenString)
		if err != nil {
			bsc.BadRequest(w, r, "Failed to validate refresh token "+err.Error())
			return
		}

		// Convert keymanager UserInfo to user module UserInfo
		userInfo := &user.UserInfo{
			Sid:       keymanagerUserInfo.Sid,
			Sub:       keymanagerUserInfo.Sub,
			UserName:  keymanagerUserInfo.UserName,
			UserEmail: keymanagerUserInfo.UserEmail,
		}

		bsc.RenderTokenResponse(s, w, r, userInfo)
		return
	}

	if grantType == "authorization_code" {
		code := r.Form.Get("code")
		if len(code) == 0 {
			bsc.BadRequest(w, r, "code parameter is required")
			return
		}

		keymanagerUserInfo, err := s.codeKeys.ValidateInnerToken(code)
		if err != nil {
			bsc.BadRequest(w, r, "Failed to validate code token "+err.Error())
			return
		}

		// Convert keymanager UserInfo to user module UserInfo
		userInfo := &user.UserInfo{
			Sid:       keymanagerUserInfo.Sid,
			Sub:       keymanagerUserInfo.Sub,
			UserName:  keymanagerUserInfo.UserName,
			UserEmail: keymanagerUserInfo.UserEmail,
		}

		bsc.RenderTokenResponse(s, w, r, userInfo)
		return
	}

	log.Printf("token request %s %s %s \n\n", r.Method, r.URL.String(), r.Form.Encode())
	w.WriteHeader(500)
}

package broserver

import (
	"log"
	"net/http"

	"jonnyzzz.com/oauth2-bro/keymanager"
	"jonnyzzz.com/oauth2-bro/user"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// NewResponseWrapper creates a response wrapper function
func NewResponseWrapper(version string) func(func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
		return func(writer http.ResponseWriter, request *http.Request) {
			log.Println("request", request.URL.Path)
			writer.Header().Set("Expires", "11 Aug 1984 14:21:33 GMT")
			writer.Header().Set("X-oauth2-bro-version", version)
			handler(writer, request)
		}
	}
}

// badRequest sends a bad request response
func badRequest(w http.ResponseWriter, _ *http.Request, message string) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte("Bad Request. \n\n" + message))
}

// GenerateJWTToken generates a JWT token for the given user info using the provided token keys
func GenerateJWTToken(tokenKeys keymanager.BroKeys, userInfo *user.UserInfo) (string, error) {
	claims := gojwt.MapClaims{
		"sid":  userInfo.Sid,
		"sub":  userInfo.Sub,
		"name": userInfo.UserName,
	}

	if len(userInfo.UserEmail) > 0 {
		claims["email"] = userInfo.UserEmail
	}

	return tokenKeys.RenderJwtToken(claims)
}

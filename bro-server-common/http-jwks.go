package bro_server_common

import (
	"jonnyzzz.com/oauth2-bro/keymanager"
	"log"
	"net/http"
)

func JwksHandler(tokenKeys keymanager.BroKeys) http.HandlerFunc {
	jwks, err := tokenKeys.Jwks()
	if err != nil {
		log.Panicf("Failed to generate JWKS: %v", err)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/jwk+json;charset=utf-8")
		w.WriteHeader(200)
		_, _ = w.Write(jwks)
	}
}

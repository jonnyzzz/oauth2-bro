package broserver

import (
	"log"
	"net/http"

	"jonnyzzz.com/oauth2-bro/keymanager"
)

// sharedJWKS serves the JWKS endpoint for both server types
func sharedJWKS(tokenKeys keymanager.BroKeys) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		jwks, err := tokenKeys.Jwks()
		if err != nil {
			log.Printf("Failed to generate JWKS: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		w.Header().Add("Content-Type", "application/jwk+json;charset=utf-8")
		w.WriteHeader(200)
		_, _ = w.Write(jwks)
	}
}

// SharedHealth serves the health endpoint for both server types
func SharedHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(200)
	_, _ = w.Write([]byte("Alive\n\n"))
}

package broserver

import (
	"log"
	"net/http"
)

// jwks serves the JWKS endpoint
func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	jwks, err := s.tokenKeys.Jwks()
	if err != nil {
		log.Printf("Failed to generate JWKS: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/jwk+json;charset=utf-8")
	w.WriteHeader(200)
	_, _ = w.Write(jwks)
}

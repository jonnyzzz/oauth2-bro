package main

import (
	"encoding/json"
	"github.com/rakutentech/jwk-go/jwk"
	"log"
	"net/http"
)

var JWKs []byte

type Keys struct {
	// Keys is an array of JSON web keys.
	Keys []*jwk.JWK `json:"keys"`
}

func init_jwks() {
	spec, err := (&jwk.KeySpec{
		Key:       RsaPrivateKey,
		KeyID:     RsaPrivateKeyId,
		Use:       "sig",
		Algorithm: SigningMethodRSA.Alg(),
	}).PublicOnly()

	if err != nil {
		log.Fatalln("Failed to get RSA key spec. ", err)
	}

	j, err := spec.ToJWK()
	if err != nil {
		log.Fatalln("Failed to serialize JWK from key spec. ", err)
	}

	keys := Keys{
		Keys: []*jwk.JWK{j},
	}

	data, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		log.Fatalln("Failed to serialize JWKs to JSON. ", err)
	}

	log.Println("Actual JWKs:\n", string(data))
	JWKs = data
}

func jwks(w http.ResponseWriter, _ *http.Request) {
	w.Header().Add("Content-Type", "application/jwk+json")
	w.WriteHeader(200)
	_, _ = w.Write(JWKs)
}

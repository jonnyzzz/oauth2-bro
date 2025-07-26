package main

import (
	"encoding/json"
	"github.com/rakutentech/jwk-go/jwk"
	"log"
	"net/http"
)

import gojwt "github.com/golang-jwt/jwt/v5"

var SigningMethodRSA *gojwt.SigningMethodRSA
var JWKs []byte

type Keys struct {
	// Keys is an array of JSON web keys.
	Keys []*jwk.JWK `json:"keys"`
}

func init_jwks() {
	SigningMethodRSA = gojwt.SigningMethodRS512

	spec, err := (&jwk.KeySpec{
		Key:       RsaPrivateKey,
		KeyID:     RsaPrivateKeyId,
		Use:       "sig",
		Algorithm: SigningMethodRSA.Alg(),
	}).PublicOnly()

	if err != nil {
		log.Fatalln("Failed to convert RSA key. ", err)
	}

	j, err := spec.ToJWK()
	if err != nil {
		log.Fatalln("Failed to serialize to JWK. ", err)
	}

	keys := Keys{
		Keys: []*jwk.JWK{j},
	}

	data, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		log.Fatalln("Failed to serialize to JSON. ", err)
	}

	log.Println("Generated JWKS:\n", string(data))
	JWKs = data
}

func jwks(w http.ResponseWriter, _ *http.Request) {
	w.Header().Add("Content-Type", "application/jwk+json")
	w.WriteHeader(200)
	_, _ = w.Write(JWKs)
}

package keymanager

import (
	"encoding/json"

	"github.com/rakutentech/jwk-go/jwk"
)

// Keys represents the JWKS structure
type Keys struct {
	// Keys is an array of JSON web keys.
	Keys []*jwk.JWK `json:"keys"`
}

// GenerateJWKS generates a JWKS (JSON Web Key Set) from the provided BroKeys
func GenerateJWKS(tokenKeys BroKeys) ([]byte, error) {
	spec, err := (&jwk.KeySpec{
		Key:       tokenKeys.PrivateKey(),
		KeyID:     tokenKeys.KeyId(),
		Use:       "sig",
		Algorithm: tokenKeys.SigningMethod().Alg(),
	}).PublicOnly()

	if err != nil {
		return nil, err
	}

	j, err := spec.ToJWK()
	if err != nil {
		return nil, err
	}

	keys := Keys{
		Keys: []*jwk.JWK{j},
	}

	data, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return nil, err
	}

	return data, nil
}

// GenerateJWKSForServing generates JWKS data for serving over HTTP
func GenerateJWKSForServing(tokenKeys BroKeys) ([]byte, error) {
	return GenerateJWKS(tokenKeys)
}

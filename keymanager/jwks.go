package keymanager

import (
	"github.com/rakutentech/jwk-go/jwk"
)

// Keys represents the JWKS structure
type Keys struct {
	// Keys is an array of JSON web keys.
	Keys []*jwk.JWK `json:"keys"`
}

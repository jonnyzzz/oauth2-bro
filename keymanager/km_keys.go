package keymanager

import (
	"crypto/rsa"

	gojwt "github.com/golang-jwt/jwt/v5"
)

type BroKeys interface {
	KeyId() string
	ExpirationSeconds() int

	RenderJwtToken(claims gojwt.MapClaims) (string, error)
	ValidateJwtToken(tokenString string, claims gojwt.Claims) (*gojwt.Token, error)
	Jwks() ([]byte, error)
}

type broKeysImpl struct {
	privateKey        *rsa.PrivateKey
	keyId             string
	expirationSeconds int
}

func (tk *broKeysImpl) KeyId() string {
	return tk.keyId
}

func (tk *broKeysImpl) ExpirationSeconds() int {
	return tk.expirationSeconds
}

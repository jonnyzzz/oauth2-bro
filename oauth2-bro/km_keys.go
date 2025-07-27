package main

import (
	"crypto/rsa"
	gojwt "github.com/golang-jwt/jwt/v5"
)

type BroKeys interface {
	KeyId() string
	PrivateKey() *rsa.PrivateKey
	ExpirationSeconds() int

	SigningMethod() *gojwt.SigningMethodRSA

	RenderJwtToken(claims gojwt.MapClaims) (string, error)
}

type broKeysImpl struct {
	privateKey        *rsa.PrivateKey
	keyId             string
	expirationSeconds int
}

func (tk *broKeysImpl) PrivateKey() *rsa.PrivateKey {
	return tk.privateKey
}

func (tk *broKeysImpl) KeyId() string {
	return tk.keyId
}

func (tk *broKeysImpl) ExpirationSeconds() int {
	return tk.expirationSeconds
}

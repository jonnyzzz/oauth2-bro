package main

import (
	"fmt"
	gojwt "github.com/golang-jwt/jwt/v5"
	"time"
)

// SigningMethod returns the JWT signing method
func (_ *broKeysImpl) SigningMethod() *gojwt.SigningMethodRSA {
	return gojwt.SigningMethodRS512
}

func (tk *broKeysImpl) RenderJwtToken(claims gojwt.MapClaims) (string, error) {
	mergedClaims := gojwt.MapClaims{}
	for k, v := range claims {
		mergedClaims[k] = v
	}
	mergedClaims["exp"] = time.Now().Add(time.Duration(tk.ExpirationSeconds()) * time.Second).Unix()

	token := gojwt.NewWithClaims(tk.SigningMethod(), mergedClaims)
	token.Header["kid"] = tk.KeyId()

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(tk.PrivateKey())
	if err != nil {
		return "", fmt.Errorf("failed to sign new token %s", err.Error())
	}

	return tokenString, nil
}

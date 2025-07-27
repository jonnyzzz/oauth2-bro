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

func (tk *broKeysImpl) ValidateJwtToken(tokenString string, claims gojwt.Claims) (*gojwt.Token, error) {
	token, err := gojwt.ParseWithClaims(tokenString, claims, func(t *gojwt.Token) (any, error) {
		//TODO: check signing alg
		alg := t.Method.Alg()
		if alg != tk.SigningMethod().Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", alg)
		}

		//TODO: multiple public keys check
		return &tk.PrivateKey().PublicKey, nil
	}, gojwt.WithExpirationRequired())

	if err != nil {
		return nil, err
	}

	//TODO: check expiration and other predicates
	return token, nil
}

package main

import (
	"fmt"
	gojwt "github.com/golang-jwt/jwt/v5"
	"log"
)

const broCodeVersion = "v1"

var CodeKeys BroKeys

func init_code_keys() {
	keys, err := NewKeys(
		"OAUTH2_BRO_CODE_RSA_KEY_PEM_FILE",
		"OAUTH2_BRO_CODE_RSA_KEY_ID",
		"OAUTH2_BRO_CODE_EXPIRATION_SECONDS",
		5,
	)

	if err != nil || keys == nil {
		log.Panicln("Failed to initialize code keys: ", err)
		return
	}

	CodeKeys = keys
}

func SignCodeToken() (string, error) {
	token, err := CodeKeys.RenderJwtToken(gojwt.MapClaims{
		"bro": broCodeVersion,
	})
	return token, err
}

func ValidateCodeToken(tokenString string) (bool, error) {
	type MyCustomClaims struct {
		Bro string `json:"bro"`
		gojwt.RegisteredClaims
	}

	token, err := gojwt.ParseWithClaims(tokenString, &MyCustomClaims{}, func(t *gojwt.Token) (any, error) {
		//TODO: check signing alg
		//TODO: multiple public keys check
		return &CodeKeys.PrivateKey().PublicKey, nil
	}, gojwt.WithExpirationRequired())

	if err != nil {
		return false, err
	}

	claims, ok := token.Claims.(*MyCustomClaims)
	if !ok {
		return false, fmt.Errorf("failed to get code claims. ")
	}

	if claims.Bro != broCodeVersion {
		return false, fmt.Errorf("Unsupported code claim version. ")
	}

	//TODO: check bro claim
	return true, nil
}

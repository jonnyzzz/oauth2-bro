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
	type CodeClaims struct {
		Bro string `json:"bro"`
		gojwt.RegisteredClaims
	}

	token, err := CodeKeys.ValidateJwtToken(tokenString, &CodeClaims{})
	if err != nil {
		return false, err
	}

	claims, ok := token.Claims.(*CodeClaims)
	if !ok {
		return false, fmt.Errorf("failed to cast claims to CodeClaims")
	}

	if claims.Bro != broCodeVersion {
		return false, fmt.Errorf("Unsupported code claim version. ")
	}

	return true, nil
}

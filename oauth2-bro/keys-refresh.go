package main

import (
	"fmt"
	gojwt "github.com/golang-jwt/jwt/v5"
	"log"
)

const broRefreshVersion = "v1"

var RefreshKeys BroKeys

func init_refresh_keys() {
	keys, err := NewKeys(
		"OAUTH2_BRO_REFRESH_RSA_KEY_PEM_FILE",
		"OAUTH2_BRO_REFRESH_RSA_KEY_ID",
		"OAUTH2_BRO_REFRESH_EXPIRATION_SECONDS",
		60*60*24*10,
		4096,
	)

	if err != nil || keys == nil {
		log.Panicln("Failed to initialize refresh keys: ", err)
		return
	}

	RefreshKeys = keys
}

func SignRefreshToken() (string, error) {
	token, err := RefreshKeys.RenderJwtToken(gojwt.MapClaims{
		"bro": broRefreshVersion,
	})
	return token, err
}

func ValidateRefreshToken(tokenString string) (bool, error) {
	type RefreshClaims struct {
		Bro string `json:"bro"`
		gojwt.RegisteredClaims
	}

	token, err := RefreshKeys.ValidateJwtToken(tokenString, &RefreshClaims{})
	if err != nil {
		return false, err
	}

	claims, ok := token.Claims.(*RefreshClaims)
	if !ok {
		return false, fmt.Errorf("failed to cast claims to RefreshClaims")
	}

	if claims.Bro != broRefreshVersion {
		return false, fmt.Errorf("Unsupported refresh claim version. ")
	}

	return true, nil
}

package main

import (
	"log"
)

var TokenKeys BroKeys

func init_token_keys() {
	keys, err := NewKeys(
		"OAUTH2_BRO_TOKEN_RSA_KEY_PEM_FILE",
		"OAUTH2_BRO_TOKEN_RSA_KEY_ID",
		"OAUTH2_BRO_TOKEN_EXPIRATION_SECONDS",
		300,
		2048,
	)

	if err != nil || keys == nil {
		log.Panicln("Failed to initialize token keys: ", err)
		return
	}

	TokenKeys = keys
}

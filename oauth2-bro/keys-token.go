package main

var TokenKeys BroKeys

func init_token_keys() {
	keys := NewKeys(
		"OAUTH2_BRO_TOKEN_RSA_KEY_PEM_FILE",
		"OAUTH2_BRO_TOKEN_RSA_KEY_ID",
		"OAUTH2_BRO_TOKEN_EXPIRATION_SECONDS",
		300,
		2048,
	)

	TokenKeys = keys
}

package main

var RefreshKeys BroInnerKeys

func init_refresh_keys() {
	keys := NewKeys(
		"OAUTH2_BRO_REFRESH_RSA_KEY_PEM_FILE",
		"OAUTH2_BRO_REFRESH_RSA_KEY_ID",
		"OAUTH2_BRO_REFRESH_EXPIRATION_SECONDS",
		60*60*24*10,
		4096,
	)

	RefreshKeys = NewInnerKeys(keys, "r1")
}

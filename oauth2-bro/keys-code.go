package main

var CodeKeys BroInnerKeys

func init_code_keys() {
	keys := NewKeys(
		"OAUTH2_BRO_CODE_RSA_KEY_PEM_FILE",
		"OAUTH2_BRO_CODE_RSA_KEY_ID",
		"OAUTH2_BRO_CODE_EXPIRATION_SECONDS",
		5,
		2048,
	)

	CodeKeys = NewInnerKeys(keys, "v1")
}

package main

import "jonnyzzz.com/oauth2-bro/keymanager"

// KeyManager holds all key instances
type KeyManager struct {
	TokenKeys   keymanager.BroKeys
	CodeKeys    keymanager.BroInnerKeys
	RefreshKeys keymanager.BroInnerKeys
}

// NewKeyManager creates a new KeyManager instance with all key dependencies
func NewKeyManager() *KeyManager {
	// Create token keys
	tokenKeys := keymanager.NewKeys(
		"OAUTH2_BRO_TOKEN_RSA_KEY_PEM_FILE",
		"OAUTH2_BRO_TOKEN_RSA_KEY_ID",
		"OAUTH2_BRO_TOKEN_EXPIRATION_SECONDS",
		300,
		2048,
	)

	// Create code keys
	codeKeys := keymanager.NewKeys(
		"OAUTH2_BRO_CODE_RSA_KEY_PEM_FILE",
		"OAUTH2_BRO_CODE_RSA_KEY_ID",
		"OAUTH2_BRO_CODE_EXPIRATION_SECONDS",
		5,
		2048,
	)

	// Create refresh keys
	refreshKeys := keymanager.NewKeys(
		"OAUTH2_BRO_REFRESH_RSA_KEY_PEM_FILE",
		"OAUTH2_BRO_REFRESH_RSA_KEY_ID",
		"OAUTH2_BRO_REFRESH_EXPIRATION_SECONDS",
		60*60*24*10,
		4096,
	)

	return &KeyManager{
		TokenKeys:   tokenKeys,
		CodeKeys:    keymanager.NewInnerKeys(codeKeys, "v1"),
		RefreshKeys: keymanager.NewInnerKeys(refreshKeys, "r1"),
	}
}

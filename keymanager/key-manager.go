package keymanager

// KeyManager holds all key instances
type KeyManager struct {
	TokenKeys   BroAccessKeys
	CodeKeys    BroInnerKeys
	RefreshKeys BroInnerKeys
}

// NewKeyManager creates a new KeyManager instance with all key dependencies
func NewKeyManager() *KeyManager {
	// Create token keys
	tokenKeys := NewTokenKeys()

	// Create code keys
	codeKeys := NewKeys(
		"OAUTH2_BRO_CODE_RSA_KEY_PEM_FILE",
		"OAUTH2_BRO_CODE_RSA_KEY_ID",
		"OAUTH2_BRO_CODE_EXPIRATION_SECONDS",
		5,
		2048,
	)

	// Create refresh keys
	refreshKeys := NewKeys(
		"OAUTH2_BRO_REFRESH_RSA_KEY_PEM_FILE",
		"OAUTH2_BRO_REFRESH_RSA_KEY_ID",
		"OAUTH2_BRO_REFRESH_EXPIRATION_SECONDS",
		60*60*24*10,
		4096,
	)

	return &KeyManager{
		TokenKeys:   tokenKeys,
		CodeKeys:    NewInnerKeys(codeKeys, "v1"),
		RefreshKeys: NewInnerKeys(refreshKeys, "r1"),
	}
}

func NewTokenKeys() BroAccessKeys {
	tokenKeys := NewKeys(
		"OAUTH2_BRO_TOKEN_RSA_KEY_PEM_FILE",
		"OAUTH2_BRO_TOKEN_RSA_KEY_ID",
		"OAUTH2_BRO_TOKEN_EXPIRATION_SECONDS",
		300,
		2048,
	)
	return NewTokenKeysFrom(tokenKeys)
}

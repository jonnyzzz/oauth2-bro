package keymanager

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"log"
	"os"
	"strconv"
)

// NewKeys creates a new broKeysImpl with the specified environment variable names and initializes it
func NewKeys(envKeyPemFile, envKeyId, envExpirationSeconds string, defaultExpirationSeconds int, defaultKeyBits int) BroKeys {
	tk := &broKeysImpl{}
	initExpirationSeconds(envExpirationSeconds, tk, defaultExpirationSeconds)
	initPrivateKey(envKeyPemFile, tk, defaultKeyBits)
	initKeyId(envKeyId, tk)
	return tk
}

func initKeyId(envKeyId string, tk *broKeysImpl) {
	externalKeyId := os.Getenv(envKeyId)
	if len(externalKeyId) > 0 {
		tk.keyId = externalKeyId
		log.Println("Using key ID ", shortenKeyIdForLog(tk.keyId))
		return
	}

	publicKeyDER, err := x509.MarshalPKIXPublicKey(&tk.privateKey.PublicKey)
	if err != nil {
		log.Panicln("Failed to marshal public key: ", err)
		return
	}

	tk.keyId = "oauth2-bro-" + hex.EncodeToString(sha512.New().Sum(publicKeyDER))
	log.Println("Using key ID ", shortenKeyIdForLog(tk.keyId))
}

// shortenKeyIdForLog shortens a key ID for logging purposes using industry-best practice:
// takes the prefix and first 12 characters of the hash for readability while maintaining uniqueness
func shortenKeyIdForLog(keyId string) string {
	b := sha512.Sum512([]byte(keyId))
	return base64.URLEncoding.EncodeToString(b[:12])
}

func initPrivateKey(envKeyPemFile string, tk *broKeysImpl, defaultKeyBits int) {
	externalKeyPemFile := os.Getenv(envKeyPemFile)
	if len(externalKeyPemFile) > 0 {
		log.Println("Loading RSA key from PEM file ", externalKeyPemFile, "...")

		pemData, err := os.ReadFile(externalKeyPemFile)
		if err != nil {
			log.Panicf("failed to read RSA key PEM file %s: %v", externalKeyPemFile, err)
			return
		}

		// Decode PEM block
		block, _ := pem.Decode(pemData)
		if block == nil {
			log.Panicf("failed to decode PEM block from file %s", externalKeyPemFile)
		}

		// Parse the private key
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			// Try parsing as PKCS8 if PKCS1 fails
			if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				var ok bool
				privateKey, ok = key.(*rsa.PrivateKey)
				if !ok {
					log.Panicf("failed to parse private key from PKCS8 file %s", externalKeyPemFile)
				}
			} else {
				log.Panicf("failed to parse private key from file %s: %v", externalKeyPemFile, err)
			}
		}

		tk.privateKey = privateKey
		return
	}

	log.Println("Generating new RSA key...")
	privateKey, err := rsa.GenerateKey(rand.Reader, defaultKeyBits)
	if err != nil {
		log.Panicf("failed to generate RSA key: %v", err)
	}

	tk.privateKey = privateKey
}

func initExpirationSeconds(envExpirationSeconds string, tk *broKeysImpl, defaultExpirationSeconds int) {
	// Initialize expiration seconds
	tokenExpirationText := os.Getenv(envExpirationSeconds)
	if len(tokenExpirationText) == 0 {
		tk.expirationSeconds = defaultExpirationSeconds
		return
	}

	tokenExpirationTime, err := strconv.Atoi(tokenExpirationText)
	if tokenExpirationTime <= 0 || err != nil {
		log.Panicf("incorrect token expiration time %s: %v", tokenExpirationText, err)
	}

	tk.expirationSeconds = tokenExpirationTime
	log.Printf("Token expiration seconds = %d", tk.expirationSeconds)
}

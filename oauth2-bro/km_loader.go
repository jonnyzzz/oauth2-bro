package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"log"
	"os"
	"strconv"
)

// NewKeys creates a new broKeysImpl with the specified environment variable names and initializes it
func NewKeys(envKeyPemFile, envKeyId, envExpirationSeconds string, defaultExpirationSeconds int) (BroKeys, error) {
	tk := &broKeysImpl{}
	initExpirationSeconds(envExpirationSeconds, tk, defaultExpirationSeconds)
	initPrivateKey(envKeyPemFile, tk)
	initKeyId(envKeyId, tk)
	return tk, nil
}

func initKeyId(envKeyId string, tk *broKeysImpl) {
	externalKeyId := os.Getenv(envKeyId)
	if len(externalKeyId) > 0 {
		tk.keyId = externalKeyId
		return
	}

	publicKeyDER, err := x509.MarshalPKIXPublicKey(&tk.privateKey.PublicKey)
	if err != nil {
		log.Panicln("Failed to marshal public key: ", err)
		return
	}

	tk.keyId = "oauth2-bro-" + hex.EncodeToString(sha512.New().Sum(publicKeyDER))
	log.Println("Using key ID ", tk.keyId)
}

func initPrivateKey(envKeyPemFile string, tk *broKeysImpl) {
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
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
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

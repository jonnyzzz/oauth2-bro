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
)

var RsaPrivateKey *rsa.PrivateKey
var RsaPrivateKeyId string

func init_token_keys() {
	externalKeyPemFile := os.Getenv("OAUTH2_BRO_TOKEN_RSA_KEY_PEM_FILE")
	if len(externalKeyPemFile) > 0 {
		log.Println("Loading RSA key from PEM file ", externalKeyPemFile, "...")

		pemData, err := os.ReadFile(externalKeyPemFile)
		if err != nil {
			log.Fatalln("Failed to read RSA key PEM file ", externalKeyPemFile, ". ", err)
		}

		// Decode PEM block
		block, _ := pem.Decode(pemData)
		if block == nil {
			log.Fatalf("Failed to decode PEM block from file %s", externalKeyPemFile)
		}

		// Parse the private key
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			// Try parsing as PKCS8 if PKCS1 fails
			if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				var ok bool
				privateKey, ok = key.(*rsa.PrivateKey)
				if !ok {
					log.Fatalf("Failed to parse private key from PKCS8 file %s", externalKeyPemFile)
				}
			}
		}

		RsaPrivateKey = privateKey
	} else {
		log.Println("Generating new RSA key...")
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)

		if err != nil {
			log.Fatalln("Failed to generate RSA key. ", err)
		}

		RsaPrivateKey = privateKey
	}

	externalKeyId := os.Getenv("OAUTH2_BRO_TOKEN_RSA_KEY_ID")
	if len(externalKeyId) > 0 {
		RsaPrivateKeyId = externalKeyId
	} else {
		publicKeyDER, err := x509.MarshalPKIXPublicKey(&RsaPrivateKey.PublicKey)
		if err != nil {
			log.Fatalln("Failed to marshal public key. ", err)
		}
		// Create SHA512 hash
		hash := sha512.New()
		hash.Write(publicKeyDER)
		hashHex := hex.EncodeToString(hash.Sum(nil))
		RsaPrivateKeyId = "oauth2-bro-" + hashHex
	}
	log.Println("Using key ID ", RsaPrivateKeyId)
}

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

var version = "SNAPSHOT"

func main() {
	fmt.Println("Staring OAuth2-bro v.", version)
	fmt.Println("")
	printOAuth2BroBanner()

	init_token_keys()
	init_jwks()

	addr := os.Getenv("OAUTH2_BRO_ADDR")
	if len(addr) == 0 {
		addr = "localhost:8077"
	}

	certFile := os.Getenv("OAUTH2_BRO_HTTPS_CERT_FILE")
	certKeyFile := os.Getenv("OAUTH2_BRO_HTTPS_CERT_KEY_FILE")

	var err error
	if len(certFile) > 0 {
		fmt.Printf("Listening https://%s\n", addr)
		err = http.ListenAndServeTLS(addr, certFile, certKeyFile, nil)
	} else {
		//goland:noinspection HttpUrlsUsage
		fmt.Printf("Listening http://%s\n", addr)
		err = http.ListenAndServe(addr, nil)
	}

	if err != nil {
		log.Fatalln("Failed to start HTTP server on ", addr, ": ", err)
	}
}

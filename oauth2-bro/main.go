package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

var version = "SNAPSHOT"

func resolveBindAddress() string {
	bindPort := os.Getenv("OAUTH2_BRO_BIND_PORT")
	if len(bindPort) == 0 {
		bindPort = "8077"
	}

	bindHost := os.Getenv("OAUTH2_BRO_BIND_HOST")
	if len(bindHost) == 0 {
		bindHost = "localhost"
	}

	return bindHost + ":" + bindPort
}

func main() {
	fmt.Println("Staring OAuth2-bro v.", version)
	fmt.Println("")
	printOAuth2BroBanner()

	init_token_keys()
	init_jwks()
	init_code_keys()
	init_refresh_keys()
	init_client_id()
	init_ip_masks()

	addr := resolveBindAddress()
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

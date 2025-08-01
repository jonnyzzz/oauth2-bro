package main

import (
	"flag"
	"fmt"
	"jonnyzzz.com/oauth2-bro/keymanager"
	"log"
	"net/http"
	"os"

	browproxy "jonnyzzz.com/oauth2-bro/bro-proxy"
	browserver "jonnyzzz.com/oauth2-bro/bro-server"
	"jonnyzzz.com/oauth2-bro/client"
	"jonnyzzz.com/oauth2-bro/user"
)

var version = "SNAPSHOT"

func printHelp() {
	fmt.Println("OAuth2-bro - A simple OAuth2 authorization server")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  oauth2-bro [options]")
	fmt.Println("")
	fmt.Println("Options:")
	fmt.Println("  -h, --help     Show this help message")
	fmt.Println("  -v, --version  Show version information")
	fmt.Println("")
}

func printVersion() {
	fmt.Printf("OAuth2-bro version %s\n", version)
}

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
	// Parse command-line flags
	showHelp := flag.Bool("help", false, "Show help message")
	showVersion := flag.Bool("version", false, "Show version information")
	flag.BoolVar(showHelp, "h", false, "Show help message")
	flag.BoolVar(showVersion, "v", false, "Show version information")

	// Custom usage function
	flag.Usage = func() {
		printHelp()
	}

	flag.Parse()

	// Handle help and version flags
	if *showHelp {
		printHelp()
		return
	}

	if *showVersion {
		printVersion()
		return
	}

	fmt.Println("Starting OAuth2-bro v.", version)
	fmt.Println("")
	printOAuth2BroBanner()

	userManager := user.NewUserResolver()
	clientManager := client.NewClientManager()

	mux := http.NewServeMux()

	proxyTarget := os.Getenv("OAUTH2_BRO_PROXY_TARGET")
	if len(proxyTarget) > 0 {
		fmt.Println("Running reverse-proxy with proxy target: ", proxyTarget)
		browproxy.SetupServer(browproxy.ServerConfig{
			TokenKeys:    keymanager.NewTokenKeys(),
			UserResolver: userManager,
			Version:      version,
			TargetUrl:    proxyTarget,
		}, mux)
	} else {
		keyManager := keymanager.NewKeyManager()
		browserver.SetupServer(browserver.ServerConfig{
			RefreshKeys:        keyManager.RefreshKeys,
			CodeKeys:           keyManager.CodeKeys,
			TokenKeys:          keyManager.TokenKeys,
			UserResolver:       userManager,
			ClientInfoProvider: clientManager,
			Version:            version,
		}, mux)
	}

	addr := resolveBindAddress()
	certFile := os.Getenv("OAUTH2_BRO_HTTPS_CERT_FILE")
	certKeyFile := os.Getenv("OAUTH2_BRO_HTTPS_CERT_KEY_FILE")

	var err error
	if len(certFile) > 0 {
		fmt.Printf("Listening https://%s\n", addr)
		err = http.ListenAndServeTLS(addr, certFile, certKeyFile, mux)
	} else {
		//goland:noinspection HttpUrlsUsage
		fmt.Printf("Listening http://%s\n", addr)
		err = http.ListenAndServe(addr, mux)
	}

	if err != nil {
		log.Fatalln("Failed to start HTTP server on ", addr, ": ", err)
	}
}

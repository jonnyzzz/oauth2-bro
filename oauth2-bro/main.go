package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"jonnyzzz.com/oauth2-bro/keymanager"

	browproxy "jonnyzzz.com/oauth2-bro/bro-proxy"
	browserver "jonnyzzz.com/oauth2-bro/bro-server"
	"jonnyzzz.com/oauth2-bro/client"
	"jonnyzzz.com/oauth2-bro/user"
)

var version = "SNAPSHOT"

func printHelp() {
	fmt.Println("OAuth2-bro - IP-based OAuth2 authentication server")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  oauth2-bro [options]")
	fmt.Println("")
	fmt.Println("Options:")
	fmt.Println("  -h, --help     Show this help message")
	fmt.Println("  -v, --version  Show version information")
	fmt.Println("")
	fmt.Println("Operating Modes:")
	fmt.Println("  Server Mode - Full OAuth2/OpenID Connect server with /login, /token, /jwks endpoints")
	fmt.Println("  Proxy Mode  - Reverse proxy that injects JWT tokens (set OAUTH2_BRO_PROXY_TARGET)")
	fmt.Println("")
	fmt.Println("Network Configuration:")
	fmt.Println("  OAUTH2_BRO_BIND_HOST            Bind address (default: localhost)")
	fmt.Println("  OAUTH2_BRO_HTTP_PORT            HTTP port for internal connections")
	fmt.Println("  OAUTH2_BRO_HTTPS_PORT           HTTPS port for external connections")
	fmt.Println("  OAUTH2_BRO_HTTPS_CERT_FILE      Path to PEM certificate (required for HTTPS)")
	fmt.Println("  OAUTH2_BRO_HTTPS_CERT_KEY_FILE  Path to PEM private key (required for HTTPS)")
	fmt.Println("")
	fmt.Println("  Note: At least one port (HTTP or HTTPS) must be configured.")
	fmt.Println("        Both ports can run simultaneously: HTTPS for external clients,")
	fmt.Println("        HTTP for internal service-to-service communication.")
	fmt.Println("")
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
		fmt.Printf("OAuth2-bro version %s\n", version)
		return
	}

	fmt.Println("Starting OAuth2-bro v.", version)
	fmt.Println("")
	printOAuth2BroBanner()

	userManager := user.NewUserResolver()
	clientManager := client.NewClientManager()
	keyManager := keymanager.NewKeyManager()

	mux := http.NewServeMux()

	proxyTarget := os.Getenv("OAUTH2_BRO_PROXY_TARGET")
	if len(proxyTarget) > 0 {
		fmt.Println("Running reverse-proxy with proxy target: ", proxyTarget)
		browproxy.SetupServer(browproxy.ServerConfig{
			ClientInfoProvider: clientManager,
			KeyManager:         *keyManager,
			UserResolver:       userManager,
			Version:            version,
			TargetUrl:          proxyTarget,
		}, mux)
	} else {
		browserver.SetupServer(browserver.ServerConfig{
			KeyManager:         *keyManager,
			UserResolver:       userManager,
			ClientInfoProvider: clientManager,
			Version:            version,
		}, mux)
	}

	bindHost := os.Getenv("OAUTH2_BRO_BIND_HOST")
	if len(bindHost) == 0 {
		bindHost = "localhost"
	}
	httpPort := os.Getenv("OAUTH2_BRO_HTTP_PORT")
	httpsPort := os.Getenv("OAUTH2_BRO_HTTPS_PORT")
	certFile := os.Getenv("OAUTH2_BRO_HTTPS_CERT_FILE")
	certKeyFile := os.Getenv("OAUTH2_BRO_HTTPS_CERT_KEY_FILE")

	// Validate configuration
	if len(httpPort) == 0 && len(httpsPort) == 0 {
		log.Fatalln("Error: At least one port must be configured (OAUTH2_BRO_HTTP_PORT or OAUTH2_BRO_HTTPS_PORT)")
	}

	// Check HTTPS certificate configuration
	if len(httpsPort) > 0 {
		if len(certFile) == 0 || len(certKeyFile) == 0 {
			log.Fatalln("Error: HTTPS port configured but certificate files missing.\n" +
				"  Set OAUTH2_BRO_HTTPS_CERT_FILE and OAUTH2_BRO_HTTPS_CERT_KEY_FILE")
		}
		fmt.Println("Using certificate files for HTTPS")
	}

	// Channel to capture errors from servers
	// If either server fails, the process will exit
	errChan := make(chan error, 2)

	// Start HTTP server if configured
	if len(httpPort) > 0 {
		httpAddr := bindHost + ":" + httpPort
		go func() {
			//goland:noinspection HttpUrlsUsage
			fmt.Printf("Listening http://%s\n", httpAddr)
			if err := http.ListenAndServe(httpAddr, mux); err != nil {
				errChan <- fmt.Errorf("HTTP server failed on %s: %w", httpAddr, err)
			}
		}()
	}

	// Start HTTPS server if configured
	if len(httpsPort) > 0 {
		httpsAddr := bindHost + ":" + httpsPort
		go func() {
			fmt.Printf("Listening https://%s\n", httpsAddr)
			if err := http.ListenAndServeTLS(httpsAddr, certFile, certKeyFile, mux); err != nil {
				errChan <- fmt.Errorf("HTTPS server failed on %s: %w", httpsAddr, err)
			}
		}()
	}

	// Wait for any server to fail - this will cause the process to exit
	err := <-errChan
	log.Fatalln("Server stopped: ", err)
}

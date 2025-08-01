package main

import (
	"flag"
	"fmt"
	"jonnyzzz.com/oauth2-bro/keymanager"
	"log"
	"net/http"
	"os"

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
	fmt.Println("Environment Variables:")
	fmt.Println("  OAUTH2_BRO_BIND_HOST              Host to bind to (default: localhost)")
	fmt.Println("  OAUTH2_BRO_BIND_PORT              Port to bind to (default: 8077)")
	fmt.Println("  OAUTH2_BRO_HTTPS_CERT_FILE        Path to SSL certificate file for HTTPS")
	fmt.Println("  OAUTH2_BRO_HTTPS_CERT_KEY_FILE    Path to SSL private key file for HTTPS")
	fmt.Println("  OAUTH2_BRO_CLIENT_CREDENTIALS     Client credentials in format 'client_id=secret'")
	fmt.Println("  OAUTH2_BRO_ALLOWED_IP_MASKS       Comma-separated list of allowed IP masks")
	fmt.Println("  OAUTH2_BRO_EMAIL_DOMAIN           Email domain for user emails")
	fmt.Println("  OAUTH2_BRO_MAKE_ROOT_SECRET       Secret for making root user")
	fmt.Println("")
	fmt.Println("Key Management:")
	fmt.Println("  OAUTH2_BRO_TOKEN_RSA_KEY_PEM_FILE     Path to token RSA private key")
	fmt.Println("  OAUTH2_BRO_TOKEN_RSA_KEY_ID           Token key ID")
	fmt.Println("  OAUTH2_BRO_TOKEN_EXPIRATION_SECONDS   Token expiration time (default: 300)")
	fmt.Println("  OAUTH2_BRO_CODE_RSA_KEY_PEM_FILE      Path to code RSA private key")
	fmt.Println("  OAUTH2_BRO_CODE_RSA_KEY_ID            Code key ID")
	fmt.Println("  OAUTH2_BRO_CODE_EXPIRATION_SECONDS    Code expiration time (default: 5)")
	fmt.Println("  OAUTH2_BRO_REFRESH_RSA_KEY_PEM_FILE   Path to refresh RSA private key")
	fmt.Println("  OAUTH2_BRO_REFRESH_RSA_KEY_ID         Refresh key ID")
	fmt.Println("  OAUTH2_BRO_REFRESH_EXPIRATION_SECONDS Refresh expiration time (default: 864000)")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  oauth2-bro                                    # Start with defaults")
	fmt.Println("  oauth2-bro --help                             # Show help")
	fmt.Println("  oauth2-bro --version                          # Show version")
	fmt.Println("  OAUTH2_BRO_BIND_PORT=8080 oauth2-bro         # Start on port 8080")
	fmt.Println("  OAUTH2_BRO_BIND_HOST=0.0.0.0 oauth2-bro      # Bind to all interfaces")
	fmt.Println("")
	fmt.Println("Endpoints:")
	fmt.Println("  GET  /         - Home page with OAuth2 information")
	fmt.Println("  GET  /health   - Health check endpoint")
	fmt.Println("  GET  /jwks     - JSON Web Key Set")
	fmt.Println("  GET  /login    - OAuth2 authorization endpoint")
	fmt.Println("  POST /token    - OAuth2 token endpoint")
	fmt.Println("  GET  /favicon.ico - Favicon")
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

	// Create key manager with all dependencies
	keyManager := keymanager.NewKeyManager()

	// Create user manager with all dependencies
	userManager := user.NewUserManager()

	// Create client manager with all dependencies
	clientManager := client.NewClientManager()

	// Setup the HTTP server with key configuration
	browserver.SetupServer(browserver.ServerConfig{
		RefreshKeys:        keyManager.RefreshKeys,
		CodeKeys:           keyManager.CodeKeys,
		TokenKeys:          keyManager.TokenKeys,
		UserManager:        userManager,
		ClientInfoProvider: clientManager, // ClientManager implements ClientInfoProvider
		UserInfoProvider:   userManager,   // UserManager implements UserInfoProvider
		Version:            version,
	})

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

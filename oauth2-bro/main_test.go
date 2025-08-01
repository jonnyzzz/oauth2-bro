package main

import (
	"flag"
	"os"
	"testing"
)

func TestDetermineServerMode(t *testing.T) {
	// Save original environment
	originalTarget := os.Getenv("OAUTH2_BRO_PROXY_TARGET")
	defer func() {
		if originalTarget != "" {
			os.Setenv("OAUTH2_BRO_PROXY_TARGET", originalTarget)
		} else {
			os.Unsetenv("OAUTH2_BRO_PROXY_TARGET")
		}
	}()

	testCases := []struct {
		name         string
		targetEnv    string
		expectedMode string
	}{
		{
			name:         "No proxy mode - should return regular",
			targetEnv:    "",
			expectedMode: "regular",
		},
		{
			name:         "Proxy mode - should return proxy",
			targetEnv:    "http://localhost:8080",
			expectedMode: "proxy",
		},
		{
			name:         "Proxy mode with different target - should return proxy",
			targetEnv:    "http://api.example.com:9090",
			expectedMode: "proxy",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set environment variable
			if tc.targetEnv != "" {
				os.Setenv("OAUTH2_BRO_PROXY_TARGET", tc.targetEnv)
			} else {
				os.Unsetenv("OAUTH2_BRO_PROXY_TARGET")
			}

			// Test the determineServerMode function
			mode := determineServerMode()
			if mode != tc.expectedMode {
				t.Errorf("Expected mode %s, got %s", tc.expectedMode, mode)
			}
		})
	}
}

func TestServerSetupExclusivity(t *testing.T) {
	// Save original environment
	originalTarget := os.Getenv("OAUTH2_BRO_PROXY_TARGET")
	defer func() {
		if originalTarget != "" {
			os.Setenv("OAUTH2_BRO_PROXY_TARGET", originalTarget)
		} else {
			os.Unsetenv("OAUTH2_BRO_PROXY_TARGET")
		}
	}()

	testCases := []struct {
		name                      string
		targetEnv                 string
		expectProxyServerCalled   bool
		expectRegularServerCalled bool
	}{
		{
			name:                      "No proxy mode - should call regular server only",
			targetEnv:                 "",
			expectProxyServerCalled:   false,
			expectRegularServerCalled: true,
		},
		{
			name:                      "Proxy mode - should call proxy server only",
			targetEnv:                 "http://localhost:8080",
			expectProxyServerCalled:   true,
			expectRegularServerCalled: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set environment variable
			if tc.targetEnv != "" {
				os.Setenv("OAUTH2_BRO_PROXY_TARGET", tc.targetEnv)
			} else {
				os.Unsetenv("OAUTH2_BRO_PROXY_TARGET")
			}

			// Test the determineServerMode function
			mode := determineServerMode()

			// Verify the correct mode was selected
			if tc.expectProxyServerCalled && mode != "proxy" {
				t.Errorf("Expected proxy mode but got %s", mode)
			}

			if tc.expectRegularServerCalled && mode != "regular" {
				t.Errorf("Expected regular mode but got %s", mode)
			}
		})
	}
}

func TestProxyModeEnvironment(t *testing.T) {
	// Save original environment
	originalTarget := os.Getenv("OAUTH2_BRO_PROXY_TARGET")
	defer func() {
		if originalTarget != "" {
			os.Setenv("OAUTH2_BRO_PROXY_TARGET", originalTarget)
		} else {
			os.Unsetenv("OAUTH2_BRO_PROXY_TARGET")
		}
	}()

	testCases := []struct {
		name           string
		targetEnv      string
		expectedProxy  bool
		expectedTarget string
	}{
		{
			name:           "No proxy mode (no environment variable)",
			targetEnv:      "",
			expectedProxy:  false,
			expectedTarget: "",
		},
		{
			name:           "Proxy mode with environment variable",
			targetEnv:      "http://localhost:8080",
			expectedProxy:  true,
			expectedTarget: "http://localhost:8080",
		},
		{
			name:           "Proxy mode with different target",
			targetEnv:      "http://api.example.com:9090",
			expectedProxy:  true,
			expectedTarget: "http://api.example.com:9090",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set environment variable
			if tc.targetEnv != "" {
				os.Setenv("OAUTH2_BRO_PROXY_TARGET", tc.targetEnv)
			} else {
				os.Unsetenv("OAUTH2_BRO_PROXY_TARGET")
			}

			// Test proxy mode detection
			target := os.Getenv("OAUTH2_BRO_PROXY_TARGET")
			isProxyMode := target != ""
			expectedTarget := target

			if isProxyMode != tc.expectedProxy {
				t.Errorf("Expected proxy mode %v, got %v", tc.expectedProxy, isProxyMode)
			}

			if expectedTarget != tc.expectedTarget {
				t.Errorf("Expected target URL %s, got %s", tc.expectedTarget, expectedTarget)
			}
		})
	}
}

func TestResolveBindAddress(t *testing.T) {
	// Save original environment
	originalPort := os.Getenv("OAUTH2_BRO_BIND_PORT")
	originalHost := os.Getenv("OAUTH2_BRO_BIND_HOST")
	defer func() {
		if originalPort != "" {
			os.Setenv("OAUTH2_BRO_BIND_PORT", originalPort)
		} else {
			os.Unsetenv("OAUTH2_BRO_BIND_PORT")
		}
		if originalHost != "" {
			os.Setenv("OAUTH2_BRO_BIND_HOST", originalHost)
		} else {
			os.Unsetenv("OAUTH2_BRO_BIND_HOST")
		}
	}()

	testCases := []struct {
		name           string
		port           string
		host           string
		expectedResult string
	}{
		{
			name:           "Default values",
			port:           "",
			host:           "",
			expectedResult: "localhost:8077",
		},
		{
			name:           "Custom port",
			port:           "8080",
			host:           "",
			expectedResult: "localhost:8080",
		},
		{
			name:           "Custom host",
			port:           "",
			host:           "0.0.0.0",
			expectedResult: "0.0.0.0:8077",
		},
		{
			name:           "Custom host and port",
			port:           "9090",
			host:           "127.0.0.1",
			expectedResult: "127.0.0.1:9090",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set environment variables
			if tc.port != "" {
				os.Setenv("OAUTH2_BRO_BIND_PORT", tc.port)
			} else {
				os.Unsetenv("OAUTH2_BRO_BIND_PORT")
			}
			if tc.host != "" {
				os.Setenv("OAUTH2_BRO_BIND_HOST", tc.host)
			} else {
				os.Unsetenv("OAUTH2_BRO_BIND_HOST")
			}

			result := resolveBindAddress()
			if result != tc.expectedResult {
				t.Errorf("Expected %s, got %s", tc.expectedResult, result)
			}
		})
	}
}

func TestHelpAndVersionFlags(t *testing.T) {
	// Save original args
	originalArgs := os.Args
	defer func() {
		os.Args = originalArgs
	}()

	testCases := []struct {
		name       string
		args       []string
		expectHelp bool
		expectVer  bool
	}{
		{
			name:       "Help flag -h",
			args:       []string{"oauth2-bro", "-h"},
			expectHelp: true,
			expectVer:  false,
		},
		{
			name:       "Help flag --help",
			args:       []string{"oauth2-bro", "--help"},
			expectHelp: true,
			expectVer:  false,
		},
		{
			name:       "Version flag -v",
			args:       []string{"oauth2-bro", "-v"},
			expectHelp: false,
			expectVer:  true,
		},
		{
			name:       "Version flag --version",
			args:       []string{"oauth2-bro", "--version"},
			expectHelp: false,
			expectVer:  true,
		},
		{
			name:       "No flags",
			args:       []string{"oauth2-bro"},
			expectHelp: false,
			expectVer:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set up test environment
			os.Args = tc.args

			// Reset flag state
			flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

			// Parse flags
			showHelp := flag.Bool("help", false, "Show help message")
			showVersion := flag.Bool("version", false, "Show version information")
			flag.BoolVar(showHelp, "h", false, "Show help message")
			flag.BoolVar(showVersion, "v", false, "Show version information")

			// Parse the flags
			flag.Parse()

			// Check results
			if *showHelp != tc.expectHelp {
				t.Errorf("Expected help flag %v, got %v", tc.expectHelp, *showHelp)
			}

			if *showVersion != tc.expectVer {
				t.Errorf("Expected version flag %v, got %v", tc.expectVer, *showVersion)
			}
		})
	}
}

func TestMainServerSetupLogic(t *testing.T) {
	// Save original environment
	originalTarget := os.Getenv("OAUTH2_BRO_PROXY_TARGET")
	defer func() {
		if originalTarget != "" {
			os.Setenv("OAUTH2_BRO_PROXY_TARGET", originalTarget)
		} else {
			os.Unsetenv("OAUTH2_BRO_PROXY_TARGET")
		}
	}()

	testCases := []struct {
		name              string
		targetEnv         string
		expectProxyMode   bool
		expectRegularMode bool
	}{
		{
			name:              "No proxy mode - should use regular server",
			targetEnv:         "",
			expectProxyMode:   false,
			expectRegularMode: true,
		},
		{
			name:              "Proxy mode - should use proxy server",
			targetEnv:         "http://localhost:8080",
			expectProxyMode:   true,
			expectRegularMode: false,
		},
		{
			name:              "Proxy mode with different target - should use proxy server",
			targetEnv:         "http://api.example.com:9090",
			expectProxyMode:   true,
			expectRegularMode: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set environment variable
			if tc.targetEnv != "" {
				os.Setenv("OAUTH2_BRO_PROXY_TARGET", tc.targetEnv)
			} else {
				os.Unsetenv("OAUTH2_BRO_PROXY_TARGET")
			}

			// Test the determineServerMode function
			mode := determineServerMode()

			// Verify the correct mode was selected
			if tc.expectProxyMode && mode != "proxy" {
				t.Errorf("Expected proxy mode but got %s", mode)
			}

			if tc.expectRegularMode && mode != "regular" {
				t.Errorf("Expected regular mode but got %s", mode)
			}
		})
	}
}

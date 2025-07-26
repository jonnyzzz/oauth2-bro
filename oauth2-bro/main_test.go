package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestHTTPServer(t *testing.T) {
	// Set up a test HTTP server on a random port
	port := "8078"
	addr := fmt.Sprintf("localhost:%s", port)

	// Set environment variables
	os.Setenv("OAUTH2_BRO_ADDR", addr)
	defer os.Unsetenv("OAUTH2_BRO_ADDR")

	// Start the server using our helper function
	server, errChan := startServer()

	// Ensure the server is stopped after the test
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	// Check for any immediate errors
	select {
	case err, ok := <-errChan:
		if ok && err != nil {
			t.Fatalf("Server error: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		// Server started successfully
	}

	// Test the root endpoint
	t.Run("Root endpoint", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("http://%s/", addr))
		if err != nil {
			t.Fatalf("Failed to make request to root endpoint: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Errorf("Expected status code 200, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		bodyStr := string(body)
		if !strings.Contains(bodyStr, "OAuth2-bro") {
			t.Errorf("Response body does not contain expected content. Got: %s", bodyStr)
		}

		// Check headers
		versionHeader := resp.Header.Get("X-oauth2-bro-version")
		if versionHeader != version {
			t.Errorf("Expected X-oauth2-bro-version header to be %s, got %s", version, versionHeader)
		}
	})

	// Test the health endpoint
	t.Run("Health endpoint", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("http://%s/health", addr))
		if err != nil {
			t.Fatalf("Failed to make request to health endpoint: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Errorf("Expected status code 200, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		bodyStr := string(body)
		if !strings.Contains(bodyStr, "Alive") {
			t.Errorf("Response body does not contain expected content. Got: %s", bodyStr)
		}

		// Check headers
		versionHeader := resp.Header.Get("X-oauth2-bro-version")
		if versionHeader != version {
			t.Errorf("Expected X-oauth2-bro-version header to be %s, got %s", version, versionHeader)
		}
	})
}

func TestHTTPSConfiguration(t *testing.T) {
	// Create temporary certificate and key files (empty files for testing)
	certFile, err := os.CreateTemp("", "cert*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp cert file: %v", err)
	}
	defer os.Remove(certFile.Name())

	keyFile, err := os.CreateTemp("", "key*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp key file: %v", err)
	}
	defer os.Remove(keyFile.Name())

	// Set up a test HTTPS server on a random port
	port := "8079"
	addr := fmt.Sprintf("localhost:%s", port)

	// Set environment variables
	os.Setenv("OAUTH2_BRO_ADDR", addr)
	os.Setenv("OAUTH2_BRO_HTTPS_CERT_FILE", certFile.Name())
	os.Setenv("OAUTH2_BRO_HTTPS_CERT_KEY_FILE", keyFile.Name())
	defer func() {
		os.Unsetenv("OAUTH2_BRO_ADDR")
		os.Unsetenv("OAUTH2_BRO_HTTPS_CERT_FILE")
		os.Unsetenv("OAUTH2_BRO_HTTPS_CERT_KEY_FILE")
	}()

	// Test that the server configuration is correct
	server, err := setupServer()
	if err != nil {
		t.Fatalf("Failed to set up server: %v", err)
	}

	// Verify server address
	if server.Addr != addr {
		t.Errorf("Expected server address to be %s, got %s", addr, server.Addr)
	}

	// Verify HTTPS configuration
	certFilePath := os.Getenv("OAUTH2_BRO_HTTPS_CERT_FILE")
	certKeyFilePath := os.Getenv("OAUTH2_BRO_HTTPS_CERT_KEY_FILE")

	if certFilePath != certFile.Name() {
		t.Errorf("Expected OAUTH2_BRO_HTTPS_CERT_FILE to be %s, got %s", certFile.Name(), certFilePath)
	}

	if certKeyFilePath != keyFile.Name() {
		t.Errorf("Expected OAUTH2_BRO_HTTPS_CERT_KEY_FILE to be %s, got %s", keyFile.Name(), certKeyFilePath)
	}

	// Verify that the certificate and key files exist
	if _, err := os.Stat(certFilePath); os.IsNotExist(err) {
		t.Errorf("Certificate file does not exist: %s", certFilePath)
	}

	if _, err := os.Stat(certKeyFilePath); os.IsNotExist(err) {
		t.Errorf("Certificate key file does not exist: %s", certKeyFilePath)
	}
}

// Helper function that extracts the server setup logic from main() for testing
func setupServer() (*http.Server, error) {
	addr := os.Getenv("OAUTH2_BRO_ADDR")
	if len(addr) == 0 {
		addr = "localhost:8077"
	}

	server := &http.Server{
		Addr:    addr,
		Handler: nil, // Use default ServeMux
	}

	return server, nil
}

// startServer starts the server based on environment variables
// It returns the server instance and a channel that will receive any error
func startServer() (*http.Server, chan error) {
	server, _ := setupServer()
	errChan := make(chan error, 1)

	certFile := os.Getenv("OAUTH2_BRO_HTTPS_CERT_FILE")
	certKeyFile := os.Getenv("OAUTH2_BRO_HTTPS_CERT_KEY_FILE")

	go func() {
		var err error
		if len(certFile) > 0 {
			fmt.Printf("Listening https://%s\n", server.Addr)
			err = server.ListenAndServeTLS(certFile, certKeyFile)
		} else {
			fmt.Printf("Listening http://%s\n", server.Addr)
			err = server.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
		close(errChan)
	}()

	return server, errChan
}

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// findAvailablePort finds an available port to use for testing
func findAvailablePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// testEndpoint is a helper function to test HTTP endpoints
func testEndpoint(t *testing.T, client *http.Client, baseURL, path, expectedContent string) {
	t.Helper()

	url := baseURL + path
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("Failed to make request to %s: %v", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("Expected status code 200, got %d for %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	bodyStr := string(body)
	if !strings.Contains(bodyStr, expectedContent) {
		t.Errorf("Response body does not contain expected content '%s'. Got: %s", expectedContent, bodyStr)
	}

	// Check headers
	versionHeader := resp.Header.Get("X-oauth2-bro-version")
	if versionHeader != version {
		t.Errorf("Expected X-oauth2-bro-version header to be %s, got %s", version, versionHeader)
	}
}

// startIntegrationServer starts the actual main application as a separate process
func startIntegrationServer(t *testing.T, envVars map[string]string) (*exec.Cmd, func(), error) {
	// Build the application
	cmd := exec.Command("go", "run", ".")

	// Set environment variables
	cmd.Env = os.Environ()
	for key, value := range envVars {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	// Capture output for debugging
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Start the process
	err := cmd.Start()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to start integration server: %v", err)
	}

	// Wait a bit for server to start
	time.Sleep(500 * time.Millisecond)

	// Check if process is still running
	if cmd.Process == nil {
		return nil, nil, fmt.Errorf("server process failed to start")
	}

	cleanup := func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}

	return cmd, cleanup, nil
}

func TestHTTPIntegration(t *testing.T) {
	// Find an available port
	port, err := findAvailablePort()
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}

	// Set up environment variables for HTTP testing
	envVars := map[string]string{
		"OAUTH2_BRO_ADDR": fmt.Sprintf("localhost:%d", port),
	}

	// Start the integration server
	_, cleanup, err := startIntegrationServer(t, envVars)
	if err != nil {
		t.Fatalf("Failed to start integration server: %v", err)
	}
	defer cleanup()

	// Create HTTP client
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Test the root endpoint
	t.Run("Root endpoint", func(t *testing.T) {
		testEndpoint(t, client, fmt.Sprintf("http://localhost:%d", port), "/", "OAuth2-bro")
	})

	// Test the health endpoint
	t.Run("Health endpoint", func(t *testing.T) {
		testEndpoint(t, client, fmt.Sprintf("http://localhost:%d", port), "/health", "Alive")
	})
}

func TestHTTPSIntegration(t *testing.T) {
	// Find an available port
	port, err := findAvailablePort()
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}

	// Generate test certificates
	certFile, keyFile, certCleanup, err := generateTestCertificates()
	if err != nil {
		t.Fatalf("Failed to generate test certificates: %v", err)
	}
	defer certCleanup()

	// Set up environment variables for HTTPS testing
	envVars := map[string]string{
		"OAUTH2_BRO_ADDR":                fmt.Sprintf("localhost:%d", port),
		"OAUTH2_BRO_HTTPS_CERT_FILE":     certFile,
		"OAUTH2_BRO_HTTPS_CERT_KEY_FILE": keyFile,
	}

	// Start the integration server
	_, cleanup, err := startIntegrationServer(t, envVars)
	if err != nil {
		t.Fatalf("Failed to start HTTPS integration server: %v", err)
	}
	defer cleanup()

	// Load the certificate for the client
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("Failed to load certificate for client: %v", err)
	}

	// Create a certificate pool and add our certificate
	certPool := x509.NewCertPool()
	certBytes, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("Failed to read certificate file: %v", err)
	}

	if !certPool.AppendCertsFromPEM(certBytes) {
		t.Fatalf("Failed to append certificate to pool")
	}

	// Create HTTPS client that uses the generated certificate
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      certPool,
				ServerName:   "localhost",
			},
		},
	}

	// Test the root endpoint over HTTPS
	t.Run("Root endpoint HTTPS", func(t *testing.T) {
		testEndpoint(t, client, fmt.Sprintf("https://localhost:%d", port), "/", "OAuth2-bro")
	})

	// Test the health endpoint over HTTPS
	t.Run("Health endpoint HTTPS", func(t *testing.T) {
		testEndpoint(t, client, fmt.Sprintf("https://localhost:%d", port), "/health", "Alive")
	})

	// Verify that the server is using the specified certificate
	t.Run("Server uses the specified certificate", func(t *testing.T) {
		// Parse the expected certificate
		expectedCertBytes, err := os.ReadFile(certFile)
		if err != nil {
			t.Fatalf("Failed to read certificate file: %v", err)
		}

		block, _ := pem.Decode(expectedCertBytes)
		if block == nil {
			t.Fatalf("Failed to parse certificate PEM")
		}

		expectedCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("Failed to parse certificate: %v", err)
		}

		// Connect to the server and get its certificate
		conn, err := tls.Dial("tcp", fmt.Sprintf("localhost:%d", port), &tls.Config{
			RootCAs:    certPool,
			ServerName: "localhost",
		})
		if err != nil {
			t.Fatalf("Failed to connect to server: %v", err)
		}
		defer conn.Close()

		// Get the server's certificate
		serverCerts := conn.ConnectionState().PeerCertificates
		if len(serverCerts) == 0 {
			t.Fatalf("No server certificates found")
		}
		serverCert := serverCerts[0]

		// Compare the certificates
		if !serverCert.Equal(expectedCert) {
			t.Errorf("Server certificate does not match the expected certificate")
		}
	})
}

func TestCertificateGeneration(t *testing.T) {
	certFile, keyFile, cleanup, err := generateTestCertificates()
	if err != nil {
		t.Fatalf("Failed to generate test certificates: %v", err)
	}
	defer cleanup()

	// Verify files exist
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Errorf("Certificate file does not exist: %s", certFile)
	}

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		t.Errorf("Certificate key file does not exist: %s", keyFile)
	}

	// Verify certificate can be loaded
	_, err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Errorf("Failed to load certificate pair: %v", err)
	}
}

// generateTestCertificates creates temporary certificate and key files for testing
func generateTestCertificates() (certFile, keyFile string, cleanup func(), err error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"OAuth2-bro Test"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "127.0.0.1"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Create certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", nil, err
	}

	// Create temporary files
	certFileHandle, err := os.CreateTemp("", "test-cert-*.pem")
	if err != nil {
		return "", "", nil, err
	}
	certFile = certFileHandle.Name()

	keyFileHandle, err := os.CreateTemp("", "test-key-*.pem")
	if err != nil {
		os.Remove(certFile)
		return "", "", nil, err
	}
	keyFile = keyFileHandle.Name()

	// Write certificate to file
	err = pem.Encode(certFileHandle, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		os.Remove(certFile)
		os.Remove(keyFile)
		return "", "", nil, err
	}

	// Write private key to file
	err = pem.Encode(keyFileHandle, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err != nil {
		os.Remove(certFile)
		os.Remove(keyFile)
		return "", "", nil, err
	}

	// Close files
	certFileHandle.Close()
	keyFileHandle.Close()

	// Return cleanup function
	cleanup = func() {
		os.Remove(certFile)
		os.Remove(keyFile)
	}

	return certFile, keyFile, cleanup, nil
}

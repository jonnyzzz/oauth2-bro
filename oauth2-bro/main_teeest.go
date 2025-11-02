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
	//goland:noinspection GoUnhandledErrorResult
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

// TestCertificate holds certificate data for testing
type TestCertificate struct {
	CertFile    string
	KeyFile     string
	Certificate *x509.Certificate
	CertPool    *x509.CertPool
	Cleanup     func()
}

// generateTestCertificates creates temporary certificate and key files for testing
// Returns certificate files, parsed certificate, and a certificate pool for client verification
func generateTestCertificates() (*TestCertificate, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
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
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	// Create certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	// Parse the certificate for verification
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	// Create certificate pool for client verification
	certPool := x509.NewCertPool()
	certPool.AddCert(cert)

	// Create temporary files
	certFileHandle, err := os.CreateTemp("", "test-cert-*.pem")
	if err != nil {
		return nil, err
	}
	certFile := certFileHandle.Name()

	keyFileHandle, err := os.CreateTemp("", "test-key-*.pem")
	if err != nil {
		os.Remove(certFile)
		return nil, err
	}
	keyFile := keyFileHandle.Name()

	// Write certificate to file
	err = pem.Encode(certFileHandle, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		os.Remove(certFile)
		os.Remove(keyFile)
		return nil, err
	}

	// Write private key to file
	err = pem.Encode(keyFileHandle, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err != nil {
		os.Remove(certFile)
		os.Remove(keyFile)
		return nil, err
	}

	// Close files
	certFileHandle.Close()
	keyFileHandle.Close()

	// Create cleanup function
	cleanup := func() {
		os.Remove(certFile)
		os.Remove(keyFile)
	}

	return &TestCertificate{
		CertFile:    certFile,
		KeyFile:     keyFile,
		Certificate: cert,
		CertPool:    certPool,
		Cleanup:     cleanup,
	}, nil
}

func TestHTTPIntegration(t *testing.T) {
	// Find an available port
	port, err := findAvailablePort()
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}

	// Set up environment variables for HTTP testing
	envVars := map[string]string{
		"OAUTH2_BRO_HTTP_PORT": fmt.Sprintf("%d", port),
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

	// Generate test certificate
	testCert, err := generateTestCertificates()
	if err != nil {
		t.Fatalf("Failed to generate test certificates: %v", err)
	}
	defer testCert.Cleanup()

	// Set up environment variables for HTTPS testing
	envVars := map[string]string{
		"OAUTH2_BRO_HTTPS_PORT":          fmt.Sprintf("%d", port),
		"OAUTH2_BRO_HTTPS_CERT_FILE":     testCert.CertFile,
		"OAUTH2_BRO_HTTPS_CERT_KEY_FILE": testCert.KeyFile,
	}

	// Start the integration server
	_, cleanup, err := startIntegrationServer(t, envVars)
	if err != nil {
		t.Fatalf("Failed to start HTTPS integration server: %v", err)
	}
	defer cleanup()

	// Create HTTPS client with proper certificate verification
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    testCert.CertPool,
				ServerName: "localhost",
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

	// Verify certificate is properly used
	t.Run("Server uses the specified certificate", func(t *testing.T) {
		conn, err := tls.Dial("tcp", fmt.Sprintf("localhost:%d", port), &tls.Config{
			RootCAs:    testCert.CertPool,
			ServerName: "localhost",
		})
		if err != nil {
			t.Fatalf("Failed to connect to server: %v", err)
		}
		defer conn.Close()

		serverCerts := conn.ConnectionState().PeerCertificates
		if len(serverCerts) == 0 {
			t.Fatalf("No server certificates found")
		}

		if !serverCerts[0].Equal(testCert.Certificate) {
			t.Errorf("Server certificate does not match expected certificate")
		}
	})
}

func TestDualHTTPAndHTTPSIntegration(t *testing.T) {
	// Find two available ports
	httpPort, err := findAvailablePort()
	if err != nil {
		t.Fatalf("Failed to find available HTTP port: %v", err)
	}

	httpsPort, err := findAvailablePort()
	if err != nil {
		t.Fatalf("Failed to find available HTTPS port: %v", err)
	}

	// Generate test certificate
	testCert, err := generateTestCertificates()
	if err != nil {
		t.Fatalf("Failed to generate test certificates: %v", err)
	}
	defer testCert.Cleanup()

	// Set up environment variables for dual HTTP/HTTPS testing
	envVars := map[string]string{
		"OAUTH2_BRO_HTTP_PORT":           fmt.Sprintf("%d", httpPort),
		"OAUTH2_BRO_HTTPS_PORT":          fmt.Sprintf("%d", httpsPort),
		"OAUTH2_BRO_HTTPS_CERT_FILE":     testCert.CertFile,
		"OAUTH2_BRO_HTTPS_CERT_KEY_FILE": testCert.KeyFile,
	}

	// Start the integration server
	_, cleanup, err := startIntegrationServer(t, envVars)
	if err != nil {
		t.Fatalf("Failed to start dual HTTP/HTTPS integration server: %v", err)
	}
	defer cleanup()

	// Test HTTP endpoint
	t.Run("HTTP endpoint works", func(t *testing.T) {
		httpClient := &http.Client{
			Timeout: 10 * time.Second,
		}
		testEndpoint(t, httpClient, fmt.Sprintf("http://localhost:%d", httpPort), "/health", "Alive")
	})

	// Test HTTPS endpoint
	t.Run("HTTPS endpoint works", func(t *testing.T) {
		// Create HTTPS client with proper certificate verification
		httpsClient := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    testCert.CertPool,
					ServerName: "localhost",
				},
			},
		}
		testEndpoint(t, httpsClient, fmt.Sprintf("https://localhost:%d", httpsPort), "/health", "Alive")
	})
}

func TestCertificateGeneration(t *testing.T) {
	testCert, err := generateTestCertificates()
	if err != nil {
		t.Fatalf("Failed to generate test certificates: %v", err)
	}
	defer testCert.Cleanup()

	// Verify files exist
	if _, err := os.Stat(testCert.CertFile); os.IsNotExist(err) {
		t.Errorf("Certificate file does not exist: %s", testCert.CertFile)
	}

	if _, err := os.Stat(testCert.KeyFile); os.IsNotExist(err) {
		t.Errorf("Certificate key file does not exist: %s", testCert.KeyFile)
	}

	// Verify certificate can be loaded
	_, err = tls.LoadX509KeyPair(testCert.CertFile, testCert.KeyFile)
	if err != nil {
		t.Errorf("Failed to load certificate pair: %v", err)
	}

	// Verify certificate pool is not nil
	if testCert.CertPool == nil {
		t.Errorf("Certificate pool is nil")
	}

	// Verify parsed certificate is not nil
	if testCert.Certificate == nil {
		t.Errorf("Parsed certificate is nil")
	}
}

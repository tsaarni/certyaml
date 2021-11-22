package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/tsaarni/certyaml"
)

func main() {
	// Define certificate hierarchy.

	// CA certificate is defined by not setting Issuer field.
	ca := certyaml.Certificate{
		Subject: "cn=ca",
	}

	// Define server certificate with FQDN in SubjectAltNameS.
	// Issuer is set with a pointer to CA certificate.
	server := certyaml.Certificate{
		Subject:         "CN=server",
		SubjectAltNames: []string{"DNS:localhost"},
		Issuer:          &ca,
	}

	// Client certificate also refers to the same CA as the Issuer.
	client := certyaml.Certificate{
		Subject: "CN=client",
		Issuer:  &ca,
	}

	// Create CertPool with CA certificate loaded as as trusted CA cert.
	caCert, _ := ca.X509Certificate()
	certPool := x509.NewCertPool()
	certPool.AddCert(&caCert)

	// Also get server and client cert as tls.Certificate.
	serverCert, _ := server.TLSCertificate()
	clientCert, _ := client.TLSCertificate()

	// Create and run HTTPS server.
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
			fmt.Fprintf(w, "Hello HTTPS world!\n")
		})

		server := &http.Server{
			Addr:    "localhost:8443",
			Handler: mux,
			TLSConfig: &tls.Config{
				// Configure server certificate.
				Certificates: []tls.Certificate{serverCert},

				// Require client to present valid client certificate.
				ClientAuth: tls.RequireAndVerifyClientCert,

				// Configure trusted CA certificate to validate client cert.
				ClientCAs: certPool,

				MinVersion: tls.VersionTLS13,
			},
		}

		// Certs were provided in tls.Config so using "" as filenames.
		err := server.ListenAndServeTLS("", "")
		if err != nil {
			fmt.Printf("HTTPS server failed to run: %s", err)
			os.Exit(1)
		}
	}()

	// Hack: wait for the go routine to spin up.
	time.Sleep(1 * time.Second)

	httpClient := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// Configure client certificate.
				Certificates: []tls.Certificate{clientCert},

				// Configure trusted CA certificate to validate server cert.
				RootCAs: certPool,

				MinVersion: tls.VersionTLS13,
			},
		},
	}

	// Make HTTPS request.
	resp, err := httpClient.Get("https://localhost:8443")
	if err != nil {
		fmt.Printf("HTTP request failed: %s", err)
		os.Exit(1)
	}

	buf, _ := io.ReadAll(resp.Body)
	fmt.Printf("Received response: %s", buf)
}

// Copyright certyaml authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certyaml

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/tsaarni/x500dn"
)

// Certificate defines the properties for generating a certificate.
//
// Note that struct tags are for certyaml command line command to unmarshal manifest file.
type Certificate struct {
	// Subject defines the distinguished name for the certificate.
	// Example: CN=Joe.
	Subject string `json:"subject"`

	// SubjectAltNames defines an optional list of values for x509 Subject Alternative Name extension.
	// Examples: DNS:www.example.com, IP:1.2.3.4, URI:https://www.example.com.
	SubjectAltNames []string `json:"sans"`

	// KeyType defines the certificate key algorithm.
	// Default value is KeyTypeEC (elliptic curve) if KeyType is undefined (when value is 0).
	KeyType KeyType `json:"-"`

	// KeySize defines the key length in bits.
	// Default value is 256 (EC) or 2048 (RSA) if KeySize is undefined (when value is 0).
	// Examples: For key_type EC: 256, 384, 521. For key_type RSA: 1024, 2048, 4096.
	KeySize int `json:"key_size"`

	// Expires automatically defines certificate's NotAfter field by adding duration defined in Expires to the current time.
	// Default value is 8760h (one year) if Expires is undefined (when value is nil).
	// NotAfter takes precedence over Expires.
	Expires *time.Duration `json:"-"`

	// KeyUsage defines bitmap of values for x509 key usage extension.
	// If KeyUsage is undefined (when value is 0),
	// CertSign and CRLSign are set for CA certificates,
	// KeyEncipherment and DigitalSignature are set for end-entity certificates.
	KeyUsage x509.KeyUsage `json:"-"`

	// ExtKeyUsage defines a sequence of x509 extended key usages.
	// Not set by default.
	ExtKeyUsage []x509.ExtKeyUsage `json:"-"`

	// Issuer refers to the issuer Certificate.
	// Self-signed certificate is generated if Issuer is undefined (when value is nil).
	Issuer *Certificate `json:"-" hash:"-"`

	// IsCA defines if certificate is / is not CA.
	// If IsCA is undefined (when value is nil), true is set by default for self-signed certificates (Issuer is nil).
	IsCA *bool `json:"ca"`

	// NotBefore defines certificate not to be valid before this time.
	// Default value is current time if NotBefore is undefined (when value is nil).
	NotBefore *time.Time `json:"not_before"`

	// NotAfter defines certificate not to be valid after this time.
	// Default value is current time +  Expires if NotAfter is undefined (when value is nil)
	NotAfter *time.Time `json:"not_after"`

	// SerialNumber defines serial number for the certificate.
	// If not set, the default value is current time in nanoseconds.
	SerialNumber *big.Int `json:"-" hash:"-"`

	// GeneratedCert is a pointer to the generated certificate and private key.
	// It is automatically set after calling any of the Certificate functions.
	GeneratedCert *tls.Certificate `json:"-" hash:"-"`
}

type KeyType uint

const (
	KeyTypeEC = iota
	KeyTypeRSA
)

// TLSCertificate returns the Certificate as tls.Certificate.
// Complete certificate chain (up to but not including root) is included for end-entity certificates.
// A key pair and certificate will be generated at first call of any Certificate functions.
// Error is not nil if generation fails.
func (c *Certificate) TLSCertificate() (tls.Certificate, error) {
	err := c.ensureGenerated()
	if err != nil {
		return tls.Certificate{}, err
	}
	return *c.GeneratedCert, nil
}

// X509Certificate returns the Certificate as x509.Certificate.
// A key pair and certificate will be generated at first call of any Certificate functions.
// Error is not nil if generation fails.
func (c *Certificate) X509Certificate() (x509.Certificate, error) {
	err := c.ensureGenerated()
	if err != nil {
		return x509.Certificate{}, err
	}
	cert, err := x509.ParseCertificate(c.GeneratedCert.Certificate[0])
	return *cert, err
}

// PublicKey returns crypto.PublicKey associated to the Certificate.
// A key pair and certificate will be generated at first call of any Certificate functions.
// Error is not nil if generation fails.
func (c *Certificate) PublicKey() (crypto.PublicKey, error) {
	err := c.ensureGenerated()
	if err != nil {
		return nil, err
	}
	return c.GeneratedCert.PrivateKey.(crypto.Signer).Public(), nil
}

// PrivateKey returns crypto.Signer that represents the PrivateKey associated to the Certificate.
// A key pair and certificate will be generated at first call of any Certificate functions.
// Error is not nil if generation fails.
func (c *Certificate) PrivateKey() (crypto.Signer, error) {
	err := c.ensureGenerated()
	if err != nil {
		return nil, err
	}
	return c.GeneratedCert.PrivateKey.(crypto.Signer), nil
}

// PEM returns the Certificate as certificate and private key PEM buffers.
// Complete certificate chain (up to but not including root) is included for end-entity certificates.
// A key pair and certificate will be generated at first call of any Certificate functions.
// Error is not nil if generation fails.
func (c *Certificate) PEM() (cert []byte, key []byte, err error) {
	err = c.ensureGenerated()
	if err != nil {
		return
	}

	cert, err = encodeToPEMBlocks("CERTIFICATE", c.GeneratedCert.Certificate)
	if err != nil {
		return
	}

	k, err := x509.MarshalPKCS8PrivateKey(c.GeneratedCert.PrivateKey)
	if err != nil {
		cert = nil
		return
	}

	key, err = encodeToPEMBlocks("PRIVATE KEY", [][]byte{k})
	if err != nil {
		cert = nil
		return
	}

	return
}

// WritePEM writes the Certificate as certificate and private key PEM files.
// Complete certificate chain (up to but not including root) is included for end-entity certificates.
// A key pair and certificate will be generated at first call of any Certificate functions.
// Error is not nil if generation fails.
func (c *Certificate) WritePEM(certFile, keyFile string) error {
	err := c.ensureGenerated()
	if err != nil {
		return err
	}

	cert, key, err := c.PEM()
	if err != nil {
		return err
	}
	err = os.WriteFile(certFile, cert, 0600)
	if err != nil {
		return err
	}
	err = os.WriteFile(keyFile, key, 0600)
	if err != nil {
		return err
	}

	return nil
}

func (c *Certificate) defaults() error {
	_, err := x500dn.ParseDN(c.Subject)
	if err != nil {
		return err
	}

	if c.KeySize == 0 {
		if c.KeyType == KeyTypeEC {
			c.KeySize = 256
		} else if c.KeyType == KeyTypeRSA {
			c.KeySize = 2048
		}
	}

	if c.Expires == nil && c.NotAfter == nil {
		year := 8760 * time.Hour
		c.Expires = &year
	}

	if c.IsCA == nil {
		noExplicitIssuer := (c.Issuer == nil)
		c.IsCA = &noExplicitIssuer
	}

	if c.KeyUsage == 0 {
		if *c.IsCA {
			c.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		} else {
			c.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
		}
	}

	if c.SerialNumber == nil {
		c.SerialNumber = big.NewInt(time.Now().UnixNano())
	}

	return nil
}

func (c *Certificate) ensureGenerated() error {
	if c.GeneratedCert == nil {
		err := c.Generate()
		if err != nil {
			return err
		}
	}

	return nil
}

// Generate forces re-generation of key pair and certificate according to current state of the Certificate.
// Usually it is automatically called when necessary, e.g. PEM() will internally call Generate().
// It can be called explicitly after changing Certificate fields since certificate was last generated,
// or when a new certificate with same values is needed.
// Error is not nil if generation fails.
func (c *Certificate) Generate() error {
	// Traverse the certificate hierarchy recursively to ensure issuing CAs have been generated as well.
	if c.Issuer != nil {
		err := c.Issuer.ensureGenerated()
		if err != nil {
			return err
		}
	}

	// Ensure defaults are set correctly.
	err := c.defaults()
	if err != nil {
		return err
	}

	// Generate key-pair for the certificate.
	var key crypto.Signer
	if c.KeyType == KeyTypeEC {
		var curve elliptic.Curve
		switch c.KeySize {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return fmt.Errorf("invalid EC key size: %d (valid: 256, 384, 521)", c.KeySize)
		}
		key, err = ecdsa.GenerateKey(curve, rand.Reader)
	} else if c.KeyType == KeyTypeRSA {
		key, err = rsa.GenerateKey(rand.Reader, c.KeySize)
	}
	if err != nil {
		return err
	}

	// Calculate the validity dates according to given values and current time.
	var notBefore, notAfter time.Time
	if c.NotBefore != nil {
		notBefore = *c.NotBefore
	} else {
		notBefore = time.Now()
	}

	if c.NotAfter != nil {
		notAfter = *c.NotAfter
	} else {
		notAfter = notBefore.UTC().Add(*c.Expires)
	}

	// Get subject name as pkix.Name.
	// Validity is already ensured by calling default() so it is safe to ignore error.
	name, _ := x500dn.ParseDN(c.Subject)

	template := &x509.Certificate{
		SerialNumber:          c.SerialNumber,
		Subject:               *name,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              c.KeyUsage,
		ExtKeyUsage:           c.ExtKeyUsage,
		BasicConstraintsValid: *c.IsCA,
		IsCA:                  *c.IsCA,
	}

	for _, san := range c.SubjectAltNames {
		switch {
		case strings.HasPrefix(san, "DNS:"):
			template.DNSNames = append(template.DNSNames, strings.TrimPrefix(san, "DNS:"))
		case strings.HasPrefix(san, "URI:"):
			uri, err := url.Parse(strings.TrimPrefix(san, "URI:"))
			if err != nil {
				return err
			}
			template.URIs = append(template.URIs, uri)
		case strings.HasPrefix(san, "IP:"):
			ip := net.ParseIP(strings.TrimPrefix(san, "IP:"))
			if ip == nil {
				return fmt.Errorf("invalid IP address: %s", strings.TrimPrefix(san, "IP:"))
			}
			template.IPAddresses = append(template.IPAddresses, ip)
		default:
			return fmt.Errorf("unknown san, forgot prefix? (must be one of DNS:|URI:|IP:): %s", san)
		}
	}

	var issuerCert *x509.Certificate
	var issuerKey crypto.Signer
	var chain [][]byte
	if c.Issuer != nil {
		issuerCert, err = x509.ParseCertificate(c.Issuer.GeneratedCert.Certificate[0])
		if err != nil {
			return nil
		}
		issuerKey = c.Issuer.GeneratedCert.PrivateKey.(crypto.Signer)

		// Add certificate chain to end-entity certificates.
		if !*c.IsCA {
			issuer := c.Issuer
			for issuer != nil {
				// Add issuer to chain unless it is root certificate.
				if issuer.Issuer != nil {
					chain = append(chain, issuer.GeneratedCert.Certificate[0])
				}
				issuer = issuer.Issuer
			}
		}
	} else {
		// create self-signed certificate
		issuerCert = template
		issuerKey = key
	}

	var cert []byte
	cert, err = x509.CreateCertificate(rand.Reader, template, issuerCert, key.Public(), issuerKey)
	if err != nil {
		return nil
	}

	c.GeneratedCert = &tls.Certificate{
		Certificate: append([][]byte{cert}, chain...),
		PrivateKey:  key,
	}

	return nil
}

func encodeToPEMBlocks(blockType string, blocks [][]byte) ([]byte, error) {
	var buf bytes.Buffer

	for _, b := range blocks {
		err := pem.Encode(&buf, &pem.Block{
			Type:  blockType,
			Bytes: b,
		})
		if err != nil {
			return nil, err
		}

	}

	return buf.Bytes(), nil
}

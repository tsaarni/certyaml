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
type Certificate struct {
	// Subject defines the distinguished name for the certificate.
	// Example: CN=Joe.
	Subject string

	// SubjectAltNames defines an optional list of values for x509 Subject Alternative Name extension.
	// Examples: DNS:www.example.com, IP:1.2.3.4, URI:https://www.example.com.
	SubjectAltNames []string

	// KeyType defines the certificate key algorithm.
	// Default value is KeyTypeEC (elliptic curve).
	KeyType *KeyType

	// KeySize defines the key length in bits.
	// Default value is 256 if key_size is not defined.
	// Examples: For key_type EC: 256, 384, 521. For key_type RSA: 1024, 2048, 4096.
	KeySize int

	// Expires automatically defines certificate's NotAfter field by adding duration defined in Expires to the current time.
	// Default value is 8760h (one year) if expires is not defined.
	// NotAfter takes precedence over Expires.
	Expires *time.Duration

	// KeyUsage defines bitmap of values for x509 key usage extension.
	// If key_usages is not defined, CertSign and CRLSign are set for CA certificates, KeyEncipherment and DigitalSignature are set for end-entity certificates.
	KeyUsage x509.KeyUsage

	// Issuer refers to the issuer Certificate.
	// Self-signed certificate is generated if issuer is nil.
	Issuer *Certificate

	// IsCA defines if certificate is / is not CA.
	// If IsCA is not defined, true is set by default for self-signed certificates (Issuer is nil).
	IsCA *bool

	// NotBefore defines certificate not to be valid before this time.
	NotBefore *time.Time

	// NotAfter defines certificate not to be valid after this time.
	NotAfter *time.Time

	//
	// Private fields follow.
	//

	// generatedCert is a pointer to the generated certificate and private key.
	generatedCert *tls.Certificate
}

type KeyType int

const (
	KeyTypeEC = iota
	KeyTypeRSA
)

func (c *Certificate) TLSCertificate() (tls.Certificate, error) {
	err := c.ensureGenerated()
	if err != nil {
		return tls.Certificate{}, err
	}
	return *c.generatedCert, nil
}

func (c *Certificate) X509Certificate() (x509.Certificate, error) {
	err := c.ensureGenerated()
	if err != nil {
		return x509.Certificate{}, err
	}
	cert, err := x509.ParseCertificate(c.generatedCert.Certificate[0])
	return *cert, err
}

func (c *Certificate) writePEM(certFile, keyFile string) error {
	err := c.ensureGenerated()
	if err != nil {
		return err
	}

	cf, err := os.Create(certFile)
	if err != nil {
		return err
	}
	defer cf.Close()

	pem.Encode(cf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.generatedCert.Certificate[0],
	})

	kf, err := os.Create(keyFile)
	if err != nil {
		return err
	}
	defer kf.Close()

	bytes, err := x509.MarshalPKCS8PrivateKey(c.generatedCert.PrivateKey)
	if err != nil {
		return err
	}

	pem.Encode(kf, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: bytes,
	})

	return nil
}

func (c *Certificate) defaults() error {
	_, err := x500dn.ParseDN(c.Subject)
	if err != nil {
		return err
	}

	if c.KeyType == nil {
		var k KeyType = KeyTypeEC
		c.KeyType = &k
	}

	if c.KeySize == 0 {
		if *c.KeyType == KeyTypeEC {
			c.KeySize = 256
		} else if *c.KeyType == KeyTypeRSA {
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

	return nil
}

func (c *Certificate) ensureGenerated() error {
	// Traverse the certificate hierarchy recursively to generate all certs.
	if c.Issuer != nil {
		err := c.Issuer.ensureGenerated()
		if err != nil {
			return err
		}
	}

	if c.generatedCert == nil {
		err := c.Generate()
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Certificate) Generate() error {
	// Ensure defaults are set correctly.
	err := c.defaults()
	if err != nil {
		return err
	}

	// Generate key-pair for the certificate.
	var key crypto.Signer
	if *c.KeyType == KeyTypeEC {
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
	} else if *c.KeyType == KeyTypeRSA {
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
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               *name,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              c.KeyUsage,
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
	if c.Issuer != nil {
		issuerCert, err = x509.ParseCertificate(c.Issuer.generatedCert.Certificate[0])
		if err != nil {
			return nil
		}
		issuerKey = c.Issuer.generatedCert.PrivateKey.(crypto.Signer)

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

	c.generatedCert = &tls.Certificate{
		Certificate: [][]byte{cert},
		PrivateKey:  key,
	}

	return nil
}

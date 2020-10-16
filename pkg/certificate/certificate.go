// Copyright 2020 Tero Saarni
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

package certificate

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/cnf/structhash"
	"github.com/tsaarni/x500dn"
)

// Certificate stores the required parameters for creating certificate and key
type Certificate struct {
	Subject        string   `yaml:"subject"`
	SubjectAltName []string `yaml:"sans"`
	KeyType        string   `yaml:"key_type"`
	KeySize        int      `yaml:"key_size"`
	Expires        string
	KeyUsage       []string `yaml:"key_usages"`
	Issuer         string
	Filename       string     `yaml:"filename"`
	IsCA           *bool      `yaml:"ca"`
	NotBefore      *time.Time `yaml:"not_before"`
	NotAfter       *time.Time `yaml:"not_after"`

	// generated at runtime, not read from yaml
	Key       crypto.Signer `yaml:"-"`
	Cert      []byte        `yaml:"-"`
	Generated bool          `hash:"-"`
}

// getKeyUsage converts key usage string representation to x509.KeyUsage
func getKeyUsage(keyUsage []string) (x509.KeyUsage, error) {
	var result x509.KeyUsage
	var usages = map[string]x509.KeyUsage{
		"DigitalSignature":  x509.KeyUsageDigitalSignature,
		"ContentCommitment": x509.KeyUsageContentCommitment,
		"KeyEncipherment":   x509.KeyUsageKeyEncipherment,
		"DataEncipherment":  x509.KeyUsageDataEncipherment,
		"KeyAgreement":      x509.KeyUsageKeyAgreement,
		"CertSign":          x509.KeyUsageCertSign,
		"CRLSign":           x509.KeyUsageCRLSign,
		"EncipherOnly":      x509.KeyUsageEncipherOnly,
		"DecipherOnly":      x509.KeyUsageDecipherOnly,
	}

	for _, usage := range keyUsage {
		ku, ok := usages[usage]
		if !ok {
			return result, fmt.Errorf("Invalid key usage %s", usage)
		}
		result |= ku
	}

	return result, nil
}

const (
	ecKey  string = "EC"
	rsaKey        = "RSA"
)

func normalizeKeyType(keyType string) (string, error) {
	if keyType == "" {
		return ecKey, nil
	} else if strings.EqualFold(keyType, "EC") {
		return ecKey, nil
	} else if strings.EqualFold(keyType, "RSA") {
		return rsaKey, nil
	} else {
		return "", fmt.Errorf("Invalid key type %s", keyType)
	}
}

// Defaults sets the default values to Certificate fields that may be overwritten by the fields in the certificate manifest file
func (c *Certificate) defaults() error {
	if c.Subject == "" {
		return errors.New("Mandatory field subject: missing")
	}

	name, err := x500dn.ParseDN(c.Subject)
	if err != nil {
		return err
	}

	if name.CommonName == "" {
		return errors.New("Subject must contain CN")
	}

	c.KeyType, err = normalizeKeyType(c.KeyType)
	if err != nil {
		return err
	}

	if c.KeySize == 0 {
		if c.KeyType == ecKey {
			c.KeySize = 256
		} else if c.KeyType == rsaKey {
			c.KeySize = 2048
		}
	}

	if c.Expires == "" && c.NotAfter == nil {
		c.Expires = "8760h" // year
	}

	if c.IsCA == nil {
		noExplicitIssuer := (c.Issuer == "")
		c.IsCA = &noExplicitIssuer
	}

	if len(c.KeyUsage) == 0 {
		if *c.IsCA {
			c.KeyUsage = []string{"CertSign", "CRLSign"}
		} else {
			c.KeyUsage = []string{"KeyEncipherment", "DigitalSignature"}
		}
	}

	if c.Filename == "" {
		c.Filename = name.CommonName
	}

	return nil
}

// Generate creates a certificate and key
func (c *Certificate) Generate(ca *Certificate) error {
	err := c.defaults()
	if err != nil {
		return err
	}

	keyUsage, err := getKeyUsage(c.KeyUsage)
	if err != nil {
		return err
	}

	if c.KeyType == ecKey {
		var curve elliptic.Curve
		switch c.KeySize {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return fmt.Errorf("Invalid EC key size: %d (valid: 256, 384, 521)", c.KeySize)
		}
		c.Key, err = ecdsa.GenerateKey(curve, rand.Reader)
	} else if c.KeyType == rsaKey {
		c.Key, err = rsa.GenerateKey(rand.Reader, c.KeySize)
	}

	if err != nil {
		return err
	}

	var notBefore, notAfter time.Time
	if c.NotBefore != nil {
		notBefore = *c.NotBefore
	} else {
		notBefore = time.Now()
	}

	if c.NotAfter != nil {
		notAfter = *c.NotAfter
	} else {
		expiry, err := time.ParseDuration(c.Expires)
		if err != nil {
			return err
		}
		notAfter = notBefore.UTC().Add(expiry)
	}

	name, _ := x500dn.ParseDN(c.Subject)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               *name,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		BasicConstraintsValid: *c.IsCA,
		IsCA:                  *c.IsCA,
	}

	for _, san := range c.SubjectAltName {
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
				return fmt.Errorf("Invalid IP address: %s", strings.TrimPrefix(san, "IP:"))
			}
			template.IPAddresses = append(template.IPAddresses, ip)
		default:
			return fmt.Errorf("Unknown san, forgot prefix? (must be one of DNS:|URI:|IP:): %s", san)
		}
	}

	var issuerCert *x509.Certificate
	var issuerKey crypto.Signer
	if ca != nil {
		issuerCert, err = x509.ParseCertificate(ca.Cert)
		issuerKey = ca.Key
	} else {
		// create self-signed certificate
		issuerCert = template
		issuerKey = c.Key
	}

	c.Cert, err = x509.CreateCertificate(rand.Reader, template, issuerCert, c.Key.Public(), issuerKey)

	// Mark the state as valid
	c.Generated = true

	return err
}

// Save writes the certificate and key into PEM files
func (c *Certificate) Save(dstdir string) error {
	certFilename := path.Join(dstdir, c.Filename+".pem")
	keyFilename := path.Join(dstdir, c.Filename+"-key.pem")
	fmt.Printf("Writing: %s %s\n", certFilename, keyFilename)

	cf, err := os.Create(certFilename)
	if err != nil {
		return err
	}
	defer cf.Close()

	pem.Encode(cf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Cert,
	})

	kf, err := os.Create(keyFilename)
	if err != nil {
		return err
	}
	defer kf.Close()

	bytes, err := x509.MarshalPKCS8PrivateKey(c.Key)
	if err != nil {
		return err
	}

	pem.Encode(kf, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: bytes,
	})

	return nil
}

// Load reads the certificate and key from PEM files
func (c *Certificate) Load(srcdir string) error {
	err := c.defaults()
	if err != nil {
		return err
	}

	certFilename := path.Join(srcdir, c.Filename+".pem")
	keyFilename := path.Join(srcdir, c.Filename+"-key.pem")

	buf, err := ioutil.ReadFile(certFilename)
	if err != nil {
		return err
	}
	decoded, _ := pem.Decode(buf)
	if decoded == nil || decoded.Type != "CERTIFICATE" {
		return fmt.Errorf("Error while decoding %s", certFilename)
	}
	c.Cert = decoded.Bytes

	buf, err = ioutil.ReadFile(keyFilename)
	if err != nil {
		return err
	}
	decoded, _ = pem.Decode(buf)
	if decoded == nil {
		return fmt.Errorf("Error while decoding %s", keyFilename)
	}

	var key interface{}
	if decoded.Type == "PRIVATE KEY" {
		key, err = x509.ParsePKCS8PrivateKey(decoded.Bytes)
	} else if decoded.Type == "RSA PRIVATE KEY" {
		key, err = x509.ParsePKCS1PrivateKey(decoded.Bytes)
	} else {
		return fmt.Errorf("Error while decoding %s", keyFilename)
	}

	if err != nil {
		return err
	}
	c.Key = key.(crypto.Signer)

	// Mark the state as valid
	c.Generated = true

	return nil
}

// Hash calculates the hash over the structure attributes
func (c *Certificate) Hash() string {
	return fmt.Sprintf("%x", structhash.Sha1(c, 1))
}

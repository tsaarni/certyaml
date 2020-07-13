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
	KeySize        int      `yaml:"key_size"`
	Expires        string
	KeyUsage       []string `yaml:"key_usages"`
	Issuer         string
	Filename       string     `yaml:"filename"`
	IsCA           *bool      `yaml:"ca"`
	NotBefore      *time.Time `yaml:"not_before"`
	NotAfter       *time.Time `yaml:"not_after"`

	// generated at runtime, not read from yaml
	rsaKey *rsa.PrivateKey `yaml:"-"`
	cert   []byte          `yaml:"-"`
}

// getKeyUsage converts key usage string representation to x509.KeyUsage
func getKeyUsage(keyUsage []string) (x509.KeyUsage, error) {
	var result x509.KeyUsage

	for _, usage := range keyUsage {
		switch usage {
		case "DigitalSignature":
			result |= x509.KeyUsageDigitalSignature
		case "ContentCommitment":
			result |= x509.KeyUsageContentCommitment
		case "KeyEncipherment":
			result |= x509.KeyUsageKeyEncipherment
		case "DataEncipherment":
			result |= x509.KeyUsageDataEncipherment
		case "KeyAgreement":
			result |= x509.KeyUsageKeyAgreement
		case "CertSign":
			result |= x509.KeyUsageCertSign
		case "CRLSign":
			result |= x509.KeyUsageCRLSign
		case "EncipherOnly":
			result |= x509.KeyUsageEncipherOnly
		case "DecipherOnly":
			result |= x509.KeyUsageDecipherOnly
		default:
			return result, fmt.Errorf("Invalid key usage %s", keyUsage)
		}
	}
	return result, nil
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

	if c.KeySize == 0 {
		c.KeySize = 2048
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

	c.rsaKey, err = rsa.GenerateKey(rand.Reader, c.KeySize)
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
	var issuerKey interface{}
	if ca != nil {
		issuerCert, err = x509.ParseCertificate(ca.cert)
		issuerKey = ca.rsaKey
	} else {
		issuerCert = template
		issuerKey = c.rsaKey
	}

	c.cert, err = x509.CreateCertificate(rand.Reader, template, issuerCert, &c.rsaKey.PublicKey, issuerKey)

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
		Bytes: c.cert,
	})

	kf, err := os.Create(keyFilename)
	if err != nil {
		return err
	}
	defer kf.Close()

	pem.Encode(kf, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(c.rsaKey),
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
	c.cert = decoded.Bytes

	buf, err = ioutil.ReadFile(keyFilename)
	if err != nil {
		return err
	}
	decoded, _ = pem.Decode(buf)
	if decoded == nil || decoded.Type != "RSA PRIVATE KEY" {
		return fmt.Errorf("Error while decoding %s", keyFilename)
	}
	c.rsaKey, err = x509.ParsePKCS1PrivateKey(decoded.Bytes)
	if err != nil {
		return err
	}

	return nil
}

// Hash calculates the hash over the structure attributes
func (c *Certificate) Hash() string {
	return fmt.Sprintf("%x", structhash.Sha1(c, 1))
}

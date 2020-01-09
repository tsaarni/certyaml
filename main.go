package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Certificate ...
type Certificate struct {
	CommonName     string   `yaml:"cn"`
	SubjectAltName []string `yaml:"sans"`
	KeySize        int      `yaml:"key_size"`
	Expiry         string
	KeyUsage       []string `yaml:"key_usages"`
	Issuer         string
	FileName       string `yaml:"filename"`
	IsCA           *bool  `yaml:"ca"`

	// generated at runtime
	RSAKey *rsa.PrivateKey
	Cert   []byte
}

var allCerts = make(map[string]Certificate)

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

func (c *Certificate) defaults() error {
	if c.CommonName == "" {
		return errors.New("Mandatory field cn: missing")
	}
	if c.KeySize == 0 {
		c.KeySize = 2048
	}
	if c.Expiry == "" {
		c.Expiry = "8760h" // year
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
	if c.FileName == "" {
		c.FileName = c.CommonName
	}
	return nil
}

// Generate ...
func (c *Certificate) Generate(destination string) error {
	err := c.defaults()
	if err != nil {
		return err
	}

	keyUsage, err := getKeyUsage(c.KeyUsage)
	if err != nil {
		return err
	}

	c.RSAKey, err = rsa.GenerateKey(rand.Reader, c.KeySize)
	if err != nil {
		return err
	}

	notBefore := time.Now()
	expiry, err := time.ParseDuration(c.Expiry)
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(int64(notBefore.Nanosecond())),
		Subject: pkix.Name{
			CommonName: c.CommonName,
		},
		NotBefore:             notBefore.UTC(),
		NotAfter:              notBefore.UTC().Add(expiry),
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
				return err
			}
			template.IPAddresses = append(template.IPAddresses, ip)
		default:
			return fmt.Errorf("Unknown san, forgot prefix? (must be one of DNS:|URI:|IP:): %s", san)
		}
	}

	var issuerCert *x509.Certificate
	var issuerKey interface{}
	if c.Issuer == "" {
		issuerCert = template
		issuerKey = c.RSAKey
	} else {
		ca, ok := allCerts[c.Issuer]
		if !ok {
			return fmt.Errorf("Issuer field defined but CA certificate `%s` not found", c.Issuer)
		}
		issuerCert, err = x509.ParseCertificate(ca.Cert)
		issuerKey = ca.RSAKey
	}

	c.Cert, err = x509.CreateCertificate(rand.Reader, template, issuerCert, &c.RSAKey.PublicKey, issuerKey)

	err = c.save(destination)
	if err != nil {
		return err
	}

	allCerts[c.FileName] = *c

	return nil
}

func (c *Certificate) save(destinaton string) error {
	certFileName := path.Join(destinaton, c.FileName+".pem")
	keyFileName := path.Join(destinaton, c.FileName+"-key.pem")
	fmt.Printf("Writing: %s, %s\n", certFileName, keyFileName)

	cf, err := os.Create(certFileName)
	if err != nil {
		return err
	}
	defer cf.Close()

	pem.Encode(cf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Cert,
	})

	kf, err := os.Create(keyFileName)
	if err != nil {
		return err
	}
	defer kf.Close()

	pem.Encode(kf, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(c.RSAKey),
	})

	return nil
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [-d destination] [certs.yaml]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Creates certificates and keys according to manifest file in YAML format.\n")
		fmt.Fprintf(os.Stderr, "By default it reads `certs.yaml` as a manifest file and creates files\n")
		fmt.Fprintf(os.Stderr, "in current directory.\n\n")
		flag.PrintDefaults()
	}

	var destination string
	flag.StringVar(&destination, "d", "", "Short for --destination")
	flag.StringVar(&destination, "destination", "", "Destination directory where to create the certificates and keys")
	flag.Parse()

	manifest := "certs.yaml"
	if flag.Arg(0) != "" {
		manifest = flag.Arg(0)
	}

	f, err := os.Open(manifest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read certificate manifest: %s\n", err)
		os.Exit(1)
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	for {
		var c Certificate
		if err := dec.Decode(&c); err == io.EOF {
			break
		} else if err != nil {
			fmt.Fprintf(os.Stderr, "Error while decoding %s: %s\n", manifest, err)
			os.Exit(1)
		}

		err = c.Generate(destination)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while creating certificate: %s\n", err)
			os.Exit(1)
		}
	}
}

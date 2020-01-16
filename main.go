package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/cnf/structhash"
	"github.com/tsaarni/x500dn"
	"gopkg.in/yaml.v3"
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

// destination directory for writing the created files
var destination string

// state stores the hash of the Certificate structs, in order to not re-create them unless manifest changed.
// state is persistently stored in state.yaml between executions
var state = make(map[string]string)

// allCerts contains the generated certificates. The list is needed at runtime during signing the end-entity certificates
var allCerts = make(map[string]Certificate)

// getKeyUsage converts key usage string to x509.KeyUsage
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

// defaults sets the default values to Certificate
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

// Generate creates and saves a certificate and key, or optionally loads previously generated ones.
// It compares the Certificate struct content to previously stored state, in order to create new
// certificate and key only when needed.
func (c *Certificate) Generate() error {
	err := c.defaults()
	if err != nil {
		return err
	}

	// try to load previously generated certificate and key, which might not exist
	_ = c.load()

	// find out if manifest has been changed since certificate and key was created
	hash := c.hash()
	if state[c.Subject] == hash {
		allCerts[c.Subject] = *c
		fmt.Printf("No changes in manifest: skipping %s\n", c.Filename)
		return nil
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
		issuerKey = c.rsaKey
	} else {
		ca, ok := allCerts[c.Issuer]
		if !ok {
			return fmt.Errorf("Issuer field defined but CA certificate `%s` not found", c.Issuer)
		}
		issuerCert, err = x509.ParseCertificate(ca.cert)
		issuerKey = ca.rsaKey
	}

	c.cert, err = x509.CreateCertificate(rand.Reader, template, issuerCert, &c.rsaKey.PublicKey, issuerKey)

	err = c.save()
	if err != nil {
		return err
	}

	allCerts[c.Subject] = *c
	state[c.Subject] = c.hash()

	return nil
}

// save writes the certificate and key into PEM files
func (c *Certificate) save() error {
	certFilename := path.Join(destination, c.Filename+".pem")
	keyFilename := path.Join(destination, c.Filename+"-key.pem")
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

// load reads the certificate and key from PEM files
func (c *Certificate) load() error {
	certFilename := path.Join(destination, c.Filename+".pem")
	keyFilename := path.Join(destination, c.Filename+"-key.pem")

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

// hash calculates the hash over the structure attributes
func (c *Certificate) hash() string {
	return fmt.Sprintf("%x", structhash.Sha1(c, 1))
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [-d destination] [certs.yaml]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Creates certificates and keys according to manifest file in YAML format.\n")
		fmt.Fprintf(os.Stderr, "By default it reads `certs.yaml` as a manifest file and creates files\n")
		fmt.Fprintf(os.Stderr, "in current directory.\n\n")
		flag.PrintDefaults()
	}

	flag.StringVar(&destination, "d", "", "Short for --destination")
	flag.StringVar(&destination, "destination", "", "Destination directory where to create the certificates and keys")
	flag.Parse()

	manifestFilename := "certs.yaml"
	if flag.Arg(0) != "" {
		manifestFilename = flag.Arg(0)
	}
	stateFilename := strings.TrimSuffix(manifestFilename, filepath.Ext(manifestFilename))
	stateFilename = path.Join(destination, path.Base(stateFilename)+".state")

	fmt.Printf("Loading manifest: %s\n", manifestFilename)
	f, err := os.Open(manifestFilename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read certificate manifest: %s\n", err)
		os.Exit(1)
	}
	defer f.Close()

	// load previously stored state of created certificates and keys.
	// state is used to determine when files need to be re-created
	fmt.Printf("Reading state: %s\n", stateFilename)
	data, _ := ioutil.ReadFile(stateFilename)
	err = yaml.Unmarshal(data, &state)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while reading state.yaml: %s", err)
		os.Exit(1)
	}

	// create certificates and keys
	dec := yaml.NewDecoder(f)
	for {
		var c Certificate
		if err := dec.Decode(&c); err == io.EOF {
			break
		} else if err != nil {
			fmt.Fprintf(os.Stderr, "Error while decoding %s: %s\n", manifestFilename, err)
			os.Exit(1)
		}

		err = c.Generate()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while creating certificate: %s\n", err)
			os.Exit(1)
		}
	}

	// store state back to disk
	fmt.Printf("Writing state: %s\n", stateFilename)
	stateYaml, err := yaml.Marshal(state)
	err = ioutil.WriteFile(stateFilename, stateYaml, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while writing state: %s\n", err)
		os.Exit(1)

	}
}

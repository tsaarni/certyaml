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
	"io/ioutil"
	"math/big"
	"net"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/cnf/structhash"
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
	FileName       string     `yaml:"filename"`
	IsCA           *bool      `yaml:"ca"`
	NotBefore      *time.Time `yaml:"not_before"`
	NotAfter       *time.Time `yaml:"not_after"`

	// generated at runtime, not from yaml
	rsaKey *rsa.PrivateKey `yaml:"-"`
	cert   []byte          `yaml:"-"`
}

// destination directory for writing out files
var destination string

// state stores the hash of the Certificate structs, in order to skip re-generating unless manifest changes.
// it is persistently stored in state.yaml between executions
var state = make(map[string]string)

// allCerts contains the generated certificates, used when issuing
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
	if c.Expiry == "" && c.NotAfter == nil {
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
func (c *Certificate) Generate() error {
	err := c.defaults()
	if err != nil {
		return err
	}

	// try to load previously generated certificate and key, which might not exist
	_ = c.load()

	// find out if manifest has been changed since certificate and key was created
	hash := c.hash()
	if state[c.FileName] == hash {
		allCerts[c.FileName] = *c
		fmt.Printf("No changes in manifest: skipping %s\n", c.FileName)
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
	if c.NotBefore == nil {
		notBefore = time.Now()
	} else {
		notBefore = *c.NotBefore
	}

	if c.NotAfter == nil {
		expiry, err := time.ParseDuration(c.Expiry)
		if err != nil {
			return err
		}
		notAfter = notBefore.UTC().Add(expiry)
	} else {
		notAfter = *c.NotAfter
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: c.CommonName,
		},
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

	allCerts[c.FileName] = *c
	state[c.FileName] = c.hash()

	return nil
}

func (c *Certificate) save() error {
	certFileName := path.Join(destination, c.FileName+".pem")
	keyFileName := path.Join(destination, c.FileName+"-key.pem")
	fmt.Printf("Writing: %s, %s\n", certFileName, keyFileName)

	cf, err := os.Create(certFileName)
	if err != nil {
		return err
	}
	defer cf.Close()

	pem.Encode(cf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.cert,
	})

	kf, err := os.Create(keyFileName)
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

func (c *Certificate) load() error {
	certFileName := path.Join(destination, c.FileName+".pem")
	keyFileName := path.Join(destination, c.FileName+"-key.pem")

	buf, err := ioutil.ReadFile(certFileName)
	if err != nil {
		return err
	}
	decoded, _ := pem.Decode(buf)
	if decoded == nil || decoded.Type != "CERTIFICATE" {
		return fmt.Errorf("Error while decoding %s", certFileName)
	}
	c.cert = decoded.Bytes

	buf, err = ioutil.ReadFile(keyFileName)
	if err != nil {
		return err
	}
	decoded, _ = pem.Decode(buf)
	if decoded == nil || decoded.Type != "RSA PRIVATE KEY" {
		return fmt.Errorf("Error while decoding %s", keyFileName)
	}
	c.rsaKey, err = x509.ParsePKCS1PrivateKey(decoded.Bytes)
	if err != nil {
		return err
	}

	return nil
}

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

	data, _ := ioutil.ReadFile(path.Join(destination, "state.yaml"))
	err = yaml.Unmarshal(data, &state)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while reading state.yaml: %s", err)
		os.Exit(1)
	}

	dec := yaml.NewDecoder(f)
	for {
		var c Certificate
		if err := dec.Decode(&c); err == io.EOF {
			break
		} else if err != nil {
			fmt.Fprintf(os.Stderr, "Error while decoding %s: %s\n", manifest, err)
			os.Exit(1)
		}

		err = c.Generate()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while creating certificate: %s\n", err)
			os.Exit(1)
		}
	}

	stateYaml, err := yaml.Marshal(state)
	err = ioutil.WriteFile(path.Join(destination, "state.yaml"), stateYaml, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while writing state: %s\n", err)
		os.Exit(1)

	}
}

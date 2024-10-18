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

package manifest

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/cnf/structhash"
	api "github.com/tsaarni/certyaml"
	"github.com/tsaarni/x500dn"
	"sigs.k8s.io/yaml"
)

type Manifest struct {
	// certs is a map from subject name to CertificateManifest.
	certs map[string]*CertificateManifest

	// hashes is a map from file name (typically subject name) to hash of CertificateManifest struct.
	// It is stored and read from certyaml's .state file between consequent executions of certyaml.
	hashes map[string]string

	// dataDir is the path where certificates, private keys and .state file are stored.
	dataDir string
}

// CertificateManifest is used to unmarshal the certificate YAML document.
type CertificateManifest struct {
	api.Certificate

	KeyTypeAsString      string   `json:"key_type"`
	KeyUsagesAsString    []string `json:"key_usages"`
	ExtKeyUsagesAsString []string `json:"ext_key_usages"`
	ExpiresAsString      string   `json:"expires"`
	IssuerAsString       string   `json:"issuer"`
	Filename             string   `json:"filename"`
	SerialNumberAsInt    *int64   `json:"serial"`
	Revoked              bool     `json:"revoked"`
}

func (c *CertificateManifest) hash() string {
	return fmt.Sprintf("%x", structhash.Sha1(c, 1))
}

// GenerateCertificates generates certificates and private keys and stores them into directory pointed by the destination parameter.
func GenerateCertificates(output io.Writer, manifestFile, stateFile, destDir string) error {
	m := &Manifest{
		dataDir: destDir,
		certs:   make(map[string]*CertificateManifest),
		hashes:  make(map[string]string),
	}

	fmt.Fprintf(output, "Loading manifest file: %s\n", manifestFile)
	f, err := os.Open(filepath.Clean(manifestFile))
	if err != nil {
		return fmt.Errorf("cannot read certificate manifest file: %s", err)
	}
	defer f.Close() // #nosec G307

	// Load stored state (if any) about previously created certificates and private keys.
	// The state file is used to determine when certificates need to be re-created.
	fmt.Fprintf(output, "Reading certificate state file: %s\n", stateFile)
	data, _ := os.ReadFile(filepath.Clean(stateFile))
	err = yaml.Unmarshal(data, &m.hashes)
	if err != nil {
		return fmt.Errorf("error while parsing certificate state file: %s", err)
	}

	// Map of CLRs, indexed by issuing CAs subject name.
	revocationLists := map[string]*api.CRL{}

	// Parse multi-document YAML file
	scanner := bufio.NewScanner(f)
	scanner.Split(splitByDocument)
	for scanner.Scan() {
		c := CertificateManifest{}
		err := yaml.UnmarshalStrict(scanner.Bytes(), &c)
		if err != nil {
			return fmt.Errorf("error while decoding: %s", err)
		}

		err = m.processCertificate(&c)
		if err != nil {
			return err
		}

		// Compare hash from state file to hash of the loaded certificate.
		hash, ok := m.hashes[c.Filename]
		if ok && c.GeneratedCert != nil && hash == c.hash() {
			fmt.Fprintf(output, "No changes: skipping %s\n", c.Filename)
			continue // Continue to next certificate in manifest.
		}

		// If certificate was read successfully but it did not exist in state file:
		// "adopt" the existing certificate like we would have generated it.
		if !ok && c.GeneratedCert != nil {
			fmt.Fprintf(output, "Recognized existing certificate: skipping %s\n", c.Filename)
			m.hashes[c.Filename] = c.hash()
			continue // Continue to next certificate in manifest.
		}

		// Store hash of the current state of the certificate.
		m.hashes[c.Filename] = c.hash()

		// Write the certificate and key to data dir.
		certFile := path.Join(m.dataDir, c.Filename+".pem")
		keyFile := path.Join(m.dataDir, c.Filename+"-key.pem")
		fmt.Fprintf(output, "Writing: %s %s\n", certFile, keyFile)
		err = c.WritePEM(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("error while saving certificate: %s", err)
		}
		m.certs[c.Subject] = &c

		// If revoked, add to existing revocation list or create new one.
		if c.Revoked {
			issuer := c.Issuer
			if issuer == nil {
				return fmt.Errorf("cannot revoke self-signed certificate: %s", c.Subject)
			}
			// Does revocation list already exist for this CA?
			crl, ok := revocationLists[issuer.Subject]
			// If not, create new CRL.
			if !ok {
				crl = &api.CRL{}
			}
			err := crl.Add(&c.Certificate)
			if err != nil {
				return err
			}
			revocationLists[issuer.Subject] = crl
		}
	}

	// Write CRLs to PEM files.
	for _, crl := range revocationLists {
		issuer := m.certs[crl.Revoked[0].Issuer.Subject]
		crlFile := path.Join(m.dataDir, issuer.Filename+"-crl.pem")
		fmt.Fprintf(output, "Writing CRL: %s\n", crlFile)
		err := crl.WritePEM(crlFile)
		if err != nil {
			return err
		}
	}

	// Write hashes to state file.
	stateYaml, err := yaml.Marshal(m.hashes)
	if err != nil {
		return err
	}
	fmt.Fprintf(output, "Writing state: %s\n", stateFile)
	err = os.WriteFile(stateFile, stateYaml, 0600)
	if err != nil {
		return fmt.Errorf("error while writing state: %s", err)
	}

	return nil
}

// processCertificate generates attributes for certificate, which cannot be directly parsed by JSON/YAML parser.
func (m *Manifest) processCertificate(c *CertificateManifest) error {
	// Ensure that mandatory fields are set.
	if c.Subject == "" && c.Filename == "" {
		return errors.New("either subject or filename field must be defined")
	}

	// If filename was not given, set it according to common name.
	if c.Filename == "" {
		name, err := x500dn.ParseDN(c.Subject)
		if err != nil {
			return err
		}
		c.Filename = name.CommonName
	}

	// If expires time was given, parse it and set parsed value to Expires field.
	if c.ExpiresAsString != "" {
		expires, err := time.ParseDuration(c.ExpiresAsString)
		if err != nil {
			return err
		}
		c.Expires = &expires
	}

	// If issuer was given, check if it is known. If yes, set the Issuer reference.
	if c.IssuerAsString != "" {
		ca, ok := m.certs[c.IssuerAsString]
		if !ok {
			return fmt.Errorf("issuer field defined but CA certificate `%s` not found", c.IssuerAsString)
		}
		c.Issuer = &ca.Certificate
	}

	if c.KeyTypeAsString != "" {
		switch c.KeyTypeAsString {
		case "EC":
			c.KeyType = api.KeyTypeEC
		case "RSA":
			c.KeyType = api.KeyTypeRSA
		case "ED25519":
			c.KeyType = api.KeyTypeEd25519
		default:
			return fmt.Errorf("key_type contains invalid value: %s", c.KeyTypeAsString)
		}
	}

	if len(c.KeyUsagesAsString) > 0 {
		usage, err := getKeyUsage(c.KeyUsagesAsString)
		if err != nil {
			return err
		}
		c.KeyUsage = usage
	}

	if len(c.ExtKeyUsagesAsString) > 0 {
		usage, err := getExtKeyUsage(c.ExtKeyUsagesAsString)
		if err != nil {
			return err
		}
		c.ExtKeyUsage = usage
	}

	if c.SerialNumberAsInt != nil {
		c.SerialNumber = big.NewInt(*c.SerialNumberAsInt)
	}

	// Try to load previously generated certificate and key, which might not exists, so ignore errors.
	certOnDisk, err := tls.LoadX509KeyPair(path.Join(m.dataDir, c.Filename+".pem"), path.Join(m.dataDir, c.Filename+"-key.pem"))
	if err == nil {
		// Existing certificate and key was found on disk, set reference.
		c.GeneratedCert = &certOnDisk
		m.certs[c.Subject] = c
	}

	return nil
}

// splitByDocument is a splitter function for bufio.Scanner for multi-document YAML files.
func splitByDocument(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.Index(data, []byte("\n---")); i >= 0 {
		return i + len("\n---") + 1, data[0:i], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
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
			return result, fmt.Errorf("key_usages contains invalid value: %s", usage)
		}
		result |= ku
	}

	return result, nil
}

// getExtKeyUsage converts extended key usage string representation to X509.ExtKeyUsage
func getExtKeyUsage(extKeyUsage []string) ([]x509.ExtKeyUsage, error) {
	var result []x509.ExtKeyUsage
	var usages = map[string]x509.ExtKeyUsage{
		"Any":                            x509.ExtKeyUsageAny,
		"ServerAuth":                     x509.ExtKeyUsageServerAuth,
		"ClientAuth":                     x509.ExtKeyUsageClientAuth,
		"CodeSigning":                    x509.ExtKeyUsageCodeSigning,
		"EmailProtection":                x509.ExtKeyUsageEmailProtection,
		"IPSECEndSystem":                 x509.ExtKeyUsageIPSECEndSystem,
		"IPSECTunnel":                    x509.ExtKeyUsageIPSECTunnel,
		"IPSECUser":                      x509.ExtKeyUsageIPSECUser,
		"TimeStamping":                   x509.ExtKeyUsageTimeStamping,
		"OCSPSigning":                    x509.ExtKeyUsageOCSPSigning,
		"MicrosoftServerGatedCrypto":     x509.ExtKeyUsageMicrosoftServerGatedCrypto,
		"NetscapeServerGatedCrypto":      x509.ExtKeyUsageNetscapeServerGatedCrypto,
		"MicrosoftCommercialCodeSigning": x509.ExtKeyUsageMicrosoftCommercialCodeSigning,
		"MicrosoftKernelCodeSigning":     x509.ExtKeyUsageMicrosoftKernelCodeSigning,
	}

	for _, usage := range extKeyUsage {
		ku, ok := usages[usage]
		if !ok {
			return nil, fmt.Errorf("ext_key_usages contains invalid value: %s", usage)
		}
		result = append(result, ku)
	}

	return result, nil
}

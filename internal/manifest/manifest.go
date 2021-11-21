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
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"time"

	"github.com/cnf/structhash"
	api "github.com/tsaarni/certyaml"
	"github.com/tsaarni/x500dn"
	"sigs.k8s.io/yaml"
)

type Manifest struct {
	// certs is a map from subject name to CertificateManifest.
	certs map[string]*CertificateManifest

	// hashes is a map from subject name to hash of CertificateManifest struct.
	// It is stored and read from certyaml's .state file between consequent executions of certyaml.
	hashes map[string]string

	// dataDir is the path where certificates, private keys and .state file are stored.
	dataDir string
}

// CertificateManifest is used to unmarshal the certificate YAML document.
type CertificateManifest struct {
	api.Certificate

	ExpiresAsString string `json:"expires"`
	IssuerAsString  string `json:"issuer"`
	Filename        string `json:"filename"`
}

func (c *CertificateManifest) hash() string {
	return fmt.Sprintf("%x", structhash.Sha1(c, 1))
}

// GenerateCertificates generates certificates and private keys and stores them into directory pointed by the destination parameter
func GenerateCertificates(manifestFile, stateFile, destDir string) error {
	m := &Manifest{
		dataDir: destDir,
		certs:   make(map[string]*CertificateManifest),
		hashes:  make(map[string]string),
	}

	fmt.Printf("Loading manifest file: %s\n", manifestFile)
	f, err := os.Open(manifestFile)
	if err != nil {
		return fmt.Errorf("cannot read certificate manifest file: %s", err)
	}
	defer f.Close()

	// Load stored state (if any) about previously created certificates and private keys.
	// The state file is used to determine when certificates need to be re-created.
	fmt.Printf("Reading certificate state file: %s\n", stateFile)
	data, _ := ioutil.ReadFile(stateFile)
	err = yaml.Unmarshal(data, &m.hashes)
	if err != nil {
		return fmt.Errorf("error while parsing certificate state file: %s", err)
	}

	// Parse multi-document YAML file
	scanner := bufio.NewScanner(f)
	scanner.Split(splitByDocument)
	for scanner.Scan() {
		c := CertificateManifest{}
		err := yaml.Unmarshal(scanner.Bytes(), &c)
		if err != nil {
			return fmt.Errorf("error while decoding: %s", err)
		}

		err = m.processCertificate(&c)
		if err != nil {
			return err
		}

		// Compare hash from state file to hash of the loaded certificate.
		hash, ok := m.hashes[c.Subject]
		if ok && c.GeneratedCert != nil && hash == c.hash() {
			fmt.Printf("No changes: skipping %s\n", c.Filename)
			continue // Continue to next certificate in manifest.
		}

		// If certificate was read successfully but it did not exist in state file:
		// "adopt" the existing certificate like we would have generated it.
		if !ok && c.GeneratedCert != nil {
			fmt.Printf("Recognized existing certificate: skipping %s\n", c.Filename)
			m.hashes[c.Subject] = c.hash()
			continue // Continue to next certificate in manifest.
		}

		// Store hash of the current state of the certificate.
		m.hashes[c.Subject] = c.hash()

		// Write the certificate and key to data dir.
		certFile := path.Join(m.dataDir, c.Filename+".pem")
		keyFile := path.Join(m.dataDir, c.Filename+"-key.pem")
		fmt.Printf("Writing: %s %s\n", certFile, keyFile)
		err = c.WritePEM(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("error while saving certificate: %s", err)
		}
		m.certs[c.Subject] = &c
	}

	// Write hashes to state file.
	stateYaml, err := yaml.Marshal(m.hashes)
	if err != nil {
		return err
	}
	fmt.Printf("Writing state: %s\n", stateFile)
	err = ioutil.WriteFile(stateFile, stateYaml, 0644)
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

	// Try to load previously generated certificate and key, which might not exists, so ignore errors.
	certOnDisk, err := tls.LoadX509KeyPair(path.Join(m.dataDir, c.Filename+".pem"), path.Join(m.dataDir, c.Filename+"-key.pem"))
	if err == nil {
		// Existing certificate and key was found on disk, set reference.
		c.GeneratedCert = &certOnDisk
		m.certs[c.Subject] = c
	}

	return nil
}

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

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
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v3"
)

// allCerts contains the generated certificates.
// When end-entity certificate is issued, we need to get access to previously
// generated CA certificate to sign the end-entity certificate.
// allCerts allows getting access to CA certificates.
var allCerts = make(map[string]*Certificate)

// GenerateCertficatesFromManifest generates certificates and private keys and stores them into directory pointed by the destination parameter
func GenerateCertficatesFromManifest(manifestFilename, stateFilename, destination string) error {
	f, err := os.Open(manifestFilename)
	if err != nil {
		return fmt.Errorf("Cannot read certificate manifest file: %s", err)
	}
	defer f.Close()

	decoder := yaml.NewDecoder(f)

	// state is a map from subject name to the hash over the Certificate struct
	var state = make(map[string]string)

	// load stored state (if any) about previously created certificates and keys
	// this is used to determine when files need to be re-created
	fmt.Printf("Reading certificate state file: %s\n", stateFilename)
	data, _ := ioutil.ReadFile(stateFilename)
	err = yaml.Unmarshal(data, &state)
	if err != nil {
		return fmt.Errorf("Error while parsing certificate state file: %s", err)
	}

	// loop over all certificate documents in the manifest file
	for {
		var c Certificate
		if err := decoder.Decode(&c); err == io.EOF {
			break // we reached last document in multi-document YAML file
		} else if err != nil {
			return fmt.Errorf("Error while decoding: %s", err)
		}

		// try to load previously generated certificate and key, which might not exist, so we ignore the error
		_ = c.Load(destination)

		// store certificate to allow its use later for signing
		allCerts[c.Subject] = &c

		// compare hash from state file to has of loaded certificate
		if state[c.Subject] == c.Hash() {
			fmt.Printf("No changes: skipping %s\n", c.Filename)
			continue // continue to next certificate in manifest
		}

		ca, ok := allCerts[c.Issuer]
		if c.Issuer != "" && !ok {
			return fmt.Errorf("Issuer field defined but CA certificate `%s` not found", c.Issuer)
		}
		err = c.Generate(ca)
		if err != nil {
			return fmt.Errorf("Error while creating certificate: %s", err)
		}

		// store hash of generated certificate
		state[c.Subject] = c.Hash()

		err = c.Save(destination)
		if err != nil {
			return fmt.Errorf("Error while saving certificate: %s", err)
		}
	}

	// write state file
	stateYaml, err := yaml.Marshal(state)
	err = ioutil.WriteFile(stateFilename, stateYaml, 0644)
	if err != nil {
		return fmt.Errorf("Error while writing state: %s", err)
	}

	return nil
}

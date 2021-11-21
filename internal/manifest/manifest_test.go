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
	"io/ioutil"
	"os"
	"path"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/mod/sumdb/dirhash"
)

func TestManifestHandling(t *testing.T) {
	dir, err := ioutil.TempDir("", "certyaml-testsuite-*")
	assert.Nil(t, err)
	defer os.RemoveAll(dir)

	err = GenerateCertificates("testdata/certs-state-1.yaml", path.Join(dir, "state.yaml"), dir)
	assert.Nil(t, err)

	wantFiles := []string{
		"client-root-ca-key.pem",
		"client-root-ca.pem",
		"clientcert-key.pem",
		"clientcert.pem",
		"fixedtime-key.pem",
		"fixedtime.pem",
		"intermediate-ca-key.pem",
		"intermediate-ca.pem",
		"myserver-key.pem",
		"myserver.pem",
		"selfsigned-server-key.pem",
		"selfsigned-server.pem",
		"server-root-ca-key.pem",
		"server-root-ca.pem",
		"shortlived-key.pem",
		"shortlived.pem",
		"state.yaml",
	}

	// Check that files got generated.
	fileInfos, err := ioutil.ReadDir(dir)
	assert.Nil(t, err)
	var gotFiles []string
	for _, file := range fileInfos {
		gotFiles = append(gotFiles, file.Name())
	}
	sort.Strings(gotFiles)
	assert.Equal(t, wantFiles, gotFiles)
}

func TestStateHandling(t *testing.T) {
	dir, err := ioutil.TempDir("", "certyaml-testsuite-*")
	assert.Nil(t, err)
	defer os.RemoveAll(dir)

	err = GenerateCertificates("testdata/certs-state-1.yaml", path.Join(dir, "state.yaml"), dir)
	assert.Nil(t, err)

	// Check that calling generate again does not alter the state.
	h1, err := dirhash.HashDir(dir, "", dirhash.Hash1)
	assert.Nil(t, err)
	err = GenerateCertificates("testdata/certs-state-1.yaml", path.Join(dir, "state.yaml"), dir)
	assert.Nil(t, err)

	h2, err := dirhash.HashDir(dir, "", dirhash.Hash1)
	assert.Nil(t, err)
	assert.Equal(t, h1, h2)

	// Check that files are re-generated if some are missing.
	os.Remove(path.Join(dir, "intermediate-ca-key.pem"))
	os.Remove(path.Join(dir, "intermediate-ca.pem"))
	err = GenerateCertificates("testdata/certs-state-1.yaml", path.Join(dir, "state.yaml"), dir)
	assert.Nil(t, err)

	h3, err := dirhash.HashDir(dir, "", dirhash.Hash1)
	assert.Nil(t, err)
	assert.NotEqual(t, h2, h3)

	// Check that files are re-generated if manifest changes.
	err = GenerateCertificates("testdata/certs-state-2.yaml", path.Join(dir, "state.yaml"), dir)
	assert.Nil(t, err)

	h4, err := dirhash.HashDir(dir, "", dirhash.Hash1)
	assert.Nil(t, err)
	assert.NotEqual(t, h3, h4)
}

func TestInvalidIssuer(t *testing.T) {
	dir, err := ioutil.TempDir("", "certyaml-testsuite-*")
	assert.Nil(t, err)
	defer os.RemoveAll(dir)
	err = GenerateCertificates("testdata/certs-invalid-issuer.yaml", path.Join(dir, "state.yaml"), dir)
	assert.NotNil(t, err)
}

func TestInvalidManifest(t *testing.T) {
	err := GenerateCertificates("testdata/non-existing-manifest.yaml", "", "")
	assert.NotNil(t, err)
}

func TestInvalidDestinationDir(t *testing.T) {
	dir, err := ioutil.TempDir("", "certyaml-testsuite-*")
	assert.Nil(t, err)
	defer os.RemoveAll(dir)
	err = GenerateCertificates("testdata/certs-state-1.yaml", path.Join(dir, "state.yaml"), "non-existing-dir")
	assert.NotNil(t, err)
}

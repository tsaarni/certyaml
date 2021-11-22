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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"path"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/mod/sumdb/dirhash"
)

func TestManifestHandling(t *testing.T) {
	dir, err := ioutil.TempDir("", "certyaml-testsuite-*")
	assert.Nil(t, err)
	defer os.RemoveAll(dir)

	var output bytes.Buffer
	err = GenerateCertificates(&output, "testdata/certs-state-1.yaml", path.Join(dir, "state.yaml"), dir)
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

	var output bytes.Buffer
	err = GenerateCertificates(&output, "testdata/certs-state-1.yaml", path.Join(dir, "state.yaml"), dir)
	assert.Nil(t, err)

	// Check that calling generate again does not alter the state.
	h1, err := dirhash.HashDir(dir, "", dirhash.Hash1)
	assert.Nil(t, err)
	err = GenerateCertificates(&output, "testdata/certs-state-1.yaml", path.Join(dir, "state.yaml"), dir)
	assert.Nil(t, err)

	h2, err := dirhash.HashDir(dir, "", dirhash.Hash1)
	assert.Nil(t, err)
	assert.Equal(t, h1, h2)

	// Check that files are re-generated if some are missing.
	os.Remove(path.Join(dir, "intermediate-ca-key.pem"))
	os.Remove(path.Join(dir, "intermediate-ca.pem"))
	err = GenerateCertificates(&output, "testdata/certs-state-1.yaml", path.Join(dir, "state.yaml"), dir)
	assert.Nil(t, err)

	h3, err := dirhash.HashDir(dir, "", dirhash.Hash1)
	assert.Nil(t, err)
	assert.NotEqual(t, h2, h3)

	// Check that files are re-generated if manifest changes.
	err = GenerateCertificates(&output, "testdata/certs-state-2.yaml", path.Join(dir, "state.yaml"), dir)
	assert.Nil(t, err)

	h4, err := dirhash.HashDir(dir, "", dirhash.Hash1)
	assert.Nil(t, err)
	assert.NotEqual(t, h3, h4)
}

func TestInvalidIssuer(t *testing.T) {
	dir, err := ioutil.TempDir("", "certyaml-testsuite-*")
	assert.Nil(t, err)
	defer os.RemoveAll(dir)
	var output bytes.Buffer
	err = GenerateCertificates(&output, "testdata/certs-invalid-issuer.yaml", path.Join(dir, "state.yaml"), dir)
	assert.NotNil(t, err)
}

func TestInvalidManifest(t *testing.T) {
	var output bytes.Buffer
	err := GenerateCertificates(&output, "testdata/non-existing-manifest.yaml", "", "")
	assert.NotNil(t, err)
}

func TestInvalidDestinationDir(t *testing.T) {
	dir, err := ioutil.TempDir("", "certyaml-testsuite-*")
	assert.Nil(t, err)
	defer os.RemoveAll(dir)
	var output bytes.Buffer
	err = GenerateCertificates(&output, "testdata/certs-state-1.yaml", path.Join(dir, "state.yaml"), "non-existing-dir")
	assert.NotNil(t, err)
}

func TestParsingAllCertificateFields(t *testing.T) {
	dir, err := ioutil.TempDir("", "certyaml-testsuite-*")
	assert.Nil(t, err)
	defer os.RemoveAll(dir)

	var output bytes.Buffer
	err = GenerateCertificates(&output, "testdata/certs-test-all-fields.yaml", path.Join(dir, "state.yaml"), dir)
	assert.Nil(t, err)

	// Check fields from first end-entity cert.
	tlsCert, err := tls.LoadX509KeyPair(path.Join(dir, "rsa-cert.pem"), path.Join(dir, "rsa-cert-key.pem"))
	assert.Nil(t, err)
	got, err := x509.ParseCertificate(tlsCert.Certificate[0])
	assert.Nil(t, err)

	assert.Equal(t, "ca", got.Issuer.CommonName)
	assert.Equal(t, "rsa-cert", got.Subject.CommonName)

	expectedNotBefore, _ := time.Parse(time.RFC3339, "2020-01-01T09:00:00Z")
	expectedNotAfter, _ := time.Parse(time.RFC3339, "2030-01-01T09:00:00Z")
	assert.Equal(t, expectedNotBefore, got.NotBefore)
	assert.Equal(t, expectedNotAfter, got.NotAfter)

	expectedKeyUsage := x509.KeyUsageDigitalSignature |
		x509.KeyUsageContentCommitment |
		x509.KeyUsageKeyEncipherment |
		x509.KeyUsageDataEncipherment |
		x509.KeyUsageKeyAgreement |
		x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign |
		x509.KeyUsageEncipherOnly |
		x509.KeyUsageDecipherOnly
	assert.Equal(t, expectedKeyUsage, got.KeyUsage)

	assert.True(t, got.IsCA)

	assert.Equal(t, x509.RSA, got.PublicKeyAlgorithm)
	assert.Equal(t, 4096, got.PublicKey.(*rsa.PublicKey).Size()*8)

	expectedURL, _ := url.Parse("spiffe://myworkload")
	expectedIP := net.ParseIP("127.0.0.1")

	assert.Equal(t, []string{"www.example.com"}, got.DNSNames)
	assert.Equal(t, expectedURL, got.URIs[0])
	assert.True(t, got.IPAddresses[0].Equal(expectedIP))

	// Check fields from second end-entity cert.
	tlsCert, err = tls.LoadX509KeyPair(path.Join(dir, "ec-cert.pem"), path.Join(dir, "ec-cert-key.pem"))
	assert.Nil(t, err)
	got, err = x509.ParseCertificate(tlsCert.Certificate[0])
	assert.Nil(t, err)

	assert.Equal(t, "ec-cert", got.Issuer.CommonName)
	assert.Equal(t, "ec-cert", got.Subject.CommonName)

	expectedNotBefore, _ = time.Parse(time.RFC3339, "2020-01-01T09:00:00Z")
	expectedNotAfter, _ = time.Parse(time.RFC3339, "2020-01-01T10:00:00Z")
	assert.Equal(t, expectedNotBefore, got.NotBefore)
	assert.Equal(t, expectedNotAfter, got.NotAfter)

	assert.Equal(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, got.KeyUsage)

	assert.True(t, got.IsCA)

	assert.Equal(t, x509.ECDSA, got.PublicKeyAlgorithm)
	assert.Equal(t, elliptic.P256(), got.PublicKey.(*ecdsa.PublicKey).Curve)

	assert.Empty(t, got.DNSNames)
	assert.Empty(t, got.URIs)
	assert.Empty(t, got.IPAddresses)
}

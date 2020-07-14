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
	"crypto/x509"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSubjectName(t *testing.T) {
	input := Certificate{Subject: "CN=Joe"}
	err := input.Generate(nil)
	assert.Nil(t, err)
	got, err := x509.ParseCertificate(input.cert)
	assert.Nil(t, err)
	assert.Equal(t, "Joe", got.Subject.CommonName)
}

func TestSubjectAltName(t *testing.T) {
	input := Certificate{Subject: "CN=Joe", SubjectAltName: []string{"DNS:host.example.com", "URI:http://www.example.com", "IP:1.2.3.4"}}
	err := input.Generate(nil)
	assert.Nil(t, err)
	got, err := x509.ParseCertificate(input.cert)
	assert.Nil(t, err)
	assert.Equal(t, "Joe", got.Subject.CommonName)
	assert.Equal(t, "host.example.com", got.DNSNames[0])
	assert.Equal(t, url.URL{Scheme: "http", Host: "www.example.com"}, *got.URIs[0])
	assert.Equal(t, net.IP{1, 2, 3, 4}, got.IPAddresses[0])
}

func TestKeySize(t *testing.T) {
	got := Certificate{Subject: "CN=Joe", KeySize: 1024}
	err := got.Generate(nil)
	assert.Nil(t, err)
	assert.Equal(t, 1024, got.rsaKey.Size()*8)

	got = Certificate{Subject: "CN=Joe", KeySize: 2048}
	err = got.Generate(nil)
	assert.Nil(t, err)
	assert.Equal(t, 2048, got.rsaKey.Size()*8)

	got = Certificate{Subject: "CN=Joe", KeySize: 4096}
	err = got.Generate(nil)
	assert.Nil(t, err)
	assert.Equal(t, 4096, got.rsaKey.Size()*8)
}

func TestExpires(t *testing.T) {
	input := Certificate{Subject: "CN=Joe", Expires: "1h"}
	err := input.Generate(nil)
	assert.Nil(t, err)
	cert, err := x509.ParseCertificate(input.cert)
	assert.Nil(t, err)
	want, _ := time.ParseDuration("1h")
	got := cert.NotAfter.Sub(cert.NotBefore)
	assert.Equal(t, want, got)
}

func TestKeyUsage(t *testing.T) {
	input := Certificate{Subject: "CN=Joe", KeyUsage: []string{"DigitalSignature"}}
	err := input.Generate(nil)
	assert.Nil(t, err)
	got, err := x509.ParseCertificate(input.cert)
	assert.Nil(t, err)
	assert.Equal(t, x509.KeyUsageDigitalSignature, got.KeyUsage)

	input = Certificate{Subject: "CN=Joe", KeyUsage: []string{"DigitalSignature", "KeyEncipherment"}}
	err = input.Generate(nil)
	assert.Nil(t, err)
	got, err = x509.ParseCertificate(input.cert)
	assert.Nil(t, err)
	assert.Equal(t, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, got.KeyUsage)

	input = Certificate{Subject: "CN=Joe", KeyUsage: []string{"DigitalSignature", "ContentCommitment", "KeyEncipherment", "DataEncipherment", "KeyAgreement", "CertSign", "CRLSign", "EncipherOnly", "DecipherOnly"}}
	err = input.Generate(nil)
	assert.Nil(t, err)
	got, err = x509.ParseCertificate(input.cert)
	assert.Nil(t, err)
	assert.Equal(t, x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment|x509.KeyUsageKeyEncipherment|x509.KeyUsageDataEncipherment|x509.KeyUsageKeyAgreement|x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageEncipherOnly|x509.KeyUsageDecipherOnly, got.KeyUsage)
}

func TestIssuer(t *testing.T) {
	input1 := Certificate{Subject: "CN=Joe"}
	err := input1.Generate(nil)
	assert.Nil(t, err)
	got, err := x509.ParseCertificate(input1.cert)
	assert.Nil(t, err)
	assert.Equal(t, "Joe", got.Subject.CommonName)
	assert.Equal(t, "Joe", got.Issuer.CommonName)
	assert.Equal(t, true, got.IsCA)

	input2 := Certificate{Subject: "CN=EndEntity", Issuer: "CN:Joe"}
	err = input2.Generate(&input1)
	assert.Nil(t, err)
	got, err = x509.ParseCertificate(input2.cert)
	assert.Nil(t, err)
	assert.Equal(t, "EndEntity", got.Subject.CommonName)
	assert.Equal(t, "Joe", got.Issuer.CommonName)
	assert.Equal(t, false, got.IsCA)
}

func TestFilename(t *testing.T) {
	dir, err := ioutil.TempDir("", "certyaml-testsuite-*")
	assert.Nil(t, err)
	defer os.RemoveAll(dir)

	got := Certificate{Subject: "CN=Joe"}
	err = got.Generate(nil)
	assert.Nil(t, err)
	assert.Equal(t, "Joe", got.Filename)
	err = got.Save(dir)
	assert.Nil(t, err)
	input := Certificate{Subject: "CN=dummy", Filename: "Joe"}
	err = input.Load(dir)
	assert.Nil(t, err)
	cert, err := x509.ParseCertificate(input.cert)
	assert.Nil(t, err)
	assert.Equal(t, "Joe", cert.Subject.CommonName)

	got = Certificate{Subject: "CN=Jane", Filename: "mycert"}
	err = got.Generate(nil)
	assert.Nil(t, err)
	assert.Equal(t, "mycert", got.Filename)
	err = got.Save(dir)
	assert.Nil(t, err)
	input = Certificate{Subject: "CN=dummy", Filename: "mycert"}
	err = input.Load(dir)
	assert.Nil(t, err)
	cert, err = x509.ParseCertificate(input.cert)
	assert.Nil(t, err)
	assert.Equal(t, "Jane", cert.Subject.CommonName)
}

func TestIsCa(t *testing.T) {
	input1 := Certificate{Subject: "CN=Joe"}
	err := input1.Generate(nil)
	assert.Nil(t, err)
	got, err := x509.ParseCertificate(input1.cert)
	assert.Nil(t, err)
	assert.Equal(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, got.KeyUsage)
	assert.Equal(t, true, got.IsCA)

	isCA := true
	input1 = Certificate{Subject: "CN=Joe", IsCA: &isCA}
	err = input1.Generate(nil)
	assert.Nil(t, err)
	got, err = x509.ParseCertificate(input1.cert)
	assert.Nil(t, err)
	assert.Equal(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, got.KeyUsage)
	assert.Equal(t, true, got.IsCA)

	input2 := Certificate{Subject: "CN=EndEntity", Issuer: "CN=Joe"}
	err = input2.Generate(&input1)
	assert.Nil(t, err)
	got, err = x509.ParseCertificate(input2.cert)
	assert.Nil(t, err)
	assert.Equal(t, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, got.KeyUsage)
	assert.Equal(t, false, got.IsCA)
}

func TestNotBeforeAndNotAfter(t *testing.T) {
	wantNotBefore, _ := time.Parse(time.RFC3339, "2020-01-01T09:00:00Z")
	wantNotAfter, _ := time.Parse(time.RFC3339, "2020-01-01T09:00:00Z")
	defaultDuration, _ := time.ParseDuration("8760h")

	input := Certificate{Subject: "CN=Joe", NotBefore: &wantNotBefore}
	err := input.Generate(nil)
	assert.Nil(t, err)
	got, err := x509.ParseCertificate(input.cert)
	assert.Nil(t, err)
	assert.Equal(t, wantNotBefore, got.NotBefore)
	assert.Equal(t, got.NotBefore.Add(defaultDuration), got.NotAfter)

	input = Certificate{Subject: "CN=Joe", NotBefore: &wantNotBefore, NotAfter: &wantNotAfter}
	err = input.Generate(nil)
	assert.Nil(t, err)
	got, err = x509.ParseCertificate(input.cert)
	assert.Nil(t, err)
	assert.Equal(t, wantNotBefore, got.NotBefore)
	assert.Equal(t, wantNotAfter, got.NotAfter)
}

func TestInvalidSubject(t *testing.T) {
	var input Certificate
	err := input.Generate(nil)
	assert.NotNil(t, err)

	input = Certificate{Subject: "Foo=Bar"}
	err = input.Generate(nil)
	assert.NotNil(t, err)
}

func TestInvalidSubjectAltName(t *testing.T) {
	input := Certificate{Subject: "CN=Joe", SubjectAltName: []string{"EMAIL:user@example.com"}}
	err := input.Generate(nil)
	assert.NotNil(t, err)

	input = Certificate{Subject: "CN=Joe", SubjectAltName: []string{"URL:"}}
	err = input.Generate(nil)
	assert.NotNil(t, err)

	input = Certificate{Subject: "CN=Joe", SubjectAltName: []string{"IP:999.999.999.999"}}
	err = input.Generate(nil)
	assert.NotNil(t, err)
}

func TestInvalidKeysize(t *testing.T) {
	input := Certificate{Subject: "CN=Joe", KeySize: 1}
	err := input.Generate(nil)
	assert.NotNil(t, err)
}

func TestInvalidExpires(t *testing.T) {
	input := Certificate{Subject: "CN=Joe", Expires: "1not-an-unit"}
	err := input.Generate(nil)
	assert.NotNil(t, err)
}

func TestInvalidKeyUsage(t *testing.T) {
	input := Certificate{Subject: "CN=Joe", KeyUsage: []string{"DigitalSignature", "invalid-key-usage"}}
	err := input.Generate(nil)
	assert.NotNil(t, err)
}

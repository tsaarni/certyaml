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

package certyaml

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSubjectName(t *testing.T) {
	input := Certificate{Subject: "CN=Joe"}
	got, err := input.X509Certificate()
	assert.Nil(t, err)
	assert.Equal(t, "Joe", got.Subject.CommonName)
}

func TestSubjectAltName(t *testing.T) {
	input := Certificate{Subject: "CN=Joe", SubjectAltNames: []string{"DNS:host.example.com", "URI:http://www.example.com", "IP:1.2.3.4"}}
	got, err := input.X509Certificate()
	assert.Nil(t, err)
	assert.Equal(t, "Joe", got.Subject.CommonName)
	assert.Equal(t, "host.example.com", got.DNSNames[0])
	assert.Equal(t, url.URL{Scheme: "http", Host: "www.example.com"}, *got.URIs[0])
	assert.Equal(t, net.IP{1, 2, 3, 4}, got.IPAddresses[0])
}

func TestEcKeySize(t *testing.T) {
	input := Certificate{Subject: "CN=Joe", KeyType: KeyTypeEC, KeySize: 256}
	got, err := input.PublicKey()
	assert.Nil(t, err)
	assert.Equal(t, elliptic.P256(), got.(*ecdsa.PublicKey).Curve)

	input = Certificate{Subject: "CN=Joe", KeyType: KeyTypeEC, KeySize: 384}
	got, err = input.PublicKey()
	assert.Nil(t, err)
	assert.Equal(t, elliptic.P384(), got.(*ecdsa.PublicKey).Curve)

	input = Certificate{Subject: "CN=Joe", KeyType: KeyTypeEC, KeySize: 521}
	got, err = input.PublicKey()
	assert.Nil(t, err)
	assert.Equal(t, elliptic.P521(), got.(*ecdsa.PublicKey).Curve)
}

func TestRsaKeySize(t *testing.T) {
	input := Certificate{Subject: "CN=Joe", KeyType: KeyTypeRSA, KeySize: 1024}
	got, err := input.PublicKey()
	assert.Nil(t, err)
	assert.Equal(t, 1024, got.(*rsa.PublicKey).Size()*8)

	input = Certificate{Subject: "CN=Joe", KeyType: KeyTypeRSA, KeySize: 2048}
	got, err = input.PublicKey()
	assert.Nil(t, err)
	assert.Equal(t, 2048, got.(*rsa.PublicKey).Size()*8)

	input = Certificate{Subject: "CN=Joe", KeyType: KeyTypeRSA, KeySize: 4096}
	got, err = input.PublicKey()
	assert.Nil(t, err)
	assert.Equal(t, 4096, got.(*rsa.PublicKey).Size()*8)
}

func TestExpires(t *testing.T) {
	hour := 1 * time.Hour
	input := Certificate{Subject: "CN=Joe", Expires: &hour}
	cert, err := input.X509Certificate()
	assert.Nil(t, err)
	got := cert.NotAfter.Sub(cert.NotBefore)
	assert.Equal(t, hour, got)
}

func TestKeyUsage(t *testing.T) {
	input := Certificate{Subject: "CN=Joe", KeyUsage: x509.KeyUsageDigitalSignature}
	got, err := input.X509Certificate()
	assert.Nil(t, err)
	assert.Equal(t, x509.KeyUsageDigitalSignature, got.KeyUsage)

	input = Certificate{Subject: "CN=Joe", KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
	got, err = input.X509Certificate()
	assert.Nil(t, err)
	assert.Equal(t, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, got.KeyUsage)

	input = Certificate{Subject: "CN=Joe", KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageEncipherOnly | x509.KeyUsageDecipherOnly}
	got, err = input.X509Certificate()
	assert.Nil(t, err)
	assert.Equal(t, x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment|x509.KeyUsageKeyEncipherment|x509.KeyUsageDataEncipherment|x509.KeyUsageKeyAgreement|x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageEncipherOnly|x509.KeyUsageDecipherOnly, got.KeyUsage)
}

func TestExtendedKeyUsage(t *testing.T) {
	input := Certificate{Subject: "CN=Joe", ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning}}
	got, err := input.X509Certificate()
	assert.Nil(t, err)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning}, got.ExtKeyUsage)
}

func TestIssuer(t *testing.T) {
	input1 := Certificate{Subject: "CN=Joe"}
	got, err := input1.X509Certificate()
	assert.Nil(t, err)
	assert.Equal(t, "Joe", got.Subject.CommonName)
	assert.Equal(t, "Joe", got.Issuer.CommonName)
	assert.Equal(t, true, got.IsCA)

	input2 := Certificate{Subject: "CN=EndEntity", Issuer: &input1}
	got, err = input2.X509Certificate()
	assert.Nil(t, err)
	assert.Equal(t, "EndEntity", got.Subject.CommonName)
	assert.Equal(t, "Joe", got.Issuer.CommonName)
	assert.Equal(t, false, got.IsCA)
}

func TestIsCa(t *testing.T) {
	input1 := Certificate{Subject: "CN=Joe"}
	got, err := input1.X509Certificate()
	assert.Nil(t, err)
	assert.Equal(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, got.KeyUsage)
	assert.Equal(t, true, got.IsCA)

	isCA := true
	input2 := Certificate{Subject: "CN=Joe", IsCA: &isCA}
	got, err = input2.X509Certificate()
	assert.Nil(t, err)
	assert.Equal(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, got.KeyUsage)
	assert.Equal(t, true, got.IsCA)

	input3 := Certificate{Subject: "CN=EndEntity", Issuer: &input2}
	got, err = input3.X509Certificate()
	assert.Nil(t, err)
	assert.Equal(t, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, got.KeyUsage)
	assert.Equal(t, false, got.IsCA)
}

func TestNotBeforeAndNotAfter(t *testing.T) {
	wantNotBefore, _ := time.Parse(time.RFC3339, "2020-01-01T09:00:00Z")
	wantNotAfter, _ := time.Parse(time.RFC3339, "2020-01-01T09:00:00Z")
	defaultDuration, _ := time.ParseDuration("8760h")

	input := Certificate{Subject: "CN=Joe", NotBefore: &wantNotBefore}
	got, err := input.X509Certificate()
	assert.Nil(t, err)
	assert.Equal(t, wantNotBefore, got.NotBefore)
	assert.Equal(t, got.NotBefore.Add(defaultDuration), got.NotAfter)

	input = Certificate{Subject: "CN=Joe", NotBefore: &wantNotBefore, NotAfter: &wantNotAfter}
	got, err = input.X509Certificate()
	assert.Nil(t, err)
	assert.Equal(t, wantNotBefore, got.NotBefore)
	assert.Equal(t, wantNotAfter, got.NotAfter)
}

func TestInvalidSubject(t *testing.T) {
	input := Certificate{Subject: "Foo=Bar"}
	_, err := input.X509Certificate()
	assert.NotNil(t, err)
}

func TestEmptySubject(t *testing.T) {
	// Empty subject is allowed.
	var input Certificate
	_, err := input.X509Certificate()
	assert.Nil(t, err)
}

func TestInvalidSubjectAltName(t *testing.T) {
	input := Certificate{Subject: "CN=Joe", SubjectAltNames: []string{"EMAIL:user@example.com"}}
	_, err := input.X509Certificate()
	assert.NotNil(t, err)

	input = Certificate{Subject: "CN=Joe", SubjectAltNames: []string{"URL:"}}
	_, err = input.X509Certificate()
	assert.NotNil(t, err)

	input = Certificate{Subject: "CN=Joe", SubjectAltNames: []string{"IP:999.999.999.999"}}
	_, err = input.X509Certificate()
	assert.NotNil(t, err)
}

func TestInvalidKeySize(t *testing.T) {
	input := Certificate{Subject: "CN=Joe", KeyType: KeyTypeEC, KeySize: 1}
	_, err := input.X509Certificate()
	assert.NotNil(t, err)

	input = Certificate{Subject: "CN=Joe", KeyType: KeyTypeRSA, KeySize: 1}
	_, err = input.X509Certificate()
	assert.NotNil(t, err)

	input = Certificate{Subject: "CN=Joe", KeyType: KeyTypeEd25519, KeySize: 1}
	_, err = input.X509Certificate()
	assert.NotNil(t, err)
}

func TestPEM(t *testing.T) {
	ca := Certificate{
		Subject: "cn=ca",
	}

	server := Certificate{
		Subject:         "CN=server",
		SubjectAltNames: []string{"DNS:localhost"},
		Issuer:          &ca,
	}

	client := Certificate{
		Subject: "CN=client",
		Issuer:  &ca,
	}

	caCert, caKey, err := ca.PEM()
	assert.Nil(t, err)

	block, rest := pem.Decode(caCert)
	assert.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)
	assert.Empty(t, rest)
	block, rest = pem.Decode(caKey)
	assert.NotNil(t, block)
	assert.Equal(t, "PRIVATE KEY", block.Type)
	assert.Empty(t, rest)

	serverCert, serverKey, err := server.PEM()
	assert.Nil(t, err)

	block, rest = pem.Decode(serverCert)
	assert.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)
	assert.Empty(t, rest)
	block, rest = pem.Decode(serverKey)
	assert.NotNil(t, block)
	assert.Equal(t, "PRIVATE KEY", block.Type)
	assert.Empty(t, rest)

	clientCert, clientKey, err := client.PEM()
	assert.Nil(t, err)

	block, rest = pem.Decode(clientCert)
	assert.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)
	assert.Empty(t, rest)
	block, rest = pem.Decode(clientKey)
	assert.NotNil(t, block)
	assert.Equal(t, "PRIVATE KEY", block.Type)
	assert.Empty(t, rest)
}

func TestWritingPEMFiles(t *testing.T) {
	ca := Certificate{
		Subject: "cn=ca",
	}

	server := Certificate{
		Subject:         "CN=server",
		SubjectAltNames: []string{"DNS:localhost"},
		Issuer:          &ca,
	}

	client := Certificate{
		Subject: "CN=client",
		Issuer:  &ca,
	}

	dir, err := os.MkdirTemp("/tmp", "certyaml-unittest")
	assert.Nil(t, err)
	defer os.RemoveAll(dir)

	// Write CA certificate to disk.
	err = ca.WritePEM(path.Join(dir, "ca.pem"), path.Join(dir, "ca-key.pem"))
	assert.Nil(t, err, "failed writing: %s", err)

	// Read it back and compare to original.
	certFromPEM, err := tls.LoadX509KeyPair(path.Join(dir, "ca.pem"), path.Join(dir, "ca-key.pem"))
	assert.Nil(t, err, "failed loading: %s", err)
	cert, err := ca.TLSCertificate()
	assert.Nil(t, err, "failed getting tls.Certificate: %s", err)
	assert.Equal(t, cert, certFromPEM)

	// Write server certificate to disk.
	err = server.WritePEM(path.Join(dir, "server.pem"), path.Join(dir, "server-key.pem"))
	assert.Nil(t, err, "failed writing: %s", err)

	// Read it back and compare to original.
	certFromPEM, err = tls.LoadX509KeyPair(path.Join(dir, "server.pem"), path.Join(dir, "server-key.pem"))
	assert.Nil(t, err, "failed loading: %s", err)
	cert, err = server.TLSCertificate()
	assert.Nil(t, err, "failed getting tls.Certificate: %s", err)
	assert.Equal(t, cert, certFromPEM)

	// Write client certificate to disk.
	err = client.WritePEM(path.Join(dir, "client.pem"), path.Join(dir, "client-key.pem"))
	assert.Nil(t, err, "failed writing: %s", err)

	// Read it back and compare to original.
	certFromPEM, err = tls.LoadX509KeyPair(path.Join(dir, "client.pem"), path.Join(dir, "client-key.pem"))
	assert.Nil(t, err, "failed loading: %s", err)
	cert, err = client.TLSCertificate()
	assert.Nil(t, err, "failed getting tls.Certificate: %s", err)
	assert.Equal(t, cert, certFromPEM)
}

func TestRegenerate(t *testing.T) {
	cert := Certificate{Subject: "CN=Joe"}

	older, err := cert.TLSCertificate()
	assert.Nil(t, err)

	err = cert.Generate()
	assert.Nil(t, err)

	newer, err := cert.TLSCertificate()
	assert.Nil(t, err)

	assert.NotEqual(t, older.Certificate, newer.Certificate)
	assert.NotEqual(t, older.PrivateKey, newer.PrivateKey)
}

func TestSerial(t *testing.T) {
	serial := big.NewInt(123)
	input := Certificate{Subject: "CN=Joe", SerialNumber: serial}
	got, err := input.X509Certificate()
	assert.Nil(t, err)
	assert.Equal(t, serial, got.SerialNumber)

	// Check that unique serial is generated by default.
	input1 := Certificate{Subject: "CN=Joe"}
	input2 := Certificate{Subject: "CN=Joe"}
	got1, err := input1.X509Certificate()
	assert.Nil(t, err)
	got2, err := input2.X509Certificate()
	assert.Nil(t, err)
	assert.NotEqual(t, got1.SerialNumber, got2.SerialNumber)
}

func TestCertificateChain(t *testing.T) {
	isCA := true
	rootCA := Certificate{Subject: "CN=ca"}
	subCA1 := Certificate{Subject: "CN=sub-ca-1", Issuer: &rootCA, IsCA: &isCA}
	subCA2 := Certificate{Subject: "CN=sub-ca-2", Issuer: &subCA1, IsCA: &isCA}
	endEntity := Certificate{Subject: "CN=end-entity", Issuer: &subCA2}

	// End-entity certificates have certificate chains appended.
	got, err := endEntity.TLSCertificate()
	assert.Nil(t, err)
	assert.Equal(t, 3, len(got.Certificate))
	assert.Equal(t, endEntity.GeneratedCert.Certificate[0], got.Certificate[0])
	assert.Equal(t, subCA2.GeneratedCert.Certificate[0], got.Certificate[1])
	assert.Equal(t, subCA1.GeneratedCert.Certificate[0], got.Certificate[2])

	// CA certificates do not have chains appended.
	got, err = subCA2.TLSCertificate()
	assert.Nil(t, err)
	assert.Equal(t, 1, len(got.Certificate))
}

func TestCertificateChainInPEM(t *testing.T) {
	isCA := true
	rootCA := Certificate{Subject: "CN=ca"}
	subCA1 := Certificate{Subject: "CN=sub-ca-1", Issuer: &rootCA, IsCA: &isCA}
	subCA2 := Certificate{Subject: "CN=sub-ca-2", Issuer: &subCA1, IsCA: &isCA}
	endEntity := Certificate{Subject: "CN=end-entity", Issuer: &subCA2}

	// End-entity certificates have certificate chains appended.
	got, _, err := endEntity.PEM()
	assert.Nil(t, err)

	block, rest := pem.Decode(got)
	assert.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	assert.Nil(t, err)
	assert.Equal(t, "CN=end-entity", cert.Subject.String())

	block, rest = pem.Decode(rest)
	assert.NotNil(t, block)
	cert, err = x509.ParseCertificate(block.Bytes)
	assert.Nil(t, err)
	assert.Equal(t, "CN=sub-ca-2", cert.Subject.String())

	block, rest = pem.Decode(rest)
	assert.NotNil(t, block)
	cert, err = x509.ParseCertificate(block.Bytes)
	assert.Nil(t, err)
	assert.Equal(t, "CN=sub-ca-1", cert.Subject.String())

	assert.Empty(t, rest)
}

func TestParallelCertificateLazyInitialization(t *testing.T) {
	cert := Certificate{Subject: "CN=Joe"}

	// Trigger lazy initialization by calling one of the generator methods in parallel.
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(cert *Certificate) {
			defer wg.Done()
			_, err := cert.X509Certificate()
			assert.Nil(t, err)
		}(&cert)
	}

	wg.Wait()
}

func TestCRLDistributionPoint(t *testing.T) {
	input := Certificate{Subject: "CN=Joe", CRLDistributionPoints: []string{"http://example.com/crl.pem"}}
	got, err := input.X509Certificate()
	assert.Nil(t, err)
	assert.Equal(t, []string{"http://example.com/crl.pem"}, got.CRLDistributionPoints)
}

func TestConvenienceGetters(t *testing.T) {
	input := Certificate{Subject: "CN=Joe"}
	cert, key, err := input.PEM()
	assert.Nil(t, err)
	assert.Equal(t, cert, input.CertPEM())
	assert.Equal(t, key, input.KeyPEM())
}

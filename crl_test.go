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
	"crypto/x509"
	"math/big"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRevocation(t *testing.T) {
	ca := Certificate{Subject: "CN=ca"}
	input1 := Certificate{Subject: "CN=Joe", Issuer: &ca, SerialNumber: big.NewInt(123)}
	input2 := Certificate{Subject: "CN=Jill", Issuer: &ca, SerialNumber: big.NewInt(456)}

	crl := CRL{}
	err := crl.Add(&input1)
	assert.Nil(t, err)
	err = crl.Add(&input2)
	assert.Nil(t, err)

	crlBytes, err := crl.DER()
	assert.Nil(t, err)
	certList, err := x509.ParseRevocationList(crlBytes)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(certList.RevokedCertificateEntries))
	assert.Equal(t, "CN=ca", certList.Issuer.String())
	assert.Equal(t, big.NewInt(123), certList.RevokedCertificateEntries[0].SerialNumber)
	assert.Equal(t, big.NewInt(456), certList.RevokedCertificateEntries[1].SerialNumber)
}

func TestInvalidSelfSigned(t *testing.T) {
	input := Certificate{Subject: "CN=joe"}

	// Include self-signed certificate in struct.
	crl := CRL{Revoked: []*Certificate{&input}}
	_, err := crl.DER()
	assert.NotNil(t, err)

	// Try adding self-signed certificates.
	err = crl.Add(&input)
	assert.NotNil(t, err)
}

func TestInvalidIssuers(t *testing.T) {
	ca1 := Certificate{Subject: "CN=ca1"}
	ca2 := Certificate{Subject: "CN=ca2"}
	input1 := Certificate{Subject: "CN=Joe", Issuer: &ca1}
	input2 := Certificate{Subject: "CN=Jill", Issuer: &ca2}

	// Include certificates with different issuers in struct.
	crl := CRL{Revoked: []*Certificate{&input1, &input2}}
	_, err := crl.DER()
	assert.NotNil(t, err)

	// Try adding certificates with different issuers.
	crl = CRL{}
	err = crl.Add(&input1)
	assert.Nil(t, err)
	err = crl.Add(&input2)
	assert.NotNil(t, err)

	// Explicitly set issuer but add certificates issued by different CA.
	crl = CRL{Issuer: &ca1, Revoked: []*Certificate{&input2}}
	_, err = crl.DER()
	assert.NotNil(t, err)

}

func TestEmptyCRL(t *testing.T) {
	// Empty CRL can be created by explicitly defining Issuer.
	ca := Certificate{Subject: "CN=ca"}
	crl := CRL{Issuer: &ca}
	crlBytes, err := crl.DER()
	assert.Nil(t, err)

	certList, err := x509.ParseRevocationList(crlBytes)
	assert.Nil(t, err)
	assert.Equal(t, 0, len(certList.RevokedCertificateEntries))
	assert.Equal(t, "CN=ca", certList.Issuer.String())

	// Empty CRL with no issuer cannot be created.
	crl = CRL{}
	_, err = crl.DER()
	assert.NotNil(t, err)
}

func TestParallelCRLLazyInitialization(t *testing.T) {
	ca := Certificate{Subject: "CN=ca"}
	revoked := Certificate{Subject: "CN=Joe", Issuer: &ca}
	crl := CRL{Revoked: []*Certificate{&revoked}}

	// Call CRL generation in parallel.
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(cert *Certificate) {
			defer wg.Done()
			_, err := crl.DER()
			assert.Nil(t, err)
		}(&ca)
	}

	wg.Wait()
}

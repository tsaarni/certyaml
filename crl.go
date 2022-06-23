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
	"bytes"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// CRL defines properties for generating CRL files.
type CRL struct {
	// ThisUpdate is the issue date of this CRL.
	// Default value is current time (when value is nil).
	ThisUpdate *time.Time

	// NextUpdate indicates the date by which the next CRL will be issued.
	// Default value is ThisUpdate + one week (when value is nil).
	NextUpdate *time.Time

	// Revoked is the list of Certificates that will be included in the CRL.
	// All Certificates must be issued by the same Issuer.
	// Self-signed certificates cannot be added.
	Revoked []*Certificate

	// Issuer is the CA certificate issuing this CRL.
	// If not set, it defaults to the issuer of certificates added to Revoked list.
	Issuer *Certificate
}

// Add appends a Certificate to CRL list.
// All Certificates must be issued by the same Issuer.
// Self-signed certificates cannot be added.
// Error is not nil if adding fails.
func (crl *CRL) Add(cert *Certificate) error {
	if cert.Issuer == nil {
		return fmt.Errorf("cannot revoke self-signed certificate: %s", cert.Subject)
	}
	if len(crl.Revoked) > 0 && (crl.Revoked[0].Issuer != cert.Issuer) {
		return fmt.Errorf("CRL can contain certificates for single issuer only")
	}
	crl.Revoked = append(crl.Revoked, cert)
	return nil
}

// DER returns the CRL as DER buffer.
// Error is not nil if generation fails.
func (crl *CRL) DER() (crlBytes []byte, err error) {
	if crl.Issuer == nil {
		if len(crl.Revoked) == 0 {
			return nil, fmt.Errorf("Issuer not known: either set Issuer or add certificates to the CRL")
		}
		crl.Issuer = crl.Revoked[0].Issuer
	}

	effectiveRevocationTime := time.Now()
	if crl.ThisUpdate != nil {
		effectiveRevocationTime = *crl.ThisUpdate
	}

	week := 24 * 7 * time.Hour
	effectiveExpiry := effectiveRevocationTime.UTC().Add(week)
	if crl.NextUpdate != nil {
		effectiveExpiry = *crl.NextUpdate
	}

	var revokedCerts []pkix.RevokedCertificate
	for _, c := range crl.Revoked {
		err := c.ensureGenerated()
		if err != nil {
			return nil, err
		}
		if c.Issuer == nil {
			return nil, fmt.Errorf("cannot revoke self-signed certificate: %s", c.Subject)
		} else if c.Issuer != crl.Issuer {
			return nil, fmt.Errorf("revoked certificates added from several issuers, or certificate does not match explicitly set Issuer")
		}
		revokedCerts = append(revokedCerts, pkix.RevokedCertificate{
			SerialNumber:   c.SerialNumber,
			RevocationTime: effectiveRevocationTime,
		})
	}

	ca, err := crl.Issuer.X509Certificate()
	if err != nil {
		return nil, err
	}

	privateKey, err := crl.Issuer.PrivateKey()
	if err != nil {
		return nil, err
	}

	return ca.CreateCRL(rand.Reader, privateKey, revokedCerts, effectiveRevocationTime, effectiveExpiry)
}

// PEM returns the CRL as PEM buffer.
// Error is not nil if generation fails.
func (crl *CRL) PEM() (crlBytes []byte, err error) {
	derBytes, err := crl.DER()
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	err = pem.Encode(&buf, &pem.Block{
		Type:  "X509 CRL",
		Bytes: derBytes,
	})
	if err != nil {
		return nil, err
	}

	crlBytes = append(crlBytes, buf.Bytes()...) // Create copy of underlying buf.
	return
}

// WritePEM writes the CRL as PEM file.
// Error is not nil if writing fails.
func (crl *CRL) WritePEM(crlFile string) error {
	pemBytes, err := crl.PEM()
	if err != nil {
		return err
	}
	err = os.WriteFile(crlFile, pemBytes, 0600)
	if err != nil {
		return err
	}

	return nil
}

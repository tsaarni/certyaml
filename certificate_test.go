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
	"crypto/tls"
	"io/ioutil"
	"log"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

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

	dir, err := ioutil.TempDir("/tmp", "certyaml-unittest")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// Write CA certificate to disk.
	err = ca.writePEM(path.Join(dir, "ca.pem"), path.Join(dir, "ca-key.pem"))
	assert.Nil(t, err, "failed writing: %s", err)

	// Read it back and compare to original.
	certFromPEM, err := tls.LoadX509KeyPair(path.Join(dir, "ca.pem"), path.Join(dir, "ca-key.pem"))
	assert.Nil(t, err, "failed loading: %s", err)
	cert, err := ca.TLSCertificate()
	assert.Nil(t, err, "failed getting tls.Certificate: %s", err)
	assert.Equal(t, cert, certFromPEM)

	// Write server certificate to disk.
	err = server.writePEM(path.Join(dir, "server.pem"), path.Join(dir, "server-key.pem"))
	assert.Nil(t, err, "failed writing: %s", err)

	// Read it back and compare to original.
	certFromPEM, err = tls.LoadX509KeyPair(path.Join(dir, "server.pem"), path.Join(dir, "server-key.pem"))
	assert.Nil(t, err, "failed loading: %s", err)
	cert, err = server.TLSCertificate()
	assert.Nil(t, err, "failed getting tls.Certificate: %s", err)
	assert.Equal(t, cert, certFromPEM)

	// Write client certificate to disk.
	err = client.writePEM(path.Join(dir, "client.pem"), path.Join(dir, "client-key.pem"))
	assert.Nil(t, err, "failed writing: %s", err)

	// Read it back and compare to original.
	certFromPEM, err = tls.LoadX509KeyPair(path.Join(dir, "client.pem"), path.Join(dir, "client-key.pem"))
	assert.Nil(t, err, "failed loading: %s", err)
	cert, err = client.TLSCertificate()
	assert.Nil(t, err, "failed getting tls.Certificate: %s", err)
	assert.Equal(t, cert, certFromPEM)
}

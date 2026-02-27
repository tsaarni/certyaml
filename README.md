# certyaml

Declarative way to create x509 certificates for test environments.
No more storing test certificates and private keys in the repository!

![](https://github.com/tsaarni/certyaml/workflows/unit-tests/badge.svg)
[![Go Reference](https://pkg.go.dev/badge/github.com/tsaarni/certyaml.svg)](https://pkg.go.dev/github.com/tsaarni/certyaml)

## Table of Contents

- [Description](#description)
- [Using certyaml](#using-certyaml)
- [Installing](#installing)
- [YAML Syntax](#yaml-syntax)
- [Go API](#go-api)

## Description

Certyaml is a command line tool and a Go API for issuing certificates.
It is similar to `openssl` or `cfssl` which can also be used for issuing certificates, but certyaml provides simpler way to define complete PKI hierarchies with a compact [YAML syntax](#YAML-syntax) or directly from Go code with a simple API.

Certyaml is targeted for developers who need to set up a private PKI for test environments.
It cannot be used for production environments where publicly trusted certificates are needed.

If you program in other languages, check out following projects:

- [java-certy](https://github.com/tsaarni/java-certy)
- [python-certy](https://github.com/tsaarni/python-certy)

## Using certyaml

```
Usage: certyaml [-d destination] [certs.yaml]

Creates certificates and keys according to manifest file in YAML format.
By default it reads `certs.yaml` as a manifest file and creates files
in current directory.

  -d string
        Short for --destination
  -destination string
        Destination directory where to create the certificates and keys
```

### Installing

**Release builds**

Release builds are available for download in [releases page](https://github.com/tsaarni/certyaml/releases).

**Compiling from source code**

Go compiler is required to build `certyaml` binary

```bash
go install github.com/tsaarni/certyaml/cmd/certyaml@latest
```

The executable will be stored in the go path, by default `~/go/bin/certyaml`.

Alternatively, you can run the tool without installing it:

```bash
go run github.com/tsaarni/certyaml/cmd/certyaml@latest
```


### Using certyaml

Create a YAML manifest file which describes the wanted PKI hierarchy and end-entity certificates

```console
$ cat >certs.yaml <<EOF
subject: cn=server-root-ca
---
subject: cn=intermediate-ca
issuer: cn=server-root-ca
ca: true
---
subject: cn=myserver
issuer: cn=intermediate-ca
sans:
- DNS:myserver.example.com
- DNS:foo
---
subject: cn=selfsigned-server
ca: false
key_usages:
- KeyEncipherment
- DigitalSignature
---
subject: cn=fixedtime
issuer: cn=intermediate-ca
not_before: 2020-01-01T09:00:00Z
not_after: 2020-02-01T10:10:10Z
---
subject: cn=shortlived
issuer: cn=intermediate-ca
expires: 1m
---
subject: cn=client-root-ca
---
subject: CN=John Doe,OU=People,O=Company
filename: clientcert
issuer: cn=client-root-ca
EOF
```

Generate the certificates

```console
$ certyaml
Loading manifest: certs.yaml
Reading state: certs.state
Writing: server-root-ca.pem server-root-ca-key.pem
Writing: intermediate-ca.pem intermediate-ca-key.pem
Writing: myserver.pem myserver-key.pem
Writing: selfsigned-server.pem selfsigned-server-key.pem
Writing: fixedtime.pem fixedtime-key.pem
Writing: shortlived.pem shortlived-key.pem
Writing: client-root-ca.pem client-root-ca-key.pem
Writing: clientcert.pem clientcert-key.pem
Writing state: certs.state

$ ls -l
total 72
-rw-r--r-- 1 tsaarni tsaarni  483 Jun 15 17:08 certs.state
-rw-rw-r-- 1 tsaarni tsaarni  588 Jun 15 17:07 certs.yaml
-rw-rw-r-- 1 tsaarni tsaarni 1679 Jun 15 17:08 clientcert-key.pem
-rw-rw-r-- 1 tsaarni tsaarni 1062 Jun 15 17:08 clientcert.pem
-rw-rw-r-- 1 tsaarni tsaarni 1679 Jun 15 17:08 client-root-ca-key.pem
-rw-rw-r-- 1 tsaarni tsaarni 1046 Jun 15 17:08 client-root-ca.pem
-rw-rw-r-- 1 tsaarni tsaarni 1675 Jun 15 17:08 fixedtime-key.pem
-rw-rw-r-- 1 tsaarni tsaarni 1017 Jun 15 17:08 fixedtime.pem
-rw-rw-r-- 1 tsaarni tsaarni 1679 Jun 15 17:08 intermediate-ca-key.pem
-rw-rw-r-- 1 tsaarni tsaarni 1046 Jun 15 17:08 intermediate-ca.pem
-rw-rw-r-- 1 tsaarni tsaarni 1679 Jun 15 17:08 myserver-key.pem
-rw-rw-r-- 1 tsaarni tsaarni 1066 Jun 15 17:08 myserver.pem
-rw-rw-r-- 1 tsaarni tsaarni 1675 Jun 15 17:08 selfsigned-server-key.pem
-rw-rw-r-- 1 tsaarni tsaarni 1029 Jun 15 17:08 selfsigned-server.pem
-rw-rw-r-- 1 tsaarni tsaarni 1675 Jun 15 17:08 server-root-ca-key.pem
-rw-rw-r-- 1 tsaarni tsaarni 1046 Jun 15 17:08 server-root-ca.pem
-rw-rw-r-- 1 tsaarni tsaarni 1675 Jun 15 17:08 shortlived-key.pem
-rw-rw-r-- 1 tsaarni tsaarni 1017 Jun 15 17:08 shortlived.pem
```

You can change parameters of the certificates in the YAML manifest or remove generated certificate files from the filesystem and then run `certyaml` again.
Only changed or missing certificates will be regenerated.

```console
$ rm myserver*
$ certyaml
Loading manifest: certs.yaml
Reading state: certs.state
No changes in manifest: skipping server-root-ca
No changes in manifest: skipping intermediate-ca
Writing: myserver.pem myserver-key.pem
No changes in manifest: skipping selfsigned-server
No changes in manifest: skipping fixedtime
No changes in manifest: skipping shortlived
No changes in manifest: skipping client-root-ca
No changes in manifest: skipping clientcert
Writing state: certs.state
```

### YAML syntax

| tag | description | examples |
| --- | ----------- | -------- |
| subject | Distinguished name for the certificate. `subject` is the only mandatory field and it must be unique. | `CN=Joe` |
| sans | List of values for x509 Subject Alternative Name extension. | `DNS:www.example.com`, `IP:1.2.3.4`, `URI:https://www.example.com`, `email:user@example.com` |
| key_type | Certificate key algorithm. Default value is `EC` (elliptic curve). | `EC`, `RSA` or `ED25519` |
| key_size | The key length in bits. Default value is 256 if `key_size` is not defined. | For key_type EC: `256`, `384`, `521`. For key_type RSA: `1024`, `2048`, `4096`. For key_type ED25519: `256`. |
| expires | Certificate NotAfter field is calculated by adding duration defined in `expires` to current time. Default value is 8760h (one year) if `expires` is not defined. `not_after` takes precedence over `expires`. | `1s`, `10m`, `1h` |
| key_usages | List of values for x509 key usage extension. If `key_usages` is not defined, `CertSign` and `CRLSign` are set for CA certificates, `KeyEncipherment` and `DigitalSignature` are set for end-entity certificates. | `DigitalSignature`, `ContentCommitment`, `KeyEncipherment`, `DataEncipherment`, `KeyAgreement`, `CertSign`, `CRLSign`, `EncipherOnly`, `DecipherOnly` |
| ext_key_usages | List of values for x509 extended key usage extension. Not set by default. | `Any`, `ServerAuth`, `ClientAuth`, `CodeSigning`, `EmailProtection`, `IPSECEndSystem`, `IPSECTunnel`, `IPSECUser`. `TimeStamping`, `OCSPSigning`, `MicrosoftServerGatedCrypto`, `NetscapeServerGatedCrypto`, `MicrosoftCommercialCodeSigning`, `MicrosoftKernelCodeSigning` |
| issuer | Distinguished name of the issuer. Issuer must be declared as a certificate in the manifest file before referring to it as issuer. Self-signed certificate is generated if `issuer` is not defined. | `CN=myca` |
| filename | The basename of the generated certificate and private key files. The files created to destination directory will be [filename].pem and [filename]-key.pem will. If `filename` is not defined, CN field value from subject will be used as filename. | `clientcert` |
| ca | Set certificate is / is not CA. If `ca` is not defined, `true` is set by default for self-signed certificates. | `true` or  `false` |
| not_before | Certificate is not valid before this time ([RFC3339 timestamp](https://tools.ietf.org/html/rfc3339)). | `2020-01-01T09:00:00Z` |
| not_after | Certificate is not valid after this time ([RFC3339 timestamp](https://tools.ietf.org/html/rfc3339)). | `2020-01-01T09:00:00Z` |
| serial | Serial number for the certificate. Default value is current time in nanoseconds. | `123` |
| revoked | When `true` the serial number of the certificate will be written in `[issuer]-crl.pem`.  Default value is `false`. The file will be written only if at least one certificate is revoked. CRL `ThisUpdate` is set to current time and `NextUpdate` one week after. Self-signed certificates cannot be revoked. | `true`, `false` |
| crl_distribution_points | List of URLs for X509 CRL Distribution Points extension. | `http://example.com/crl.pem` |
| ocsp | List of URLs for X509 OCSP responder (Authority Information Access extension). | `http://ocsp.example.com` |

## Go API

For using certyaml in Go applications, see [API documentation](https://pkg.go.dev/github.com/tsaarni/certyaml).

For examples on how to use the API use, see [`examples/go-api`](examples/go-api) and [`certificate_test.go`](certificate_test.go).

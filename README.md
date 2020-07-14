# certyaml

Declarative way to create x509 certificates for test environments.

![](https://github.com/tsaarni/certyaml/workflows/unit-tests/badge.svg)

## Description

Certyaml is a command line tool for issuing certificates.
It is similiar to `openssl` or `cfssl` which can also be used for issuing certificates, but certyaml provides simpler way to define complete PKI hierarchies with a compact [YAML syntax](#YAML-syntax).

Certyaml is targeted for developers who need to set up a private PKI for test environments.
It cannot be used for production environments where publicly trusted certificates are needed.

## Installing

**Release builds**

Release builds are available for download in [releases page](https://github.com/tsaarni/certyaml/releases).

**Compiling from source code**

Go compiler is required to build `certyaml` binary

```bash
GO111MODULE=on go get github.com/tsaarni/certyaml@v0.1.0
```

The executable will be stored in the go path, by default `~/go/bin/certyaml`.


## Using certyaml

Create a YAML manifest file which describes the wanted PKI hierarchy and end-entity certificates

```console
$ cat certs.yaml <<EOF
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
key_usage:
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
$ ~/go/bin/certyaml certs.yaml
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
$ ~/go/bin/certyaml certs.yaml
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


## YAML syntax

| tag | description | examples |
| --- | ----------- | -------- |
| subject | Distringuished name for the certificate. | `CN=Joe` |
| sans | List of values for x509 Subject Alternative Name extension. | `DNS:www.example.com`, `IP:1.2.3.4`, `URI:https://www.example.com` |
| key_size | RSA key size. | 4096 |
| expires | Certificate NotAfter field is calculated by adding duration defined in `expires` to current time. | `1s`, `10m`, `1h` |
| key_usages | List of values for x509 key usage extension. | `DigitalSignature`, `ContentCommitment`, `KeyEncipherment`, `DataEncipherment`, `KeyAgreement`, `CertSign`, `CRLSign`, `EncipherOnly`, `DecipherOnly` |
| issuer | Distringuished name of the issuer. Issuer must be declared as a certificate in the manifest file before referring to it as issuer. | `CN=myca` |
| filename | The basename of the generated certificate and private key files. The files created to destination directory will be [filename].pem and [filename]-key.pem will. If `filename` is not defined, CN field value from subject will be used as filename. | `clientcert` |
| ca | Set certificate is / is not CA (boolean) | `true` or  `false` |
| not_before | Certificate is not valid before this time ([RFC3339 timestamp](https://tools.ietf.org/html/rfc3339)) | `2020-01-01T09:00:00Z` |
| not_after | Certificate is not valid after this time ([RFC3339 timestamp](https://tools.ietf.org/html/rfc3339)) | `2020-01-01T09:00:00Z` |

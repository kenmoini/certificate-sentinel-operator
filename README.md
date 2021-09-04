# certificate-sentinel-operator

## Certificate Sentinel Operator

[![Go Reference](https://pkg.go.dev/badge/github.com/PolyglotSystems/certificate-sentinel-operator.svg)](https://pkg.go.dev/github.com/PolyglotSystems/certificate-sentinel-operator) [![Go Report Card](https://goreportcard.com/badge/github.com/PolyglotSystems/certificate-sentinel-operator)](https://goreportcard.com/report/github.com/PolyglotSystems/certificate-sentinel-operator) [![License: GPL v3](https://img.shields.io/badge/License-Apache%20v2-blue.svg)](https://github.com/PolyglotSystems/certificate-sentinel-operator/tree/main/LICENSE)

#### Tested on OpenShift 4.8

The Certificate Sentinel Operator allows for the scanning and reporting of SSL Certificates within a Kubernetes/OpenShift cluster.

## Documentation

- [Quickstart](https://github.com/PolyglotSystems/certificate-sentinel-operator/tree/main/docs/quickstart.md)
- [SMTP Configuration](https://github.com/PolyglotSystems/certificate-sentinel-operator/tree/main/docs/smtp-configuration.md)
- [Full YAML Structure - CertificateSentinel](https://github.com/PolyglotSystems/certificate-sentinel-operator/tree/main/docs/full_yaml_spec-CertificateSentinel.md)

## Deploying the Operator

PROD IDK yet, hold on, i'm doing it dev mode deployment bby

### Development & Testing Deployment

Requires Golang 1.16+ and the DevelopmentTools dnf group.

```bash
# plz be `oc login`'d already
# also also need @DevelopmentTools & golang installed
git clone https://github.com/PolyglotSystems/certificate-sentinel-operator
cd certificate-sentinel-operator/
make generate && make manifests && make install run
```
# certificate-sentinel-operator

[![Go Reference](https://pkg.go.dev/badge/github.com/PolyglotSystems/certificate-sentinel-operator.svg)](https://pkg.go.dev/github.com/PolyglotSystems/certificate-sentinel-operator) [![Go Report Card](https://goreportcard.com/badge/github.com/PolyglotSystems/certificate-sentinel-operator)](https://goreportcard.com/report/github.com/PolyglotSystems/certificate-sentinel-operator) [![License: GPL v3](https://img.shields.io/badge/License-Apache%20v2-blue.svg)](https://github.com/PolyglotSystems/certificate-sentinel-operator/tree/main/LICENSE)

##### Tested on OpenShift 4.8

The Certificate Sentinel Operator allows for the scanning and reporting of SSL Certificates within a Kubernetes/OpenShift cluster.

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

## Quickstart

### 1. Create a Namespace

*THIS!  IS!  KUBERNETES!*

So, ya know, make a Namespace to get started...

```yaml
---
apiVersion: v1
kind: Namespace
metadata:
  name: cert-sentinel
spec: {}
```

### 2. Create ServiceAccount

This ServiceAccount will be the RBAC object that will access the K8s/OCP API in order to scan the cluster for Certificates

```yaml
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: some-service-account
  namespace: cert-sentinel
```

### 3. Create ClusterRoleBindings

These ClusterRoles will define the RBAC permissions required order to access Namespaces, Secrets, and ConfigMaps

##### namespace-reader

```yaml
---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: namespace-reader
rules:
  - verbs:
      - get
      - watch
      - list
    apiGroups:
      - ''
    resources:
      - namespaces
```

##### secret-reader

```yaml
---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: secret-reader
  - verbs:
      - get
      - watch
      - list
    apiGroups:
      - ''
    resources:
      - secrets
```

##### configmap-reader

```yaml
---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: configmap-reader
  - verbs:
      - get
      - watch
      - list
    apiGroups:
      - ''
    resources:
      - configmaps
```

### 4. Create RoleBindings

Your ServiceAccount needs to be able to query a Namespace List and the Secrets/ConfigMaps in those namespaces - you do this with a RoleBinding to associate the ClusterRoles we just defined with the some-service-account ServiceAccount.

#### Targeted to only allow the sa/some-service-account to read in a specific namespace, cert-sentinel

For other namespaces you would need to duplicate and variate the `.metadata.namespace`

##### Allow the serviceaccount/some-service-account to access Namespaces on the cluster

```yaml
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: list-namespaces-cert-sentinel
  namespace: cert-sentinel
subjects:
- kind: ServiceAccount
  name: some-service-account
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: namespace-reader
  apiGroup: rbac.authorization.k8s.io
```

##### Allow the serviceaccount/some-service-account to access Secrets in namespace/cert-sentinel

```yaml
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-secrets-cert-sentinel
  namespace: cert-sentinel
subjects:
- kind: ServiceAccount
  name: some-service-account
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: secret-reader
  apiGroup: rbac.authorization.k8s.io
```

##### Allow the serviceaccount/some-service-account to access Secrets in namespace/openshift-kube-scheduler-operator

```yaml
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-secrets-cert-sentinel
  namespace: openshift-kube-scheduler-operator
subjects:
- kind: ServiceAccount
  name: some-service-account
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: secret-reader
  apiGroup: rbac.authorization.k8s.io
```

#### Cluster-wide access to secrets

```yaml
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: list-namespaces-cert-sentinel
subjects:
- kind: ServiceAccount
  name: some-service-account
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: namespace-reader
  apiGroup: rbac.authorization.k8s.io
```

```yaml
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: read-secrets-cert-sentinel
subjects:
- kind: ServiceAccount
  name: some-service-account
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: secret-reader
  apiGroup: rbac.authorization.k8s.io
```

### 5. Create a CertificateSentinel

Now that you have a Namespace and a ServiceAccount that has access to other Namespaces and the ability to read their Secrets/ConfigMaps, you can create the an object with the type of a Custom Resource Definition (CRD) supplied by this Operator, CertificateSentinel.

CertificateSentinel will watch allowed (authorization by {Cluster}RoleBindings to the .targets[*].ServiceAccount, Kubernetes/OpenShift RBAC) Namespaces+Secrets/ConfigMaps.

It will then scan them for PEM base64 encoded x509 Certificates, such as ones used for client/server/user authentication and service security via SSL/TLS.

If the Secrets/ConfigMaps contain a valid x509 Certificate, it will check the expiration date of those certificates and check if they are to be soon expiring and if so fires off an Alert.  Current Alert Types are `logger` (just stdout via operator-controller log function, eg you just ship logs to Elastic/Splunk/etc and query/match/alert there) and `smtp` for email notifications.

The following CertificateSentinel will watch the whole cluster for Certificates in Secrets, accessing those it can and Alerting via logger to upcoming expirations:

```yaml
apiVersion: config.polyglot.systems/v1
kind: CertificateSentinel
metadata:
  name: certificatesentinel-sample
  namespace: cert-operator
spec:
  alerts:
    - name: secrets-logger
      type: logger
  targets:
    - apiVersion: v1
      kind: Secret
      name: all-secrets
      namespaces:
        - '*'
      serviceAccount: some-service-account
      daysOut:
        - 30
        - 60
        - 90
        - 9001
        - 9000
```

Once the Operator has found a series of Certificates, it will log the discovered and expired certificates and reflect the data in the `CertificateSentinel.status` as such:

```yaml
apiVersion: config.polyglot.systems/v1
kind: CertificateSentinel
metadata:
  creationTimestamp: '2021-08-31T02:53:12Z'
  generation: 4
  managedFields:
    ...
  name: certificatesentinel-sample
  namespace: cert-operator
  resourceVersion: '10437267'
  uid: 17db6400-2d6e-4c87-8b95-0a645ce211b9
spec:
  alerts:
    - name: secrets-logger
      type: logger
  targets:
    - apiVersion: v1
      daysOut:
        - 30
        - 60
        - 90
        - 9001
        - 9000
      kind: Secret
      name: all-secrets
      namespaces:
        - '*'
      serviceAccount: some-service-account
status:
  certificatesAtRisk:
    - triggeredDaysOut:
        - 9001
        - 9000
      certificateAuthorityCommonName: openshift-service-serving-signer@1630120637
      name: kube-scheduler-operator-serving-cert
      expiration: '2023-08-28 03:17:39 +0000 UTC'
      kind: Secret
      dataKey: tls.crt
      isCertificateAuthority: false
      namespace: openshift-kube-scheduler-operator
      apiVersion: v1
  discoveredCertificates:
    - triggeredDaysOut:
        - 9001
        - 9000
      certificateAuthorityCommonName: openshift-service-serving-signer@1630120637
      name: kube-scheduler-operator-serving-cert
      expiration: '2023-08-28 03:17:39 +0000 UTC'
      kind: Secret
      dataKey: tls.crt
      isCertificateAuthority: false
      namespace: openshift-kube-scheduler-operator
      apiVersion: v1
```

#### Full CertificateSentinel YAML Spec Example

```yaml
apiVersion: config.polyglot.systems/v1
kind: CertificateSentinel
metadata:
  name: certificatesentinel-sample
  namespace: cert-operator
spec:
  #  [optional] scanningInterval is the number of seconds the Operator will scan the cluster - default is 60
  scanningInterval: 60
  # alerts is a list of alerting endpoints associated with these below targets
  alerts:
    # Log report to Stdout once a day, useful for Elastic/Splunk/etc environments
    - name: secrets-logger # must be a unique dns/k8s compliant name
      type: logger # type can be: `logger` or `smtp`
      config: # optional on `logger` types, required for `smtp`
        reportInterval: daily # reportInterval can be `daily`, `weekly`, or `monthly`

    # Log report monthly to an email address via SMTP
    - name: secrets-mailer
      type: smtp
      config:
        reportInterval: daily # [optional] reportInterval can be `daily`, `weekly`, or `monthly`, defaults to `daily`
        smtp_destination_addresses: # where is the emailed report being sent to, a list of emails
          - "infosec@example.com"
          - "certificates@example.com"
        smtp_sender_addresses: "ocp-certificate-sentinel+cluster-name@example.com" # what address is it being sent from
        smtp_sender_hostname: "cluster-name.example.com" # client hostname of the sender
        smtp_endpoint: "smtp.example.com:25" # SMTP endpoint, hostname:port format
        smtp_auth_secret: my-smtp-secret-name # name of the Secret containing the SMTP log in credentials
        smtp_auth_type: plain # SMTP authentication type, can be `plain`, `login`, or `cram-md5`
        smtp_use_tls: false # [optional] Enable or disable SMTP TLS - defaults to `true`
  # targets is a list of Kubernetes objects being targeted and scanned for x509 Certificate data
  targets:
    # Target Secrets/v1, looking for certificates with expirations coming in 30, 60, 90, 9000, and 9001 days across all namespaces with a specific serviceaccount
    - apiVersion: v1 # Corresponds to the apiVersion of the object being targeted - likely just v1 for Secrets & ConfigMaps
      daysOut: # [optional] Expiration thresholds for 30, 60, 90, 9000, and 9001 days out - 9000/9001 are for testing.  Defaults to 30, 60, and 90
        - 30
        - 60
        - 90
        - 9001
        - 9000
      kind: Secret # Corresponds to the kind of the object being targeted - Secret or ConfigMap
      name: all-secrets # must be a unique dns/k8s compliant name
      namespaces: # list of namespaces to watch for certificates in Secrets - can be a single wildcard or a list of specific namespaces
        - '*'
      serviceAccount: some-service-account # the ServiceAccount in tis namespace to use against the K8s/OCP API
# .status will be updated at the end of a full scan/operator reconciliation and will list any certificates found, the ones expiring within our designated daysOut thresholds, and when the last reports were sent for each alert
status:
  certificatesAtRisk:
    - triggeredDaysOut:
        - 9001
        - 9000
      certificateAuthorityCommonName: openshift-service-serving-signer@1630120637
      name: kube-scheduler-operator-serving-cert
      expiration: '2023-08-28 03:17:39 +0000 UTC'
      kind: Secret
      dataKey: tls.crt
      isCertificateAuthority: false
      namespace: openshift-kube-scheduler-operator
      apiVersion: v1
  discoveredCertificates:
    - triggeredDaysOut:
        - 9001
        - 9000
      certificateAuthorityCommonName: openshift-service-serving-signer@1630120637
      name: kube-scheduler-operator-serving-cert
      expiration: '2023-08-28 03:17:39 +0000 UTC'
      kind: Secret
      dataKey: tls.crt
      isCertificateAuthority: false
      namespace: openshift-kube-scheduler-operator
      apiVersion: v1
```

### SMTP Configuration

In order to have a CertificateSentinel communicate with an SMTP server, it must be provided some log in parameters - these are stored as a Secret and the name of that Secret is passed to the `.spec.alerts[*].config.smtp_auth_secret` definition.

```bash
## Plain SMTP Authentication Type
export SMTP_USERNAME="someUser"
export SMTP_PASSWORD="securePassword"

oc create secret generic my-smtp-secret-name --from-literal=username=${SMTP_USERNAME} --from-literal=password=${SMTP_PASSWORD}

# Login SMTP Authentication Type
export SMTP_IDENTITY="yourIdentity" # in addition to the SMTP_{USERNAME,PASSWORD} exported vars above
oc create secret generic my-smtp-secret-name --from-literal=username=${SMTP_USERNAME} --from-literal=password=${SMTP_PASSWORD} --from-literal=identity=${SMTP_IDENTITY}

## CRAM-MD5 SMTP Authentication Types
export SMTP_CRAM_MD5="challengeSecret" # in addition to the SMTP_USERNAME exported var above
oc create secret generic my-smtp-secret-name --from-literal=username=${SMTP_USERNAME} --from-literal=cram=${SMTP_CRAM_MD5}
```
# Full CertificateSentinel YAML Spec Example

```yaml
apiVersion: config.polyglot.systems/v1
kind: CertificateSentinel
metadata:
  name: certificatesentinel-sample
  namespace: cert-operator
spec:
  logLevel: 2 # [optional] logLevel is the verbosity of the logger, 1-4 with 4 being the most verbose, defaults to 2
  scanningInterval: 60 # [optional] scanningInterval is the number of seconds the Operator will scan the cluster - default is 60
  alert: # alerts is a list of alerting endpoints associated with these below targets
    # Log report to Stdout once a day, useful for Elastic/Splunk/etc environments
    name: secrets-logger # must be a unique dns/k8s compliant name
    type: logger # type can be: `logger` or `smtp`
    config: # optional on `logger` types, required for `smtp`
      reportInterval: daily # [optional] reportInterval can be `daily`, `weekly`, `monthly`, or `debug`, defaults to `daily`
      smtp_destination_addresses: # where is the emailed report being sent to, a list of emails
        - "infosec@example.com"
        - "certificates@example.com"
      smtp_sender_addresses: "ocp-certificate-sentinel+cluster-name@example.com" # what address is it being sent from
      smtp_sender_hostname: "cluster-name.example.com" # client hostname of the sender
      smtp_endpoint: "smtp.example.com:25" # SMTP endpoint, hostname:port format
      smtp_auth_secret: my-smtp-secret-name # name of the Secret containing the SMTP log in credentials
      smtp_auth_type: plain # SMTP authentication type, can be `plain`, `login`, or `cram-md5`
      smtp_use_tls: false # [optional] Enable or disable SMTP TLS - defaults to `true`
  target: # target is a Kubernetes object being targeted and scanned for x509 Certificate data
    # Target Secrets/v1, looking for certificates with expirations coming in 30, 60, 90, 9000, and 9001 days across all namespaces with a specific serviceaccount
    apiVersion: v1 # Corresponds to the apiVersion of the object being targeted - likely just v1 for Secrets & ConfigMaps
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
status: # .status is not user-defined, it will be updated at the end of a full scan/operator reconciliation and will list any certificates found, the ones expiring within our designated daysOut thresholds, and when the last reports were sent for each alert
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
  lastReportSent: 1632013465
```
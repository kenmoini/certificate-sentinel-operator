# certificate-sentinel-operator

##### Tested on OpenShift 4.8

The Certificate Sentinel Operator allows for the scanning and reporting of SSL Certificates within a Kubernetes/OpenShift cluster.

## Deploying

IDK yet, hold on

## Quickstart

### 1. Create a Namespace

```yaml
---
apiVersion: v1
kind: Namespace
metadata:
  name: cert-sentinel
spec: {}
```

### 2. Create ServiceAccount

```yaml
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: some-service-account
  namespace: cert-sentinel
```

### 3. Create ClusterRoleBindings

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

### 4. Create RoleBindings

#### Targeted to only allow the sa/some-service-account to read in a specific namespace

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

#### Cluster-wide access to secrets

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

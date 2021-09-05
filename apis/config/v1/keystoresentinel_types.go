/*
Copyright 2021 Polyglot Systems.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// KeystoreSentinelSpec defines the desired state of KeystoreSentinel
type KeystoreSentinelSpec struct {
	// Targets is the list of K8s Objects to watch on the cluster
	Targets []KeystoreTarget `json:"targets"`

	// Alerts is where the alerts will be sent to
	Alerts []Alert `json:"alerts"`

	// ScanningInterval is how frequently the controller scans the cluster for these targets - defaults to 30s
	ScanningInterval int `json:"scanningInterval,omitempty"`
}

// KeystoreTarget provide what sort of objects we're watching for, be that a ConfigMap or a Secret
type KeystoreTarget struct {
	// TargetName is a simple DNS/k8s compliant name for identification purposes
	TargetName string `json:"name"`
	// Namespaces is the slice of namespaces to watch on the cluster - can be a single wildcard to watch all namespaces
	Namespaces []string `json:"namespaces"`
	// Kind can be either ConfigMap or Secret
	Kind string `json:"kind"`
	// APIVersion corresponds to the target kind apiVersion, so v1 is all really
	APIVersion string `json:"apiVersion"`
	// Labels is an optional slice of key pair labels to target, which will limit the scope of the matched objects to only ones with those labels
	Labels []string `json:"labels,omitempty"`
	// ServiceAccount is the ServiceAccount to use in order to scan the cluster - this allows for separate RBAC per targeted object
	ServiceAccount string `json:"serviceAccount"`
	// DaysOut is the slice of days out alerts should be triggered at.  Defaults to 30, 60, and 90
	DaysOut []int `json:"daysOut,omitempty"`
	// KeystorePassword corresponds to the source for the the KeystorePassword
	KeystorePassword KeystorePassword `json:"keystorePassword"`
}

// KeystorePassword provides the input for the Keystore Password
type KeystorePassword struct {
	// Type could be 'secret' or 'list'
	Type   string          `json:"type"`
	List   []string        `json:"list,omitempty"`
	Secret SecretReference `json:"secret,omitempty"`
}

// SecretReference provides the internal Secret reference to unlock the Keystore
type SecretReference struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// KeystoreSentinelStatus defines the observed state of KeystoreSentinel
type KeystoreSentinelStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	DiscoveredKeystores []DiscoveredKeystore `json:"discoveredKeystores"`
	// KeystoresAtRisk is the slice of CertificateInformation that list the discovered certificates that are about to expire
	KeystoresAtRisk []KeystoreAtRisk `json:"keystoresAtRisk"`
	// LastReportsSent is the collection of target alert reports that have been sent out by this Operator controller and when
	LastReportsSent []LastReportSent `json:"lastReportsSent,omitempty"`
}

// DiscoveredKeystore provides the status structure of what keystores have certificates that have been discovered on the cluster
type DiscoveredKeystore struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
}

// KeystoreAtRisk provides the status structure of what keystores have certificates that are about to expire and from what CA
type KeystoreAtRisk struct {
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Expiration string `json:"expiration"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// KeystoreSentinel is the Schema for the keystoresentinels API
type KeystoreSentinel struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KeystoreSentinelSpec   `json:"spec,omitempty"`
	Status KeystoreSentinelStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// KeystoreSentinelList contains a list of KeystoreSentinel
type KeystoreSentinelList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeystoreSentinel `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KeystoreSentinel{}, &KeystoreSentinelList{})
}

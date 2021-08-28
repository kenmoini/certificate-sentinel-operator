/*
Copyright 2021 Ken Moini.

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
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Namespaces is the list of namespaces to watch on the cluster - can be a single wildcard to watch all namespaces
	Namespaces []string `json:"namespaces"`

	// Targets is the list of K8s Objects to watch on the cluster - can be the following: ConfigMap, Secret
	Targets []Targets `json:"targets"`

	// Alerts is where the alerts will be sent to
	Alerts []Alert `json:"alerts"`
}

// KeystoreSentinelStatus defines the observed state of KeystoreSentinel
type KeystoreSentinelStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	DiscoveredKeystores []DiscoveredKeystores `json:"discoveredKeystores"`
	KeystoresAtRisk     []KeystoresAtRisk     `json:"keystoresAtRisk"`
}

// DiscoveredKeystores provides the status structure of what keystores have certificates that have been discovered on the cluster
type DiscoveredKeystores struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
}

// KeystoresAtRisk provides the status structure of what keystores have certificates that are about to expire and from what CA
type KeystoresAtRisk struct {
	Namespace                      string `json:"namespace"`
	Name                           string `json:"name"`
	Kind                           string `json:"kind"`
	Expiration                     string `json:"expiration"`
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

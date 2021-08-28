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

// CertificateSentinelSpec defines the desired state of CertificateSentinel
type CertificateSentinelSpec struct {
	// Targets is the slice of K8s Objects to watch on the cluster and with what ServiceAccount
	Targets []Targets `json:"targets"`

	// Alerts is where the alerts will be sent to
	Alerts []Alert `json:"alerts"`
}

// Targets provide what sort of objects we're watching for, be that a ConfigMap or a Secret
type Targets struct {
	// Namespaces is the slice of namespaces to watch on the cluster - can be a single wildcard to watch all namespaces
	Namespaces []string `json:"namespaces"`
	// Kind can be either ConfigMap or Secret
	Kind           string   `json:"kind"`
	// APIVersion corresponds to the target kind apiVersion, so v1 is all really
	APIVersion     string   `json:"apiVersion"`
	// Labels is an optional slice of key pair labels to target, which will limit the scope of the matched objects to only ones with those labels
	Labels         []string `json:"labels,omitempty"`
	// ServiceAccount is the ServiceAccount to use in order to scan the cluster - this allows for separate RBAC per targeted object
	ServiceAccount string   `json:"serviceAccount"`
}

// Alert provides the structure of the type of Alert
type Alert struct {
	// AlertType - valid values are: 'email' and 'logger'
	AlertType          string             `json:"type"`
	// AlertName is a simple DNS/k8s compliant name for identification purposes
	AlertName          string             `json:"name"`
	// AlertConfiguration is optional when only using `logger` as the AlertType, but with SMTP it must be defined
	AlertConfiguration AlertConfiguration `json:"config,omitempty"`
}

// AlertConfiguration provides the structure of the AlertConfigurations for different Alert Endpoints
type AlertConfiguration struct {
	// DaysOut is the slice of days out alerts should be triggered at.  Defaults to 30, 60, and 90
	DaysOut []int32 `json:"daysOut,omitempty"`
	// ReportInterval is the frequency in which Reports would be sent out - can be `daily`, `weekly`, or `monthly`.  Defaults to daily.
	ReportInterval string `json:"reportInterval,omitempty"`
	// SMTPDestinationEmailAddress is where the alert messages will be sent TO
	SMTPDestinationEmailAddress string `json:"smtp_destination_address,omitempty"`
	// SMTPSenderEmailAddress is the address that will be used to send the alert messages
	SMTPSenderEmailAddress string `json:"smtp_sender_address,omitempty"`
	// SMTPSenderHostname is the hostname used during SMTP handshake
	SMTPSenderHostname string `json:"smtp_sender_hostname,omitempty"`
	// SMTPEndpoint is the SMTP server with affixed port ie, smtp.example.com:25
	SMTPEndpoint string `json:"smtp_endpoint,omitempty"`
	// SMTPAuthSecretName is the name of the K8s Secret that holds the authentication information
	SMTPAuthSecretName string `json:"smtp_auth_secret,omitempty"`
	// SMTPAuthType can be either `plain`, `login`, or `cram-md5`
	SMTPAuthType string `json:"smtp_auth_type,omitempty"`
	// SMTPAuthUseTLS can be used to set the use of TLS
	SMTPAuthUseTLS bool `json:"smtp_use_tls,omitempty"`
	// Moved to K8s Secret
	// SMTPAuthUsername string `json:"smtp_auth_username,omitempty"`
	// SMTPAuthPassword string `json:"smtp_auth_password,omitempty"`
	// SMTPAuthIdentity string `json:"smtp_auth_identity,omitempty"`
	// SMTPAuthSecret string `json:"smtp_auth_secret,omitempty"`
}

// CertificateSentinelStatus defines the observed state of CertificateSentinel
type CertificateSentinelStatus struct {
	// DiscoveredCertificates is the slice of CertificateInformation that list the total set of discovered certificates
	DiscoveredCertificates []CertificateInformation `json:"discoveredCertificates"`
	// CertificatesAtRisk is the slice of CertificateInformation that list the discovered certificates that are about to expire
	CertificatesAtRisk     []CertificateInformation     `json:"certificatesAtRisk"`
}

// CertificateInformation provides the status structure of what certificates have been discovered on the cluster
type CertificateInformation struct {
	// Namespace provides what namespace the certificate object was found in
	Namespace                      string `json:"namespace"`
	// Name provides the name of the certificate object
	Name                           string `json:"name"`
	// Kind provides the kind of the certificate object
	Kind                           string `json:"kind"`
	// Expiration is the expiration date in YYYY-MM-DD
	Expiration                     string `json:"expiration"`
	// CertificateAuthorityCommonName provides the Common Name of the signing Certificate Authority
	CertificateAuthorityCommonName string `json:"certificateAuthorityCommonName"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// CertificateSentinel is the Schema for the certificatesentinels API
type CertificateSentinel struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CertificateSentinelSpec   `json:"spec,omitempty"`
	Status CertificateSentinelStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// CertificateSentinelList contains a slice of CertificateSentinel
type CertificateSentinelList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CertificateSentinel `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CertificateSentinel{}, &CertificateSentinelList{})
}

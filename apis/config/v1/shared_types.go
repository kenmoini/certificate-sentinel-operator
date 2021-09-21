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
	//"time"
)

// TimeSlices is just a simple TimeSlice slice
type TimeSlices []TimeSlice

// TimeSlice provides the k:v pairing for expiration dates and what daysOut gate triggered it
type TimeSlice struct {
	Time    metav1.Time
	DaysOut int
}

// LabelSelector is a struct to target specific assets with matching labels
type LabelSelector struct {
	Key    string   `json:"key"`
	Filter string   `json:"filter,omitempty"`
	Values []string `json:"value"`
}

// Alert provides the structure of the type of Alert
type Alert struct {
	// AlertType - valid values are: 'email' and 'logger'
	AlertType string `json:"type"`
	// AlertName is a simple DNS/k8s compliant name for identification purposes
	AlertName string `json:"name"`
	// AlertConfiguration is optional when only using `logger` as the AlertType, but with SMTP it must be defined
	AlertConfiguration AlertConfiguration `json:"config,omitempty"`
}

// AlertConfiguration provides the structure of the AlertConfigurations for different Alert Endpoints
type AlertConfiguration struct {
	// ReportInterval is the frequency in which Reports would be sent out - can be `daily`, `weekly`, `monthly`, or `debug` which is every 5 minutes.  Defaults to daily.
	ReportInterval string `json:"reportInterval,omitempty"`
	// SMTPDestinationEmailAddresses is where the alert messages will be sent TO
	SMTPDestinationEmailAddresses []string `json:"smtp_destination_addresses,omitempty"`
	// SMTPSenderEmailAddress is the address that will be used to send the alert messages
	SMTPSenderEmailAddress string `json:"smtp_sender_address,omitempty"`
	// SMTPSenderHostname is the hostname used during SMTP handshake
	SMTPSenderHostname string `json:"smtp_sender_hostname,omitempty"`
	// SMTPEndpoint is the SMTP server with affixed port ie, smtp.example.com:25
	SMTPEndpoint string `json:"smtp_endpoint,omitempty"`
	// SMTPAuthSecretName is the name of the K8s Secret that holds the authentication information
	SMTPAuthSecretName string `json:"smtp_auth_secret,omitempty"`
	// SMTPAuthType can be either `none`, `plain`, `login`, or `cram-md5`
	SMTPAuthType string `json:"smtp_auth_type,omitempty"`
	// SMTPAuthUseSSL can be used to set the use of TLS, default is true
	SMTPAuthUseSSL *bool `json:"smtp_use_ssl,omitempty"`
	// SMTPAuthUseSTARTTLS can be used to set the use of STARTTLS, default is true
	SMTPAuthUseSTARTTLS *bool `json:"smtp_use_starttls,omitempty"`
}

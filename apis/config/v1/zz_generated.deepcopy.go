//go:build !ignore_autogenerated
// +build !ignore_autogenerated

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

// Code generated by controller-gen. DO NOT EDIT.

package v1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Alert) DeepCopyInto(out *Alert) {
	*out = *in
	in.AlertConfiguration.DeepCopyInto(&out.AlertConfiguration)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Alert.
func (in *Alert) DeepCopy() *Alert {
	if in == nil {
		return nil
	}
	out := new(Alert)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AlertConfiguration) DeepCopyInto(out *AlertConfiguration) {
	*out = *in
	if in.SMTPDestinationEmailAddresses != nil {
		in, out := &in.SMTPDestinationEmailAddresses, &out.SMTPDestinationEmailAddresses
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.SMTPAuthUseTLS != nil {
		in, out := &in.SMTPAuthUseTLS, &out.SMTPAuthUseTLS
		*out = new(bool)
		**out = **in
	}
	if in.SMTPAuthUseSTARTTLS != nil {
		in, out := &in.SMTPAuthUseSTARTTLS, &out.SMTPAuthUseSTARTTLS
		*out = new(bool)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AlertConfiguration.
func (in *AlertConfiguration) DeepCopy() *AlertConfiguration {
	if in == nil {
		return nil
	}
	out := new(AlertConfiguration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertificateInformation) DeepCopyInto(out *CertificateInformation) {
	*out = *in
	if in.TriggeredDaysOut != nil {
		in, out := &in.TriggeredDaysOut, &out.TriggeredDaysOut
		*out = make([]int, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertificateInformation.
func (in *CertificateInformation) DeepCopy() *CertificateInformation {
	if in == nil {
		return nil
	}
	out := new(CertificateInformation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertificateSentinel) DeepCopyInto(out *CertificateSentinel) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertificateSentinel.
func (in *CertificateSentinel) DeepCopy() *CertificateSentinel {
	if in == nil {
		return nil
	}
	out := new(CertificateSentinel)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CertificateSentinel) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertificateSentinelList) DeepCopyInto(out *CertificateSentinelList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]CertificateSentinel, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertificateSentinelList.
func (in *CertificateSentinelList) DeepCopy() *CertificateSentinelList {
	if in == nil {
		return nil
	}
	out := new(CertificateSentinelList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CertificateSentinelList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertificateSentinelSpec) DeepCopyInto(out *CertificateSentinelSpec) {
	*out = *in
	if in.Targets != nil {
		in, out := &in.Targets, &out.Targets
		*out = make([]Targets, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Alerts != nil {
		in, out := &in.Alerts, &out.Alerts
		*out = make([]Alert, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertificateSentinelSpec.
func (in *CertificateSentinelSpec) DeepCopy() *CertificateSentinelSpec {
	if in == nil {
		return nil
	}
	out := new(CertificateSentinelSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertificateSentinelStatus) DeepCopyInto(out *CertificateSentinelStatus) {
	*out = *in
	if in.DiscoveredCertificates != nil {
		in, out := &in.DiscoveredCertificates, &out.DiscoveredCertificates
		*out = make([]CertificateInformation, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.CertificatesAtRisk != nil {
		in, out := &in.CertificatesAtRisk, &out.CertificatesAtRisk
		*out = make([]CertificateInformation, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.LastReportsSent != nil {
		in, out := &in.LastReportsSent, &out.LastReportsSent
		*out = make([]LastReportSent, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertificateSentinelStatus.
func (in *CertificateSentinelStatus) DeepCopy() *CertificateSentinelStatus {
	if in == nil {
		return nil
	}
	out := new(CertificateSentinelStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DiscoveredKeystores) DeepCopyInto(out *DiscoveredKeystores) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DiscoveredKeystores.
func (in *DiscoveredKeystores) DeepCopy() *DiscoveredKeystores {
	if in == nil {
		return nil
	}
	out := new(DiscoveredKeystores)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *KeystoreSentinel) DeepCopyInto(out *KeystoreSentinel) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new KeystoreSentinel.
func (in *KeystoreSentinel) DeepCopy() *KeystoreSentinel {
	if in == nil {
		return nil
	}
	out := new(KeystoreSentinel)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *KeystoreSentinel) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *KeystoreSentinelList) DeepCopyInto(out *KeystoreSentinelList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]KeystoreSentinel, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new KeystoreSentinelList.
func (in *KeystoreSentinelList) DeepCopy() *KeystoreSentinelList {
	if in == nil {
		return nil
	}
	out := new(KeystoreSentinelList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *KeystoreSentinelList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *KeystoreSentinelSpec) DeepCopyInto(out *KeystoreSentinelSpec) {
	*out = *in
	if in.Namespaces != nil {
		in, out := &in.Namespaces, &out.Namespaces
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Targets != nil {
		in, out := &in.Targets, &out.Targets
		*out = make([]Targets, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Alerts != nil {
		in, out := &in.Alerts, &out.Alerts
		*out = make([]Alert, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new KeystoreSentinelSpec.
func (in *KeystoreSentinelSpec) DeepCopy() *KeystoreSentinelSpec {
	if in == nil {
		return nil
	}
	out := new(KeystoreSentinelSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *KeystoreSentinelStatus) DeepCopyInto(out *KeystoreSentinelStatus) {
	*out = *in
	if in.DiscoveredKeystores != nil {
		in, out := &in.DiscoveredKeystores, &out.DiscoveredKeystores
		*out = make([]DiscoveredKeystores, len(*in))
		copy(*out, *in)
	}
	if in.KeystoresAtRisk != nil {
		in, out := &in.KeystoresAtRisk, &out.KeystoresAtRisk
		*out = make([]KeystoresAtRisk, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new KeystoreSentinelStatus.
func (in *KeystoreSentinelStatus) DeepCopy() *KeystoreSentinelStatus {
	if in == nil {
		return nil
	}
	out := new(KeystoreSentinelStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *KeystoresAtRisk) DeepCopyInto(out *KeystoresAtRisk) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new KeystoresAtRisk.
func (in *KeystoresAtRisk) DeepCopy() *KeystoresAtRisk {
	if in == nil {
		return nil
	}
	out := new(KeystoresAtRisk)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LastReportSent) DeepCopyInto(out *LastReportSent) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LastReportSent.
func (in *LastReportSent) DeepCopy() *LastReportSent {
	if in == nil {
		return nil
	}
	out := new(LastReportSent)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Targets) DeepCopyInto(out *Targets) {
	*out = *in
	if in.Namespaces != nil {
		in, out := &in.Namespaces, &out.Namespaces
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Labels != nil {
		in, out := &in.Labels, &out.Labels
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.DaysOut != nil {
		in, out := &in.DaysOut, &out.DaysOut
		*out = make([]int, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Targets.
func (in *Targets) DeepCopy() *Targets {
	if in == nil {
		return nil
	}
	out := new(Targets)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TimeSlice) DeepCopyInto(out *TimeSlice) {
	*out = *in
	in.Time.DeepCopyInto(&out.Time)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TimeSlice.
func (in *TimeSlice) DeepCopy() *TimeSlice {
	if in == nil {
		return nil
	}
	out := new(TimeSlice)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in TimeSlices) DeepCopyInto(out *TimeSlices) {
	{
		in := &in
		*out = make(TimeSlices, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TimeSlices.
func (in TimeSlices) DeepCopy() TimeSlices {
	if in == nil {
		return nil
	}
	out := new(TimeSlices)
	in.DeepCopyInto(out)
	return *out
}

// Package helpers contains the supporting functions for the operator at large that are shared
package helpers

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/go-logr/logr"
	configv1 "github.com/kenmoini/certificate-sentinel-operator/apis/config/v1"
)

/*=====================================================================================
| x509 Certificate Helper Functions
=====================================================================================*/

// DecodeCertificateBytes decodes the byte slice from a Secret data item into a PEM and then into an x509 DER object
func DecodeCertificateBytes(s []byte, lggr logr.Logger) ([]*x509.Certificate, error) {
	block, rest := pem.Decode(s)

	// Check to see if this can be decoded into a PEM block
	if block == nil || block.Type != "CERTIFICATE" {
		lggr.Info("Failed to decode PEM block containing a Certificate: " + string(rest))
	}

	// Parse the Certificate
	certs, err := x509.ParseCertificates(block.Bytes)
	if err != nil {
		lggr.Info("Failed to decode certificate!")
		fmt.Printf("Failed to decode certificate %v\n", err)
		return nil, err
	}
	return certs, nil
}

// ParseCertificatesIntoLists takes a slice of certificates and all the other supporting information to create a CertificateInformation return to add to .status/alert report
func ParseCertificatesIntoLists(certs []*x509.Certificate, timeOut []configv1.TimeSlice, namespace string, name string, dataKey string, kind string, apiVersion string, lggr logr.Logger) (discovered []configv1.CertificateInformation, expired []configv1.CertificateInformation) {
	discoveredL := []configv1.CertificateInformation{}
	expiredL := []configv1.CertificateInformation{}
	// Loop over parsed certificates
	for _, cert := range certs {
		var triggeredDaysOut []int
		expirationDate := cert.NotAfter
		// Loop through the timeOut slice, add triggered values to the certInfo config for priority ranking
		for _, d := range timeOut {
			utcTime := d.Time.UTC()
			if utcTime.After(expirationDate) {
				lggr.Info("Certificate will expire in less than " + fmt.Sprint(d.DaysOut) + " days! Date: " + expirationDate.String())
				triggeredDaysOut = append(triggeredDaysOut, d.DaysOut)
			}
		}
		// Create CertificateInformation object
		certInfo := configv1.CertificateInformation{Namespace: namespace, Name: name, DataKey: dataKey, Kind: kind, APIVersion: apiVersion, Expiration: expirationDate.String(), CertificateAuthorityCommonName: cert.Issuer.CommonName, IsCertificateAuthority: cert.IsCA, TriggeredDaysOut: triggeredDaysOut}
		// This certificate is not expired
		discoveredL = append(discoveredL, certInfo)
		if len(triggeredDaysOut) != 0 {
			expiredL = append(expiredL, certInfo)
		}
	}
	return discoveredL, expiredL
}

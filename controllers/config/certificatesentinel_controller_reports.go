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

package config

import (
	"bytes"
	"fmt"
	"github.com/go-logr/logr"
	configv1 "github.com/kenmoini/certificate-sentinel-operator/apis/config/v1"
	defaults "github.com/kenmoini/certificate-sentinel-operator/controllers/defaults"
	corev1 "k8s.io/api/core/v1"
	"math"
	"net"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"strconv"
	"strings"
	"text/template"
	"time"
)

// processReports processes reports for the alerts
func processReports(certificateSentinel configv1.CertificateSentinel, lggr logr.Logger, clnt client.Client) []configv1.LastReportSent {
	// Set up variables
	var totalAlerts []string
	var alreadySentAlerts []string
	var ReportsSentObject []configv1.LastReportSent

	// Loop through Alerts to get all the names
	for _, alert := range certificateSentinel.Spec.Alerts {
		totalAlerts = append(totalAlerts, alert.AlertName)
	}

	// Debug logging lol
	loggerReport := createLoggerReport(certificateSentinel, lggr)
	lggr.Info(loggerReport)
	smtpReport := createSMTPReport(certificateSentinel, lggr, clnt)
	lggr.Info(smtpReport)

	// Check the length of the ReportsSent slice
	if len(certificateSentinel.Status.LastReportsSent) > 0 {
		// Loop through LastReportsSent, add to alreadySentAlerts
		for _, report := range certificateSentinel.Status.LastReportsSent {
			// Check to see if the LastSent date is
			layout := "2006-01-02 15:04:05 -0700 MST"
			t, err := time.Parse(layout, report.LastSent)
			if err != nil {
				fmt.Printf("Error parsing time! %+v\n", err)
			}

			// Loop through alerts to match the reportInterval - this is lazy, there's probably a better way to map this data out
			var effectiveReportInterval string
			for _, alert := range certificateSentinel.Spec.Alerts {
				if alert.AlertName == report.AlertName {
					effectiveReportInterval = defaults.SetDefaultString(defaults.ReportInterval, alert.AlertConfiguration.ReportInterval)
				}
			}
			//var effectiveReportIntervalTime time.Time
			var timeThreshold time.Time
			switch effectiveReportInterval {
			case "weekly":
				timeThreshold = t.AddDate(0, 0, 7)
			case "monthly":
				timeThreshold = t.AddDate(0, 1, 0)
			case "daily":
			default:
				timeThreshold = t.AddDate(0, 0, 1)
			}

			if timeThreshold.Before(time.Now()) {
				alreadySentAlerts = append(alreadySentAlerts, report.AlertName)
			}
		}
	}

	// Get the list of alerts that need to be sent
	if len(totalAlerts) != len(alreadySentAlerts) {
		alertsToSend := differenceInStringSlices(totalAlerts, alreadySentAlerts)

		for _, alert := range certificateSentinel.Spec.Alerts {
			if defaults.ContainsString(alertsToSend, alert.AlertName) {
				lggr.Info("Sending report for " + alert.AlertName)
				// Send out alert based on alert type
				lggr.Info("alert.AlertType " + alert.AlertType)

				switch alert.AlertType {
				case "smtp":
					createSMTPReport(certificateSentinel, lggr, clnt)
				case "logger":
				default:
					lggr.Info("alert.AlertType: logger")
					createLoggerReport(certificateSentinel, lggr)
				}

				lggr.Info("Setting sent report in Status.LastReportsSent for " + alert.AlertName)
				dateSent := time.Now().UTC().String()
				reportInfo := configv1.LastReportSent{AlertName: alert.AlertName, LastSent: dateSent}
				ReportsSentObject = append(ReportsSentObject, reportInfo)
			}
		}
	}

	if len(ReportsSentObject) > 0 {
		lggr.Info("Sent report for " + fmt.Sprint(len(ReportsSentObject)) + " alerts")
		return ReportsSentObject
	}
	lggr.Info("No new reports to send")
	return certificateSentinel.Status.LastReportsSent
}

// createLoggerReport loops through CertificateSentinel.Status and creates a stdout report
func createLoggerReport(certificateSentinel configv1.CertificateSentinel, lggr logr.Logger) string {
	lggr.Info("starting createLoggerReport")
	return createTextTableReport(certificateSentinel, lggr)
}

// createSMTPReport loops through CertificateSentinel.Status and sends an email report
func createSMTPReport(certificateSentinel configv1.CertificateSentinel, lggr logr.Logger, clnt client.Client) string {
	lggr.Info("starting createSMTPReport")

	basicTextEmailReport := createTextTableReport(certificateSentinel, lggr)

	// Loop through the alerts
	for _, alert := range certificateSentinel.Spec.Alerts {
		if alert.AlertType == "smtp" {
			// Set up basic SMTP vars
			var username string
			var password string
			var identity string
			var cramSecret string
			smtpAuthSecret := &corev1.Secret{}

			// Get SMTP Authentication Secret if the AuthType is not `none`
			if alert.AlertConfiguration.SMTPAuthType != "none" {
				smtpAuthSecret, _ = GetSecret(alert.AlertConfiguration.SMTPAuthSecretName, certificateSentinel.Namespace, clnt)
			}

			// Assign SMTP Auth vars where needed
			if len(smtpAuthSecret.Data) > 0 {
				username = string(smtpAuthSecret.Data["username"])
				password = string(smtpAuthSecret.Data["password"])
				identity = string(smtpAuthSecret.Data["identity"])
				cramSecret = string(smtpAuthSecret.Data["cram"])
			}

			// Set up SMTP Auth object
			serverHostname, _, _ := net.SplitHostPort(alert.AlertConfiguration.SMTPEndpoint)
			smtpAuth := setupSMTPAuth(alert.AlertConfiguration.SMTPAuthType,
				username,
				password,
				identity,
				cramSecret,
				serverHostname,
			)

			// Set up SMTP Message
			sendSMTPMessage(smtpAuth,
				alert.AlertConfiguration.SMTPDestinationEmailAddress,
				alert.AlertConfiguration.SMTPSenderEmailAddress,
				alert.AlertConfiguration.SMTPEndpoint,
				basicTextEmailReport,
				"",
				alert.AlertConfiguration.SMTPAuthUseTLS,
			)
		}
	}

	return basicTextEmailReport
}

//============================================================================================  HELPER FUNCTIONS

// returnLonger returns the larger value of lengths between two strings
func returnLonger(currentData string, newData string) string {
	if len(newData) > len(currentData) {
		return newData
	}
	return currentData
}

// StrPad returns the input string padded on the left, right or both sides using padType to the specified padding length padLength.
//
// Example:
// input := "Codes";
// StrPad(input, 10, " ", "RIGHT")        // produces "Codes     "
// StrPad(input, 10, "-=", "LEFT")        // produces "=-=-=Codes"
// StrPad(input, 10, "_", "BOTH")         // produces "__Codes___"
// StrPad(input, 6, "___", "RIGHT")       // produces "Codes_"
// StrPad(input, 3, "*", "RIGHT")         // produces "Codes"
func StrPad(input string, padLength int, padString string, padType string) string {
	var output string

	inputLength := len(input)
	padStringLength := len(padString)

	if inputLength >= padLength {
		return input
	}

	repeat := math.Ceil(float64(1) + (float64(padLength-padStringLength))/float64(padStringLength))

	switch padType {
	case "RIGHT":
		output = input + strings.Repeat(padString, int(repeat))
		output = output[:padLength]
	case "LEFT":
		output = strings.Repeat(padString, int(repeat)) + input
		output = output[len(output)-padLength:]
	case "BOTH":
		length := (float64(padLength - inputLength)) / float64(2)
		repeat = math.Ceil(length / float64(padStringLength))
		output = strings.Repeat(padString, int(repeat))[:int(math.Floor(float64(length)))] + input + strings.Repeat(padString, int(repeat))[:int(math.Ceil(float64(length)))]
	}

	return output
}

// createTextTableReport creates a Text-based table of the report, used in logger reports and text-based SMTP reports
func createTextTableReport(certificateSentinel configv1.CertificateSentinel, lggr logr.Logger) string {
	currentConfig, _ := config.GetConfig()
	clusterEndpoint := currentConfig.Host
	apiPath := currentConfig.APIPath

	// Set up init vars
	var reportLines string
	APIVersionLongest := "APIVersion"
	KindLongest := "Kind"
	NamespaceLongest := "Namespace"
	NameLongest := "Name"
	DataKeyLongest := "Data Key"
	IsCALongest := "Is CA"
	CACNLongest := "Signing CA CN"
	ExpirationDateLongest := "Expiration Date"
	TriggeredDaysOutLongest := "Triggered Days Out"

	// Loop through the .status.CertificatesAtRisk
	for _, certInfo := range certificateSentinel.Status.CertificatesAtRisk {
		// Set up Logger Lines for length
		APIVersionLongest = returnLonger(APIVersionLongest, certInfo.APIVersion)
		KindLongest = returnLonger(KindLongest, certInfo.Kind)
		NamespaceLongest = returnLonger(NamespaceLongest, certInfo.Namespace)
		NameLongest = returnLonger(NameLongest, certInfo.Name)
		DataKeyLongest = returnLonger(DataKeyLongest, certInfo.DataKey)
		IsCALongest = returnLonger(IsCALongest, strconv.FormatBool(certInfo.IsCertificateAuthority))
		CACNLongest = returnLonger(CACNLongest, certInfo.CertificateAuthorityCommonName)
		ExpirationDateLongest = returnLonger(ExpirationDateLongest, certInfo.Expiration)
		TriggeredDaysOutLongest = returnLonger(TriggeredDaysOutLongest, strings.Trim(strings.Join(strings.Fields(fmt.Sprint(certInfo.TriggeredDaysOut)), ", "), "[]"))
	}

	// Set the longest length value
	APIVersionLength := len(APIVersionLongest)
	KindLength := len(KindLongest)
	NamespaceLength := len(NamespaceLongest)
	NameLength := len(NameLongest)
	DataKeyLength := len(DataKeyLongest)
	IsCALength := len(IsCALongest)
	CACNLength := len(CACNLongest)
	ExpirationDateLength := len(ExpirationDateLongest)
	TriggeredDaysOutLength := len(TriggeredDaysOutLongest)
	TotalLineLength := (APIVersionLength + KindLength + NamespaceLength + NameLength + DataKeyLength + IsCALength + CACNLength + ExpirationDateLength + TriggeredDaysOutLength + 28)
	LineBreak := StrPad("-", TotalLineLength, "-", "BOTH")

	// Loop through the .status.CertificatesAtRisk
	for _, certInfo := range certificateSentinel.Status.CertificatesAtRisk {
		// Set up Logger Lines
		loggerReportLineStructure := LoggerReportLineStructure{
			APIVersion:                     StrPad(certInfo.APIVersion, APIVersionLength, " ", "BOTH"),
			Kind:                           StrPad(certInfo.Kind, KindLength, " ", "BOTH"),
			Namespace:                      StrPad(certInfo.Namespace, NamespaceLength, " ", "BOTH"),
			Name:                           StrPad(certInfo.Name, NameLength, " ", "BOTH"),
			Key:                            StrPad(certInfo.DataKey, DataKeyLength, " ", "BOTH"),
			IsCA:                           StrPad(strconv.FormatBool(certInfo.IsCertificateAuthority), IsCALength, " ", "BOTH"),
			CertificateAuthorityCommonName: StrPad(certInfo.CertificateAuthorityCommonName, CACNLength, " ", "BOTH"),
			ExpirationDate:                 StrPad(certInfo.Expiration, ExpirationDateLength, " ", "BOTH"),
			TriggeredDaysOut:               StrPad(strings.Trim(strings.Join(strings.Fields(fmt.Sprint(certInfo.TriggeredDaysOut)), ", "), "[]"), TriggeredDaysOutLength, " ", "BOTH"),
		}
		lineBuf := new(bytes.Buffer)
		loggerLineTemplate, err := template.New("loggerLine").Parse(LoggerReportLine)
		if err != nil {
			lggr.Info("Error parsing loggerLineTemplate template!")
		}
		err = loggerLineTemplate.Execute(lineBuf, loggerReportLineStructure)
		if err != nil {
			lggr.Info("Error executing loggerLineTemplate template!")
		}
		// Append to total reportLines
		reportLines = (reportLines + lineBuf.String())
	}

	// Setup Logger Headers
	loggerReportHeaderStructure := LoggerReportHeaderStructure{
		APIVersion:                     StrPad("APIVersion", APIVersionLength, " ", "BOTH"),
		Kind:                           StrPad("Kind", KindLength, " ", "BOTH"),
		Namespace:                      StrPad("Namespace", NamespaceLength, " ", "BOTH"),
		Name:                           StrPad("Name", NameLength, " ", "BOTH"),
		Key:                            StrPad("Data Key", DataKeyLength, " ", "BOTH"),
		IsCA:                           StrPad("Is CA", IsCALength, " ", "BOTH"),
		CertificateAuthorityCommonName: StrPad("Signing CA CN", CACNLength, " ", "BOTH"),
		ExpirationDate:                 StrPad("Expiration Date", ExpirationDateLength, " ", "BOTH"),
		TriggeredDaysOut:               StrPad("Triggered Days Out", TriggeredDaysOutLength, " ", "BOTH"),
	}
	headerBuf := new(bytes.Buffer)
	loggerHeaderTemplate, err := template.New("loggerHeader").Parse(LoggerReportHeader)
	if err != nil {
		lggr.Info("Error parsing loggerHeaderTemplate template!")
	}
	err = loggerHeaderTemplate.Execute(headerBuf, loggerReportHeaderStructure)
	if err != nil {
		lggr.Info("Error executing loggerHeaderTemplate template!")
	}

	// Set up Logger Report
	loggerReportStructure := LoggerReportStructure{
		Namespace:          certificateSentinel.Namespace,
		Name:               certificateSentinel.Name,
		DateSent:           time.Now().UTC().String(),
		ClusterAPIEndpoint: clusterEndpoint + apiPath,
		TotalCerts:         strconv.Itoa(len(certificateSentinel.Status.DiscoveredCertificates)),
		ExpiringCerts:      strconv.Itoa(len(certificateSentinel.Status.CertificatesAtRisk)),
		ReportLines:        reportLines,
		Footer:             headerBuf.String(),
		Header:             headerBuf.String(),
		Divider:            LineBreak,
	}
	reportBuf := new(bytes.Buffer)
	loggerReportTemplate, err := template.New("loggerReport").Parse(LoggerReport)
	if err != nil {
		lggr.Error(err, "Error parsing loggerReportTemplate template!")
	}
	err = loggerReportTemplate.Execute(reportBuf, loggerReportStructure)
	if err != nil {
		lggr.Error(err, "Error executing loggerReportTemplate template!")
	}

	return reportBuf.String()
}

// differenceInStringSlices returns a []string of the unique items between two []string
func differenceInStringSlices(slice1 []string, slice2 []string) []string {
	var diff []string

	// Loop two times, first to find slice1 strings not in slice2,
	// second loop to find slice2 strings not in slice1
	for i := 0; i < 2; i++ {
		for _, s1 := range slice1 {
			found := false
			for _, s2 := range slice2 {
				if s1 == s2 {
					found = true
					break
				}
			}
			// String not found. We add it to return slice
			if !found {
				diff = append(diff, s1)
			}
		}
		// Swap the slices, only if it was the first loop
		if i == 0 {
			slice1, slice2 = slice2, slice1
		}
	}

	return diff
}

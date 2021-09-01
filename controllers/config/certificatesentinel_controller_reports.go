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
	//loggerReport := createLoggerReport(certificateSentinel, lggr)
	//lggr.Info(loggerReport)
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
	currentConfig, _ := config.GetConfig()
	clusterEndpoint := currentConfig.Host
	apiPath := currentConfig.APIPath

	var reportLines string

	// Loop through the .status.CertificatesAtRisk
	for _, certInfo := range certificateSentinel.Status.CertificatesAtRisk {
		// Set up Logger Lines
		loggerReportLineStructure := LoggerReportLineStructure{
			APIVersion:                     certInfo.APIVersion,
			Kind:                           certInfo.Kind,
			Namespace:                      certInfo.Namespace,
			Name:                           certInfo.Name,
			Key:                            certInfo.DataKey,
			IsCA:                           strconv.FormatBool(certInfo.IsCertificateAuthority),
			CertificateAuthorityCommonName: certInfo.CertificateAuthorityCommonName,
			ExpirationDate:                 certInfo.Expiration,
			TriggeredDaysOut:               strings.Trim(strings.Join(strings.Fields(fmt.Sprint(certInfo.TriggeredDaysOut)), ", "), "[]"),
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

	// Set up Logger Report
	loggerReportStructure := LoggerReportStructure{
		Namespace:          certificateSentinel.Namespace,
		Name:               certificateSentinel.Name,
		DateSent:           time.Now().UTC().String(),
		ClusterAPIEndpoint: clusterEndpoint + apiPath,
		TotalCerts:         strconv.Itoa(len(certificateSentinel.Status.DiscoveredCertificates)),
		ExpiringCerts:      strconv.Itoa(len(certificateSentinel.Status.CertificatesAtRisk)),
		ReportLines:        reportLines,
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
	//lggr.Info(reportBuf.String())

	return reportBuf.String()
}

// createSMTPReport loops through CertificateSentinel.Status and sends an email report
func createSMTPReport(certificateSentinel configv1.CertificateSentinel, lggr logr.Logger, clnt client.Client) string {
	lggr.Info("starting createSMTPReport")
	currentConfig, _ := config.GetConfig()
	clusterEndpoint := currentConfig.Host
	apiPath := currentConfig.APIPath

	var reportLines string

	// Loop through the .status.CertificatesAtRisk
	for _, certInfo := range certificateSentinel.Status.CertificatesAtRisk {
		// Set up Logger Lines
		loggerReportLineStructure := LoggerReportLineStructure{
			APIVersion:                     certInfo.APIVersion,
			Kind:                           certInfo.Kind,
			Namespace:                      certInfo.Namespace,
			Name:                           certInfo.Name,
			Key:                            certInfo.DataKey,
			IsCA:                           strconv.FormatBool(certInfo.IsCertificateAuthority),
			CertificateAuthorityCommonName: certInfo.CertificateAuthorityCommonName,
			ExpirationDate:                 certInfo.Expiration,
			TriggeredDaysOut:               strings.Trim(strings.Join(strings.Fields(fmt.Sprint(certInfo.TriggeredDaysOut)), ", "), "[]"),
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

	// Set up Logger Report
	loggerReportStructure := LoggerReportStructure{
		Namespace:          certificateSentinel.Namespace,
		Name:               certificateSentinel.Name,
		DateSent:           time.Now().UTC().String(),
		ClusterAPIEndpoint: clusterEndpoint + apiPath,
		TotalCerts:         strconv.Itoa(len(certificateSentinel.Status.DiscoveredCertificates)),
		ExpiringCerts:      strconv.Itoa(len(certificateSentinel.Status.CertificatesAtRisk)),
		ReportLines:        reportLines,
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

	basicTextEmailReport := reportBuf.String()

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
			smtpAuth := setupSMTPAuth(alert.AlertConfiguration.SMTPAuthType,
				username,
				password,
				identity,
				cramSecret,
				alert.AlertConfiguration.SMTPEndpoint,
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

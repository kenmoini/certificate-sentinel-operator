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

package config

import (
	"bytes"
	"fmt"
	"github.com/go-logr/logr"
	configv1 "github.com/kenmoini/certificate-sentinel-operator/apis/config/v1"
	defaults "github.com/kenmoini/certificate-sentinel-operator/controllers/defaults"
	helpers "github.com/kenmoini/certificate-sentinel-operator/controllers/helpers"
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
	//smtpReport := createSMTPReport(certificateSentinel, lggr, clnt)
	//lggr.Info(smtpReport)

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
	//if len(totalAlerts) != len(alreadySentAlerts) {
	alertsToSend := helpers.DifferenceInStringSlices(totalAlerts, alreadySentAlerts)

	for _, alert := range certificateSentinel.Spec.Alerts {
		if defaults.ContainsString(alertsToSend, alert.AlertName) {
			lggr.Info("Dispatching report for " + alert.AlertName)
			// Send out alert based on alert type

			switch alert.AlertType {
			case "smtp":
				createSMTPReport(certificateSentinel, lggr, clnt)
			case "logger":
			default:
				lggr.Info(createLoggerReport(certificateSentinel, lggr))
			}

			lggr.Info("Setting dispatched report in Status.LastReportsSent for " + alert.AlertName)
			dateSent := time.Now().UTC().String()
			reportInfo := configv1.LastReportSent{AlertName: alert.AlertName, LastSent: dateSent}
			ReportsSentObject = append(ReportsSentObject, reportInfo)
		}
	}
	//}

	if len(ReportsSentObject) > 0 {
		lggr.Info("Sent report for " + fmt.Sprint(len(ReportsSentObject)) + " alerts")
		return append(ReportsSentObject, certificateSentinel.Status.LastReportsSent...)
	}
	lggr.Info("No new reports to send")
	return certificateSentinel.Status.LastReportsSent
}

// createLoggerReport loops through CertificateSentinel.Status and creates a stdout report
func createLoggerReport(certificateSentinel configv1.CertificateSentinel, lggr logr.Logger) string {
	return createTextTableReport(certificateSentinel, lggr)
}

// createSMTPReport loops through CertificateSentinel.Status and sends an email report
func createSMTPReport(certificateSentinel configv1.CertificateSentinel, lggr logr.Logger, clnt client.Client) string {

	textEmailReport := tableTextReportToBasicHTMLReport(createTextTableReport(certificateSentinel, lggr))
	htmlEmailReport := createSMTPHTMLReport(certificateSentinel, lggr)

	// Loop through the alerts
	for _, alert := range certificateSentinel.Spec.Alerts {
		if alert.AlertType == "smtp" {
			// Set up basic SMTP vars
			var username string
			var password string
			var identity string
			var cramSecret string

			// Set defaults
			useTLS := defaults.SetDefaultBool(&defaults.SMTPAuthUseTLS, alert.AlertConfiguration.SMTPAuthUseTLS)
			useSTARTTLS := defaults.SetDefaultBool(&defaults.SMTPAuthUseSTARTTLS, alert.AlertConfiguration.SMTPAuthUseSTARTTLS)

			// Get SMTP Authentication Secret if the AuthType is not `none`
			smtpAuthSecret := &corev1.Secret{}
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

			// Send the message
			sendSMTPMail(alert.AlertConfiguration.SMTPAuthType,
				username,
				password,
				identity,
				cramSecret,
				useTLS,
				useSTARTTLS,
				alert.AlertConfiguration.SMTPDestinationEmailAddresses,
				alert.AlertConfiguration.SMTPSenderEmailAddress,
				alert.AlertConfiguration.SMTPEndpoint,
				textEmailReport,
				htmlEmailReport)
		}
	}

	return textEmailReport
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
		APIVersionLongest = helpers.ReturnLonger(APIVersionLongest, certInfo.APIVersion)
		KindLongest = helpers.ReturnLonger(KindLongest, certInfo.Kind)
		NamespaceLongest = helpers.ReturnLonger(NamespaceLongest, certInfo.Namespace)
		NameLongest = helpers.ReturnLonger(NameLongest, certInfo.Name)
		DataKeyLongest = helpers.ReturnLonger(DataKeyLongest, certInfo.DataKey)
		IsCALongest = helpers.ReturnLonger(IsCALongest, strconv.FormatBool(certInfo.IsCertificateAuthority))
		CACNLongest = helpers.ReturnLonger(CACNLongest, certInfo.CertificateAuthorityCommonName)
		ExpirationDateLongest = helpers.ReturnLonger(ExpirationDateLongest, certInfo.Expiration)
		TriggeredDaysOutLongest = helpers.ReturnLonger(TriggeredDaysOutLongest, strings.Trim(strings.Join(strings.Fields(fmt.Sprint(certInfo.TriggeredDaysOut)), ", "), "[]"))
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
	LineBreak := helpers.StrPad("-", TotalLineLength, "-", "BOTH")

	// Loop through the .status.CertificatesAtRisk
	for _, certInfo := range certificateSentinel.Status.CertificatesAtRisk {
		// Set up Logger Lines
		loggerReportLineStructure := LoggerReportLineStructure{
			APIVersion:                     helpers.StrPad(certInfo.APIVersion, APIVersionLength, " ", "BOTH"),
			Kind:                           helpers.StrPad(certInfo.Kind, KindLength, " ", "BOTH"),
			Namespace:                      helpers.StrPad(certInfo.Namespace, NamespaceLength, " ", "BOTH"),
			Name:                           helpers.StrPad(certInfo.Name, NameLength, " ", "BOTH"),
			Key:                            helpers.StrPad(certInfo.DataKey, DataKeyLength, " ", "BOTH"),
			IsCA:                           helpers.StrPad(strconv.FormatBool(certInfo.IsCertificateAuthority), IsCALength, " ", "BOTH"),
			CertificateAuthorityCommonName: helpers.StrPad(certInfo.CertificateAuthorityCommonName, CACNLength, " ", "BOTH"),
			ExpirationDate:                 helpers.StrPad(certInfo.Expiration, ExpirationDateLength, " ", "BOTH"),
			TriggeredDaysOut:               helpers.StrPad(strings.Trim(strings.Join(strings.Fields(fmt.Sprint(certInfo.TriggeredDaysOut)), ", "), "[]"), TriggeredDaysOutLength, " ", "BOTH"),
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
		APIVersion:                     helpers.StrPad("APIVersion", APIVersionLength, " ", "BOTH"),
		Kind:                           helpers.StrPad("Kind", KindLength, " ", "BOTH"),
		Namespace:                      helpers.StrPad("Namespace", NamespaceLength, " ", "BOTH"),
		Name:                           helpers.StrPad("Name", NameLength, " ", "BOTH"),
		Key:                            helpers.StrPad("Data Key", DataKeyLength, " ", "BOTH"),
		IsCA:                           helpers.StrPad("Is CA", IsCALength, " ", "BOTH"),
		CertificateAuthorityCommonName: helpers.StrPad("Signing CA CN", CACNLength, " ", "BOTH"),
		ExpirationDate:                 helpers.StrPad("Expiration Date", ExpirationDateLength, " ", "BOTH"),
		TriggeredDaysOut:               helpers.StrPad("Triggered Days Out", TriggeredDaysOutLength, " ", "BOTH"),
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

// createSMTPHTMLReport creates a rich HTML-based table of the report, used in SMTP reports
func createSMTPHTMLReport(certificateSentinel configv1.CertificateSentinel, lggr logr.Logger) string {

	// Set up init vars
	var reportLines string

	currentConfig, _ := config.GetConfig()
	clusterEndpoint := currentConfig.Host
	apiPath := currentConfig.APIPath

	// Loop through the .status.CertificatesAtRisk
	for iCI, certInfo := range certificateSentinel.Status.CertificatesAtRisk {
		// Set up styles
		var rowStyles string
		cellStyles := "padding:6px;text-align:left;"
		if iCI%2 == 0 {
			rowStyles = "background:#FFF;"
		} else {
			rowStyles = "background:#FAFAFA;"
		}

		// Parse time to format
		inputTimelayout := "2006-01-02 15:04:05 -0700 MST"
		t, err := time.Parse(inputTimelayout, certInfo.Expiration)
		if err != nil {
			fmt.Printf("Error parsing time! %+v\n", err)
		}

		// Set up HTML Lines
		htmlSMTPReportLine := HTMLReportLineStructure{
			APIVersion:                     certInfo.APIVersion,
			Kind:                           certInfo.Kind,
			Namespace:                      certInfo.Namespace,
			Name:                           certInfo.Name,
			Key:                            certInfo.DataKey,
			IsCA:                           strconv.FormatBool(certInfo.IsCertificateAuthority),
			CertificateAuthorityCommonName: certInfo.CertificateAuthorityCommonName,
			ExpirationDate:                 string(t.Format(time.RFC822Z)),
			TriggeredDaysOut:               strings.Trim(strings.Join(strings.Fields(fmt.Sprint(certInfo.TriggeredDaysOut)), ", "), "[]"),
			RowStyles:                      rowStyles,
			CellStyles:                     cellStyles,
		}
		lineBuf := new(bytes.Buffer)
		htmlLineTemplate, err := template.New("tableLine").Parse(HTMLSMTPReportLine)
		if err != nil {
			lggr.Info("Error parsing htmlSMTPReportLine template!")
		}
		err = htmlLineTemplate.Execute(lineBuf, htmlSMTPReportLine)
		if err != nil {
			lggr.Info("Error executing htmlSMTPReportLine template!")
		}
		// Append to total reportLines
		reportLines = (reportLines + lineBuf.String())
	}

	// Set up styles for headers
	rowStyles := "background-color:#EEE;"
	cellStyles := "padding:6px;border-top: 1px solid #999;border-bottom: 1px solid #999;text-align:left;"

	// Setup HTML Headers
	htmlReportHeaderStructure := HTMLReportHeaderStructure{
		APIVersion:                     "APIVersion",
		Kind:                           "Kind",
		Namespace:                      "Namespace",
		Name:                           "Name",
		Key:                            "Data Key",
		IsCA:                           "Is CA",
		CertificateAuthorityCommonName: "Signing CA CN",
		ExpirationDate:                 "Expiration Date",
		TriggeredDaysOut:               "Triggered Days Out",
		RowStyles:                      rowStyles,
		CellStyles:                     cellStyles,
	}
	headerBuf := new(bytes.Buffer)
	tableHeaderTemplate, err := template.New("tableHeader").Parse(HTMLSMTPReportHeader)
	if err != nil {
		lggr.Info("Error parsing tableHeaderTemplate template!")
	}
	err = tableHeaderTemplate.Execute(headerBuf, htmlReportHeaderStructure)
	if err != nil {
		lggr.Info("Error executing tableHeaderTemplate template!")
	}

	// Set up HTML Report
	htmlReportStructure := HTMLReportStructure{
		Namespace:          certificateSentinel.Namespace,
		Name:               certificateSentinel.Name,
		DateSent:           string(time.Now().UTC().Format(time.RFC822Z)),
		ClusterAPIEndpoint: clusterEndpoint + apiPath,
		TotalCerts:         strconv.Itoa(len(certificateSentinel.Status.DiscoveredCertificates)),
		ExpiringCerts:      strconv.Itoa(len(certificateSentinel.Status.CertificatesAtRisk)),
		TableRows:          reportLines,
		THead:              headerBuf.String(),
		TFoot:              headerBuf.String(),
		BodyDivider:        HTMLSMTPReportBodyDivider,
	}
	reportBuf := new(bytes.Buffer)
	htmlReportTemplate, err := template.New("HTMLReport").Parse(HTMLSMTPReportBody)
	if err != nil {
		lggr.Error(err, "Error parsing htmlReportTemplate template!")
	}
	err = htmlReportTemplate.Execute(reportBuf, htmlReportStructure)
	if err != nil {
		lggr.Error(err, "Error executing htmlReportTemplate template!")
	}

	return reportBuf.String()
}

// tableTextReportToBasicHTMLReport takes a basic text-based table report used by logger and turns it into a basic HTML report
func tableTextReportToBasicHTMLReport(table string) string {
	// Set up Logger Report
	textSMTPReportStructure := TextSMTPReportStructure{
		Content: table,
	}
	htmlBuf := new(bytes.Buffer)
	textSMTPReportTemplate, err := template.New("textSMTPReport").Parse(TextSMTPReportDocument)
	if err != nil {
		lggr.Error(err, "Error parsing textSMTPReportTemplate template!")
	}
	err = textSMTPReportTemplate.Execute(htmlBuf, textSMTPReportStructure)
	if err != nil {
		lggr.Error(err, "Error executing textSMTPReportTemplate template!")
	}

	return htmlBuf.String()
}
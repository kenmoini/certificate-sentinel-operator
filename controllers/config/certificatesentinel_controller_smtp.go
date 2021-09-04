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
	"crypto/tls"
	defaults "github.com/kenmoini/certificate-sentinel-operator/controllers/defaults"
	mail "github.com/xhit/go-simple-mail/v2"
	"log"
	"net"
	"strconv"
	"time"
)

// sendSMTPMail assembles everything needed to sent an email via go-simple-mail
func sendSMTPMail(authType string, username string, password string, identity string, cramSecret string, useTLS *bool, useSTARTTLS *bool, to []string, from string, smtpServer string, textMessage string, htmlMessage string) {

	// Create a new SMTP Client
	server := mail.NewSMTPClient()

	// Set up the Server Connection
	smtpHost, smtpPort, _ := net.SplitHostPort(smtpServer)
	server.Host = smtpHost
	server.Port, _ = strconv.Atoi(smtpPort)

	// Set Authentication
	switch authType {
	case "none":
		server.Authentication = mail.AuthNone
	case "cram-md5":
		server.Authentication = mail.AuthCRAMMD5
		server.Username = username
		server.Password = cramSecret
	case "plain":
		server.Authentication = mail.AuthPlain
		server.Username = username
		server.Password = password
	case "login":
	default:
		server.Authentication = mail.AuthLogin
		server.Username = username
		server.Password = password
	}

	// Set other server connection variables
	// Variable to keep alive connection
	server.KeepAlive = false
	// Timeout for connect to SMTP Server
	server.ConnectTimeout = 10 * time.Second
	// Timeout for send the data and wait respond
	server.SendTimeout = 10 * time.Second

	// Set STARTTLS config
	if *useSTARTTLS == true {
		server.Encryption = mail.EncryptionSTARTTLS
	}
	// Set TLSConfig to provide custom TLS configuration. For example, to skip TLS verification (useful for testing):
	if *useTLS == false {
		server.TLSConfig = &tls.Config{InsecureSkipVerify: false}
	}

	// Create SMTP client
	smtpClient, err := server.Connect()
	if err != nil {
		log.Printf("%v\n", err)
	}

	// Set up new email message
	email := mail.NewMSG()
	emailSubject := defaults.SMTPMessageSubject

	// Set message details
	email.SetFrom(from).
		SetSubject(emailSubject)

	// loop through senders, add to email message
	for _, addy := range to {
		email.AddTo(addy)
	}

	// Set additional message headers

	// Set the message body
	if htmlMessage != "" {
		email.SetBody(mail.TextHTML, htmlMessage)
	}
	/*
		if textMessage != "" {
			email.AddAlternative(mail.TextPlain, textMessage)
		}
	*/

	// Send message
	// always check error before send (y tho?)
	if email.Error != nil {
		log.Printf("%v\n", email.Error)
	}

	// Call Send and pass the client
	err = email.Send(smtpClient)
	if err != nil {
		log.Println(err)
	}
	// Email sent!

}

/*
// setupSMTPAuth creates the Authentication structure
func setupSMTPAuth(authType string, username string, password string, identity string, cramSecret string, server string) smtp.Auth {
	// Set up authentication types
	//auth := (&smtp.Auth{})
	//auth := new(smtp.Auth)
	switch authType {
	case "none":
		return nil
	case "cram-md5":
		return smtp.CRAMMD5Auth(username, cramSecret)
	case "plain":
		return smtp.PlainAuth(identity, username, password, server)
	case "login":
	default:
		return smtp.PlainAuth("", username, password, server)
	}
	return nil
}
*/

/*
// sendSMTPMessage sends a message
func sendSMTPMessage(auth smtp.Auth, to string, from string, server string, textMessage string, htmlMessage string, useTLS bool) {

	// TODO: Set:
	// - Subject
	// - Proper TO Field
	// - HTML Report

		// Following works, but is lower-level and slightly limited/challenging to expand upon
		// Message.
		message := []byte(textMessage)

		// TLS config
		tlsconfig := &tls.Config{
			InsecureSkipVerify: !useTLS,
		}

		host, _, _ := net.SplitHostPort(server)

		// Here is the key, you need to call tls.Dial instead of smtp.Dial
		// for smtp servers running on 465 that require an ssl connection
		// from the very beginning (no starttls)
		conn, err := tls.Dial("tcp", server, tlsconfig)
		if err != nil {
			log.Panic(err)
		}

		// Create an SMTP Client
		c, err := smtp.NewClient(conn, host)
		if err != nil {
			log.Panic(err)
		}

		// Auth the SMTP client
		if err = c.Auth(auth); err != nil {
			log.Panic(err)
		}

		// To && From
		if err = c.Mail(from); err != nil {
			log.Panic(err)
		}
		if err = c.Rcpt(to); err != nil {
			log.Panic(err)
		}

		// Create Data Object
		w, err := c.Data()
		if err != nil {
			log.Panic(err)
		}

		// Populate Data Object
		//_, err = w.Write([]byte(message))
		_, err = w.Write(message)
		if err != nil {
			log.Panic(err)
		}

		err = w.Close()
		if err != nil {
			log.Panic(err)
		}

		c.Quit()

}

*/

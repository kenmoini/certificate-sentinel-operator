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
	"log"
	"net"
	"net/smtp"
)

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

// sendSMTPMessage sends a message
func sendSMTPMessage(auth smtp.Auth, to string, from string, server string, textMessage string, htmlMessage string, useTLS bool) {
	/*
			// GoMail functions
			m := gomail.NewMessage()

		  // Set E-Mail sender
		  m.SetHeader("From", from)

		  // Set E-Mail receivers
		  m.SetHeader("To", to)

		  // Set E-Mail subject
		  m.SetHeader("Subject", "Report from certificate-sentinel-operator")

		  // Set E-Mail body. You can set plain text or html with text/html
		  m.SetBody("text/plain", textMessage)
			m.AddAlternative("text/html", htmlMessage)
			smartHost := strings.Split(server, ":")

		  // Settings for SMTP server
		  //d := gomail.NewDialer(smartHost[0], smartHost[1], username, password)
		  d := gomail.NewDialer{}
			switch authType {
			case "none":
				d = gomail.Dialer{Host: smartHost[0], Port: smartHost[1]}
			case "plain":
			case "login":
			default:
				d := gomail.NewDialer(smartHost[0], smartHost[1], username, password)
			}

		  // This is only needed when SSL/TLS certificate is not valid on server.
		  // In production this should be set to false.
		  d.TLSConfig = &tls.Config{InsecureSkipVerify: !useTLS}

		  // Now send E-Mail
		  if err := d.DialAndSend(m); err != nil {
		    fmt.Println(err)
		  }
	*/

	// Golang built-in SMTP Functions

	// Receiver email address.
	/*
		toSlice := []string{
			to,
		}
	*/

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

	/*
		err := smtp.SendMail(hostname+":25", auth, from, toSlice, message)
		if err != nil {
			log.Fatal(err)
		}
	*/
}

/*
 * Copyright (C) 2025 by John J. Rushford jrushford@apache.org
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package restapi

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/cookiejar"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/ramcguire/tnascert-deploy/v2/clients/certs"
	"github.com/ramcguire/tnascert-deploy/v2/config"
)

const EndPoint = "/api/v2.0"

// certificates list
var certsList = map[string]int64{}

// name of the certificate to be installed
var certName string

type AuthRoundTripper struct {
	Transport http.RoundTripper
	AuthToken string
}

// adds necessary headers to each request
func (art *AuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid modifying the original request object
	newReq := req.Clone(req.Context())

	// Add the Authorization header
	newReq.Header.Set("Authorization", art.AuthToken)

	newReq.Header.Set("Content-Type", "application/json")

	// Delegate the actual request execution to the underlying transport
	return art.Transport.RoundTrip(newReq)
}

type TrueNASRest struct {
	Url        string
	VerifySSL  bool
	HttpClient *http.Client
	Version    string
	Cfg        *config.Config
}

// noop for truenasrest
func (c *TrueNASRest) Close() error {
	if c.Cfg.Debug {
		log.Printf("close the client connection, %v", c.Url)
	}
	return nil
}

func (c *TrueNASRest) Install() error {
	if c.Cfg.Debug {
		log.Println("running install tasks")
	}
	certName = c.Cfg.CertName()

	// import the certificate
	err := c.importCertificate()
	if err != nil {
		return fmt.Errorf("could not import certificate: %v", err)
	}

	// collect a certificate list
	err = c.getCertificateList()
	if err != nil {
		return fmt.Errorf("could not get certificate list: %v", err)
	}
	return nil
}

func (c *TrueNASRest) Login() error {
	if c.Cfg.Debug {
		log.Printf("running login task")
	}

	r, err := http.NewRequest(http.MethodGet, c.Url+"/core/ping", nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	res, err := c.HttpClient.Do(r)
	if err != nil {
		return fmt.Errorf("login request: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != 200 {
		return fmt.Errorf("non-200 login status: %d - %s", res.StatusCode, res.Status)
	}
	return nil
}

// constructor
func NewClient(cfg *config.Config) (*TrueNASRest, error) {
	var authToken string
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	serverURL := strings.TrimRight(cfg.ServerURL(), "/") + EndPoint

	if cfg.ApiKey != "" {
		authToken = "Bearer " + cfg.ApiKey
	} else if cfg.Username != "" && cfg.Password != "" {
		plainText := cfg.Username + ":" + cfg.Password
		authToken = "Basic " + base64.StdEncoding.EncodeToString([]byte(plainText))
	} else {
		return nil, fmt.Errorf("no valid credentials have been supplied")
	}

	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.Protocol == "https" {
		customTransport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: cfg.TlsSkipVerify,
		}
	}
	authTransport := &AuthRoundTripper{
		Transport: customTransport,
		AuthToken: authToken,
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("creating the cookie jar failed %v", err)
	}

	httpClient := &http.Client{
		Transport: authTransport,
		Timeout:   timeout,
		Jar:       jar,
	}

	rest_client := TrueNASRest{
		Url:        serverURL,
		VerifySSL:  cfg.TlsSkipVerify,
		HttpClient: httpClient,
		Cfg:        cfg,
	}
	return &rest_client, nil
}

func (c *TrueNASRest) PostInstall() error {
	activated := false
	if c.Cfg.Debug {
		log.Println("running post install tasks")
	}

	// update the UI to use the newly
	// imported certificate
	if c.Cfg.AddAsUiCertificate {
		err := c.addAsUICertificate()
		if err != nil {
			return fmt.Errorf("failed to set %s as the UI certificate: %v", certName, err)
		}
		activated = true
	}

	// update the FTP service to use the newly
	// imported certificate
	if c.Cfg.AddAsFTPCertificate {
		err := c.addAsFTPCertificate()
		if err != nil {
			return fmt.Errorf("failed to set %s as the FTP certificate: %v", certName, err)
		}
	}

	if c.Cfg.AddAsAppCertificate {
		if c.Cfg.AppList == "" {
			log.Printf("the AppList config is empty, no apps to check")
			return nil
		} else {
			if strings.HasPrefix(c.Version, "TrueNAS-SCALE") {
				appList := strings.Split(c.Cfg.AppList, ",")
				for _, app := range appList {
					err := c.addAsAppCertificate(app)
					if err != nil {
						log.Printf("failed to add the '%s' certificate to the '%s' app: %v", certName, app, err)
					}
				}
			} else {
				log.Printf("will not process any apps as the system is not running TrueNAS-SCALE")
			}
		}
	}

	if activated {
		if c.Cfg.DeleteOldCerts {
			// give a wait of 5 seconds before deleting old certificates.
			// to insure app updates have completed.
			time.Sleep(5 * time.Second)
			err := c.deleteCertificates()
			if err != nil {
				return fmt.Errorf("error deleting old certificates: %v", err)
			} else {
				log.Println("successfully deleted old certificates")
			}
		}

		// restart the UI
		err := c.restartUI()
		if err != nil {
			return fmt.Errorf("failed to restart the UI")
		} else {
			log.Println("successfully restarted the UI")
		}
	}
	return nil
}

func (c *TrueNASRest) PreInstall() error {
	if c.Cfg.Debug {
		log.Println("running preinstall tasks")
	}

	err := c.getSystemInfo()
	if err != nil {
		return fmt.Errorf("could not get system info: %v", err)
	}

	err = certs.VerifyCertificateKeyPair(c.Cfg.FullChainPath, c.Cfg.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("failed certificate verification: %v", err)
	}

	return nil
}

func (c *TrueNASRest) addAsAppCertificate(appName string) error {
	log.Printf("adding %s with ID %d to the %s app", certName, certsList[certName], appName)

	// get the app configuration
	app := []byte("\"" + appName + "\"")
	req, err := http.NewRequest(http.MethodPost, c.Url+"/app/config", bytes.NewBuffer(app))
	if err != nil {
		return fmt.Errorf("error creating application configuration request for '%s': %v", appName, err)
	}
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error executing the application configuration request for '%s': %v", appName, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("application configuration request for '%s' failed: %v", appName, resp.Status)
	}
	var respData any
	err = json.NewDecoder(resp.Body).Decode(&respData)
	if err != nil {
		return fmt.Errorf("error decoding the application config info: %v", err)
	}

	// check the App for an existing certificate.  If it's not currently using one, we are not going
	// to add one to the App
	cMap, ok := respData.(map[string]any)
	if !ok {
		return fmt.Errorf("unexpected format in app config response for '%s'", appName)
	}
	nMap, ok := cMap["network"]
	if ok {
		cfg := nMap.(map[string]any)
		v, found := cfg["certificate_id"]
		if v == nil || !found {
			log.Printf("the '%s' application is currently not using a certificate, will not add one", appName)
			return nil
		}
	}
	_ = resp.Body.Close()

	if m, ok := nMap.(map[string]any); ok {
		certId := certsList[certName]
		m["certificate_id"] = certId
		uMap := map[string]map[string]any{
			"values": {
				"network": m,
			},
		}
		jsonUpdate, err := json.Marshal(uMap)
		if err != nil {
			return fmt.Errorf("error marshaling an update message for the '%s' app: %v", appName, err)
		}
		if c.Cfg.Debug {
			log.Printf("update message for '%s' app: %s\n", appName, string(jsonUpdate))
		}
		body := bytes.NewBuffer([]byte(jsonUpdate))
		req, err = http.NewRequest(http.MethodPut, c.Url+"/app/id/"+appName, body)
		if err != nil {
			return fmt.Errorf("error creating application configuration update for '%s': %v", appName, err)
		}
		resp, err = c.HttpClient.Do(req)
		if err != nil {
			return fmt.Errorf("error executing the application update request for '%s': %v", appName, err)
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("the application update request for '%s' failed: %v", appName, resp.Status)
		}
		defer func() { _ = resp.Body.Close() }()

		time.Sleep(5 * time.Second)
		log.Printf("updated the  certificate for application '%s' to use %s", appName, certName)
	} else {
		return fmt.Errorf("obtaining the network configuration for '%s'", appName)
	}

	return nil
}

func (c *TrueNASRest) addAsFTPCertificate() error {
	if id, ok := certsList[certName]; ok {
		data := struct {
			CertId int64 `json:"ssltls_certificate"`
		}{
			CertId: id,
		}
		jsonData, err := json.Marshal(&data)
		if err != nil {
			return fmt.Errorf("could not marshal ftp update message: %v", err)
		}
		// update active FTP certificate
		req, err := http.NewRequest(http.MethodPut, c.Url+"/ftp", bytes.NewBuffer(jsonData))
		if err != nil {
			return fmt.Errorf("error creating FTP update request: %v", err)
		}
		resp, err := c.HttpClient.Do(req)
		if err != nil {
			return fmt.Errorf("error executing the active FTP update request: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("FTP update request failed: %v", resp.Status)
		} else {
			// wait 5 seconds for the imported certificate to become available
			time.Sleep(5 * time.Second)
			log.Printf("updated the active FTP certificate to use %s", certName)
		}
		defer func() { _ = resp.Body.Close() }()
	} else {
		return fmt.Errorf("%s was not found, cannot add it as FTP certificate", certName)
	}
	return nil
}

func (c *TrueNASRest) addAsUICertificate() error {
	if id, ok := certsList[certName]; ok {
		data := struct {
			CertId int64 `json:"ui_certificate"`
		}{
			CertId: id,
		}
		jsonData, err := json.Marshal(&data)
		if err != nil {
			return fmt.Errorf("could not marshal ui update message: %v", err)
		}
		// update active UI certificate
		req, err := http.NewRequest(http.MethodPut, c.Url+"/system/general", bytes.NewBuffer(jsonData))
		if err != nil {
			return fmt.Errorf("error creating UI update request: %v", err)
		}
		resp, err := c.HttpClient.Do(req)
		if err != nil {
			return fmt.Errorf("error executing the active UI update request: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("UI update request failed: %v", resp.Status)
		} else {
			// wait 5 seconds for the imported certificate to become available
			time.Sleep(5 * time.Second)
			log.Printf("updated the active UI certificate to use %s", certName)
		}
		defer func() { _ = resp.Body.Close() }()
	} else {
		return fmt.Errorf("%s was not found, cannot add it as UI certificate", certName)
	}
	return nil
}

func (c *TrueNASRest) deleteCertificates() error {
	log.Printf("deleting old certificates with prefix '%s'", c.Cfg.CertBasename)

	// Prepare regex
	pattern := fmt.Sprintf(`^%s-\d{4}-\d{2}-\d{2}-\d+$`, regexp.QuoteMeta(c.Cfg.CertBasename))
	re := regexp.MustCompile(pattern)
	var basenameMatch bool

	for k, v := range certsList {
		if strings.Compare(k, certName) == 0 {
			log.Printf("skip the deletion of the active UI certificate %s", certName)
			continue
		}
		if c.Cfg.StrictBasenameMatch {
			basenameMatch = re.MatchString(k)
			log.Printf("Regex match %s against %s: %v", c.Cfg.CertBasename, k, basenameMatch)
		} else {
			basenameMatch = strings.HasPrefix(k, c.Cfg.CertBasename)
			log.Printf("Prefix match %s against %s: %v", c.Cfg.CertBasename, k, basenameMatch)
		}

		if basenameMatch {
			URL := fmt.Sprintf("%s/certificate/id/%d", c.Url, v)
			r, err := http.NewRequest(http.MethodDelete, URL, nil)
			if err != nil {
				return fmt.Errorf("error creating certificate delete request: %v", err)
			}
			resp, err := c.HttpClient.Do(r)
			if err != nil {
				return fmt.Errorf("error executing certificate deletion: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("error deleting certificate %s: %v", certName, resp.Status)
			}
			log.Printf("deleted certificate %s", k)
		}
	}

	return nil
}

func (c *TrueNASRest) getCertificateList() error {
	// fetch the list a list of certificates
	var respData any
	// certificate list get request
	req, err := http.NewRequest(http.MethodGet, c.Url+"/certificate?limit=0", nil)
	if err != nil {
		return fmt.Errorf("error creating certificate list request: %v", err)
	}
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error executing certificate list request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("certificate list request failed: %v", resp.Status)
	}
	defer func() { _ = resp.Body.Close() }()

	err = json.NewDecoder(resp.Body).Decode(&respData)
	if err != nil {
		return fmt.Errorf("error decoding the certificate list: %v", err)
	}
	// parse the response and build the certificates list
	for _, v := range respData.([]any) {
		if t, ok := v.(map[string]any); ok {
			name := t["name"].(string)
			idi := t["id"]
			id := int64(idi.(float64))
			certsList[name] = id
		}
	}
	if len(certsList) == 0 {
		return fmt.Errorf("no certificates were found in the certificate list")
	}
	if _, ok := certsList[certName]; !ok {
		return fmt.Errorf("certificate %s was not found in certificate list", certName)
	}

	return nil
}

func (c *TrueNASRest) getSystemInfo() error {
	// fetch the system information.
	var respData any
	// system info request
	req, err := http.NewRequest(http.MethodGet, c.Url+"/system/info", nil)
	if err != nil {
		return fmt.Errorf("error creating system info request: %v", err)
	}
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error executing system info request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("system info request failed: %v", resp.Status)
	}
	defer func() { _ = resp.Body.Close() }()

	err = json.NewDecoder(resp.Body).Decode(&respData)
	if err != nil {
		return fmt.Errorf("error decoding the system info: %v", err)
	}
	vmap, ok := respData.(map[string]any)
	if ok {
		version := vmap["version"]
		c.Version = version.(string)
		log.Printf("%s is running version '%s'", c.Cfg.ConnectHost, c.Version)
	} else {
		log.Printf("%s unable to get the version of TrueNAS", c.Cfg.ConnectHost)
	}
	return nil

}

func (c *TrueNASRest) importCertificate() error {
	log.Printf("importing the %s certificate", c.Cfg.CertName())
	certPem, err := os.ReadFile(c.Cfg.FullChainPath)
	if err != nil {
		return fmt.Errorf("error reading the certificate file: %v", err)
	}
	keyPem, err := os.ReadFile(c.Cfg.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("error reading the private key file: %v", err)
	}

	data := struct {
		Name        string `json:"name"`
		CreateType  string `json:"create_type"`
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"privatekey"`
	}{
		Name:        certName,
		CreateType:  "CERTIFICATE_CREATE_IMPORTED",
		Certificate: string(certPem),
		PrivateKey:  string(keyPem),
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("error marshaling the certificate import message: %v", err)
	}

	// certificate import post request
	req, err := http.NewRequest(http.MethodPost, c.Url+"/certificate", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("error creating certificate import request: %v", err)
	}
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error executing the import request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("certificate import request failed: %v", resp.Status)
	} else {
		// wait 5 seconds for the imported certificate to become available
		time.Sleep(5 * time.Second)
		log.Printf("successfully imported the %s certificate", certName)
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}

func (c *TrueNASRest) restartUI() error {
	// restart the UI request
	req, err := http.NewRequest(http.MethodGet, c.Url+"/system/general/ui_restart", nil)
	if err != nil {
		return fmt.Errorf("error creating the UI restart request: %v", err)
	}
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error executing the UI restart request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to restart the UI: %v", resp.Status)
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}

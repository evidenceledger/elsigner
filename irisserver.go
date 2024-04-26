package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/evidenceledger/elsignerw/certstore"
	"github.com/evidenceledger/elsignerw/tokensign"
	"github.com/pkg/browser"

	"github.com/evidenceledger/vcdemo/issuernew"
	"github.com/evidenceledger/vcdemo/vault/x509util"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/view"
)

// var recordsGlobal CredentialRecords

type server struct {
	app                           *iris.Application
	selectedCertstoreSerialNumber string
	records                       CredentialRecords
	certstoreSigner               *certstore.CertStore
	x509Certificate               *x509.Certificate
}

//go:embed data/*
var embeddedFS embed.FS

func startIrisServer(debug bool) {

	// Load view templates
	var tmpl *view.BlocksEngine
	if _, err := os.Stat("./data"); !os.IsNotExist(err) {
		fmt.Println("Using external templates")
		tmpl = view.Blocks("./data", ".html").
			RootDir("views").
			Reload(true).
			LayoutDir("layouts").Layout("main")

	} else {
		fmt.Println("Using embedded templates")
		tmpl = view.Blocks(embeddedFS, ".html").
			RootDir("data/views").
			Reload(true).
			LayoutDir("layouts").Layout("main")

	}

	// Add our functions for the template
	tmpl.AddFunc("add", func(a, b int) int {
		return a + b
	})

	// Create the server
	app := iris.Default()
	s := &server{}
	s.app = app

	// Register the view engine to the views,
	// this will load the templates.
	app.RegisterView(tmpl)

	// Handle statis assets
	app.HandleDir("/assets", iris.Dir("./data/assets"))

	// The main page of the application
	app.Get("/", s.homePage)

	app.Get("/selectcertificate/{serial}", s.selectX509Certificates)

	app.Get("/formcreatecertification", s.formCreateCertification)
	app.Post("/formcreatecertification", s.formCreateCertification)

	// Display the credential details so the user knows what is being signed
	app.Get("/displaycred/{id}", s.displayCredentialDetails)

	// Perform the actual signature and display the result to the user
	app.Get("/signwithcertificate/{id}", s.signWithCertificate)

	// Close the server and exit
	app.Get("/stop", s.stopServer)

	go func() {
		time.Sleep(2 * time.Second)
		browser.OpenURL("http://localhost:8080/")
	}()
	app.Listen("localhost:8080")

}

func (s *server) realHomePage(ctx iris.Context) {

	if len(s.selectedCertstoreSerialNumber) == 0 {
		// We have not yet initialised the certificate to use

	}

}

func (s *server) homePage(ctx iris.Context) {
	if len(s.selectedCertstoreSerialNumber) == 0 {
		s.app.Logger().Info("selecting x509 certificates")
		s.selectX509Certificates(ctx)
	} else {
		s.app.Logger().Infof("certificate %s already selected")
		s.displayLEARCredentials(ctx)
	}
}

// selectX509Certificates is a self-submit page
func (s *server) selectX509Certificates(ctx iris.Context) {
	var err error

	serialNumber := ctx.Params().Get("serial")

	// If the 'serial' path param is not found, we get the X509 certificates installed in the certstore (Windows only)
	// and display a page with the whole list, so the user can select the one used for signatures
	if len(serialNumber) == 0 {
		s.certstoreSigner, err = certstore.New()
		if err != nil {
			renderPage(ctx, "error", iris.Map{"title": "Error retrieving signing certificates", "description": "There has been an error retrieving certificater from the Windows certification store.", "message": err.Error()})
			return
		}

		renderPage(ctx, "selectcert", iris.Map{"validcerts": s.certstoreSigner.ValidCerts})
		return
	}

	// The user has selected the certificate for signature. Store it for later usage
	s.app.Logger().Info("selectedX509Certificate ", serialNumber)
	s.selectedCertstoreSerialNumber = serialNumber
	s.certstoreSigner.SelectedSerialNumber = serialNumber
	s.x509Certificate = s.certstoreSigner.ValidCerts[serialNumber].Certificate

	// Go to display the credentials available for signature in the DOME Issuer server
	s.displayLEARCredentials(ctx)

}

// displayLEARCredentials cass the remote DOME Issuer server and retrieves th ecredentials that this user has to sign.
// The credentials are displayed so the user can interact with them.
func (s *server) displayLEARCredentials(ctx iris.Context) {
	var err error

	// Ask the DOME Issuer server for available credentials
	records, err := s.retrieveCredentialsToSign()
	if err != nil {
		s.app.Logger().Errorf("retrieveCredentialsToSign: %s", err)
		renderPage(ctx, "error", iris.Map{"title": "Error retrieving credentials", "description": "The issuer server may be down.", "message": err.Error()})
		return
	}
	s.app.Logger().Infof("displayLEARCredentials: num records retrieved %d", len(records))

	// Store the records for later usage
	s.records = records

	// Display a list so the user can select one of the credentials
	renderPage(ctx, "displaycredentials", iris.Map{"records": records})

}

// displayCredentialDetails receives the credential id selected by the user, and displays its read-only view
func (s *server) displayCredentialDetails(ctx iris.Context) {
	var err error

	id := ctx.Params().Get("id")
	if len(id) == 0 {
		s.app.Logger().Error("displayCredentialDetails ", "credential id not specified")
		renderPage(ctx, "error", iris.Map{"title": "Error retrieving credentials", "description": "Credential identifier not specified."})
		return
	}
	s.app.Logger().Info("displayCredentialDetails ", id)

	// Get the selected record from the ones that were retrieved before
	record := s.records[id]
	if record == nil {
		s.app.Logger().Error("displayCredentialDetails ", "credential not found")
		renderPage(ctx, "error", iris.Map{"title": "Error retrieving credentials", "description": "Credential not found."})
		return
	}

	// The actual JWT is in the 'raw' field of the record.
	// We need to decode the payload so we can display it to the user.
	// We do not need to verify signatures here.
	raw := record["raw"].(string)
	var learcred issuernew.LEARCredentialEmployeeJWTClaims
	parser := jwt.NewParser()
	_, _, err = parser.ParseUnverified(raw, &learcred)
	if err != nil {
		s.app.Logger().Error("displayCredentialDetails ", err)
		renderPage(ctx, "error", iris.Map{"title": "Error parsing the credential", "description": "The format of the credential seems wrong.", "message": err.Error()})
		return
	}

	// Display the credential to the user, so she can decide to sign it
	renderPage(ctx, "displaycred", iris.Map{"credential": learcred, "credid": id})

}

func (s *server) signWithCertificate(ctx iris.Context) {
	var err error

	// Get the credential ID selected by the user
	id := ctx.Params().Get("id")
	if len(id) == 0 {
		s.app.Logger().Error("signWithCertificate ", "credential id not specified")
		renderPage(ctx, "error", iris.Map{"title": "Error retrieving credentials", "description": "Credential identifier not specified."})
		return
	}

	// This is the certificate that was selected by the user for signing
	serialNumber := s.selectedCertstoreSerialNumber
	s.app.Logger().Infof("signWithCertificate: cred: %s, certid: %s ", id, s.selectedCertstoreSerialNumber)

	// Get the credential record that we have to sign
	record := s.records[id]
	if record == nil {
		s.app.Logger().Error("signWithCertificate ", "credential not found")
		renderPage(ctx, "error", iris.Map{"title": "Error with credential", "description": "The credential is not found."})
		return
	}

	// Get the raw credential and parse it
	raw := record["raw"].(string)
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(raw, &issuernew.LEARCredentialEmployeeJWTClaims{})
	if err != nil {
		renderPage(ctx, "error", iris.Map{"title": "Error parsing the credential", "description": "The format of the credential seems wrong.", "message": err.Error()})
		return
	}

	// Sign the credential with the certificate selected previously
	learCred := token.Claims.(*issuernew.LEARCredentialEmployeeJWTClaims)
	tok, err := s.signLEARCredential(serialNumber, learCred.LEARCredentialEmployee)
	if err != nil {
		renderPage(ctx, "error", iris.Map{"title": "Error signing the credential", "description": "There has been an error signing the LEARCredential with the selected certificate.", "message": err.Error()})
		return
	}

	// Prepare to update the record in the server
	record["raw"] = tok
	record["status"] = "signed"

	// Serialise record
	serialised, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		renderPage(ctx, "error", iris.Map{"title": "Error with the format of the credential", "description": "There has been an error serialising the LEARCredential to prepare for signature.", "message": err.Error()})
		return
	}
	buf := bytes.NewBuffer(serialised)

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				GetClientCertificate: s.certstoreSigner.GetClientCertificate,
				MinVersion:           tls.VersionTLS13,
				MaxVersion:           tls.VersionTLS13,
			},
		},
	}

	// Send the signed credential back to the server
	resp, err := client.Post("https://issuersec.mycredential.eu/apisigner/updatesignedcredential", "application/json", buf)
	if err != nil {
		renderPage(ctx, "error", iris.Map{"title": "Error ending signed credential to server", "description": "There has been an error when trying to update the signed credential in the Issuer server.", "message": err.Error()})
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		renderPage(ctx, "error", iris.Map{"title": "Error reading response from server", "description": "There has been an error receiving the response from the Issuer server when updating the LEARCredential.", "message": err.Error()})
		return
	}
	fmt.Println("response", string(body))
	renderPage(ctx, "signed", iris.Map{"message": string(body)})

}

func renderPage(ctx iris.Context, page string, data any) {
	// Render template file: ./views/hi.html
	if err := ctx.View(page, data); err != nil {
		ctx.HTML("<h3>%s</h3>", err.Error())
		return
	}
}

type CredentialRecord map[string]any
type CredentialRecords map[string]CredentialRecord

func (s *server) retrieveCredentialsToSign() (CredentialRecords, error) {

	var recordArray []CredentialRecord
	records := CredentialRecords{}

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				GetClientCertificate: s.certstoreSigner.GetClientCertificate,
				MinVersion:           tls.VersionTLS13,
				MaxVersion:           tls.VersionTLS13,
			},
		},
	}

	url := "https://issuersec.mycredential.eu/apisigner/retrievecredentials"

	// Make a GET request to the URL
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status error %s", resp.Status)
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	fmt.Println(string(body))

	err = json.Unmarshal(body, &recordArray)
	if err != nil {
		return nil, err
	}

	// Convert the array to facilitate the life of the user
	for _, rec := range recordArray {
		id := rec["id"].(string)
		records[id] = rec
	}

	return records, nil
}

func (s *server) signLEARCredential(serialNumber string, learCred issuernew.LEARCredentialEmployee) (string, error) {

	// Get the certificate selected by the user
	certInfo, ok := s.certstoreSigner.ValidCerts[serialNumber]
	if !ok {
		return "", fmt.Errorf("certificate not found for serial number: %s", serialNumber)
	}
	signer := certInfo.PrivateKey

	// Sign the credential
	tok, err := issuernew.CreateLEARCredentialJWTtoken(learCred, tokensign.SigningMethodCert, signer)
	if err != nil {
		return "", err
	}

	return tok, nil
}

type CertificationCredential struct {
	Context        []string `form:"@context,omitempty"`
	Id             string   `form:"id,omitempty"`
	TypeCredential []string `form:"type,omitempty"`
	Issuer         struct {
		Id string `form:"id,omitempty"`
	} `form:"issuer,omitempty"`
	ValidFrom         string `form:"validFrom,omitempty"`
	ValidUntil        string `form:"validUntil,omitempty"`
	CredentialSubject struct {
		ServiceSpec        string `form:"service_spec,omitempty"`
		ServiceSpecVersion string `form:"service_spec_version,omitempty"`
		Accreditation      struct {
			Type       string `form:"type,omitempty"`
			Scope      string `form:"scope,omitempty"`
			ValidFrom  string `form:"validFrom,omitempty"`
			ValidUntil string `form:"validUntil,omitempty"`
		} `form:"accreditation,omitempty"`

		Issuer struct {
			OrganizationIdentifier string `form:"issuerorganizationIdentifier,omitempty"` // OID 2.5.4.97
			CommonName             string `form:"issuercommonName,omitempty"`             // OID 2.5.4.3
			GivenName              string `form:"issuergivenName,omitempty"`
			Surname                string `form:"issuersurname,omitempty"`
			EmailAddress           string `form:"issueremailAddress,omitempty"`
			SerialNumber           string `form:"issuerserialNumber,omitempty"`
			Organization           string `form:"issuerorganization,omitempty"`
			Country                string `form:"issuercountry,omitempty"`
			Website                string `form:"issuerwebsite,omitempty"`
		} `form:"issuer,omitempty"`
		Provider struct {
			OrganizationIdentifier string `form:"providerorganizationIdentifier,omitempty"` // OID 2.5.4.97
			CommonName             string `form:"providercommonName,omitempty"`             // OID 2.5.4.3
			GivenName              string `form:"providergivenName,omitempty"`
			Surname                string `form:"providersurname,omitempty"`
			EmailAddress           string `form:"provideremailAddress,omitempty"`
			SerialNumber           string `form:"providerserialNumber,omitempty"`
			Organization           string `form:"providerorganization,omitempty"`
			Country                string `form:"providercountry,omitempty"`
			Website                string `form:"providerwebsite,omitempty"`
		} `form:"provider,omitempty"`
	} `form:"credentialSubject,omitempty"`
}

func (f *CertificationCredential) Parse(formValues map[string][]string) {
	for name, values := range formValues {
		value := values[0]
		switch name {
		case "service_spec":
			f.CredentialSubject.ServiceSpec = value
		case "service_spec_version":
			f.CredentialSubject.ServiceSpecVersion = value
		case "type":
			f.CredentialSubject.Accreditation.Type = value
		case "scope":
			f.CredentialSubject.Accreditation.Scope = value
		case "validFrom":
			f.CredentialSubject.Accreditation.ValidFrom = value
		case "validUntil":
			f.CredentialSubject.Accreditation.ValidUntil = value

		// case "issuerorganizationIdentifier":
		// 	f.CredentialSubject.Issuer.OrganizationIdentifier = value
		// case "issuercommonName":
		// 	f.CredentialSubject.Issuer.CommonName = value
		// case "issuergivenName":
		// 	f.CredentialSubject.Issuer.GivenName = value
		// case "issuersurname":
		// 	f.CredentialSubject.Issuer.Surname = value
		// case "issueremailAddress":
		// 	f.CredentialSubject.Issuer.EmailAddress = value
		// case "issuerserialNumber":
		// 	f.CredentialSubject.Issuer.SerialNumber = value
		// case "issuerorganization":
		// 	f.CredentialSubject.Issuer.Organization = value
		// case "issuercountry":
		// 	f.CredentialSubject.Issuer.Country = value
		// case "issuerwebsite":
		// 	f.CredentialSubject.Issuer.Website = value

		case "providerorganizationIdentifier":
			f.CredentialSubject.Provider.OrganizationIdentifier = value
		case "providercommonName":
			f.CredentialSubject.Provider.CommonName = value
		case "providergivenName":
			f.CredentialSubject.Provider.GivenName = value
		case "providersurname":
			f.CredentialSubject.Provider.Surname = value
		case "provideremailAddress":
			f.CredentialSubject.Provider.EmailAddress = value
		case "providerserialNumber":
			f.CredentialSubject.Provider.SerialNumber = value
		case "providerorganization":
			f.CredentialSubject.Provider.Organization = value
		case "providercountry":
			f.CredentialSubject.Provider.Country = value
		case "providerwebsite":
			f.CredentialSubject.Provider.Website = value

		}
	}
}

type CertificationJWTClaims struct {
	CertificationCredential
	jwt.RegisteredClaims
}

func (s *server) formCreateCertification(ctx iris.Context) {
	fmt.Println("In Form handler", ctx.Request().Method)

	values := ctx.FormValues()
	if len(values) == 0 {
		// This path is when we are displaying the form
		certification := &CertificationCredential{}

		issuer := x509util.ParseEIDASNameFromATVSequence(s.x509Certificate.Subject.Names)

		certification.CredentialSubject.Issuer.CommonName = issuer.CommonName
		certification.CredentialSubject.Issuer.SerialNumber = issuer.SerialNumber
		certification.CredentialSubject.Issuer.Country = issuer.Country
		if len(issuer.OrganizationIdentifier) == 0 {
			certification.CredentialSubject.Issuer.OrganizationIdentifier = issuer.SerialNumber
			certification.CredentialSubject.Issuer.Organization = issuer.CommonName
		} else {
			certification.CredentialSubject.Issuer.OrganizationIdentifier = issuer.OrganizationIdentifier
			certification.CredentialSubject.Issuer.Organization = issuer.Organization
		}

		renderPage(ctx, "certification", iris.Map{"certification": certification, "msg": "Filling the form"})
		return
	}

	form := &CertificationCredential{}
	form.Parse(values)

	// Form was submitted
	fmt.Println("Form was SUBMITTED")
	renderPage(ctx, "certification", iris.Map{"certification": form, "msg": "Perfecto"})

}

func (s *server) stopServer(ctx iris.Context) {
	go func() {
		time.Sleep(time.Second)
		os.Exit(0)
	}()
	renderPage(ctx, "stopped", nil)
}

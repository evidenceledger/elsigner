package main

import (
	"bytes"
	"crypto/tls"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/evidenceledger/elsignerw/tokensign"
	"github.com/evidenceledger/elsignerw/winsigner"
	"github.com/pkg/browser"

	"github.com/evidenceledger/vcdemo/issuernew"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/view"
)

// var recordsGlobal CredentialRecords

type server struct {
	app          *iris.Application
	serialNumber string
	records      CredentialRecords
	winSigner    *winsigner.WindowsSigner
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

func (s *server) homePage(ctx iris.Context) {
	if len(s.serialNumber) == 0 {
		s.selectX509Certificates(ctx)
	} else {
		s.displayLEARCredentials(ctx)
	}
}

func (s *server) stopServer(ctx iris.Context) {
	go func() {
		time.Sleep(time.Second)
		os.Exit(0)
	}()
	renderPage(ctx, "stopped", nil)
}

func (s *server) selectX509Certificates(ctx iris.Context) {

	serialNumber := ctx.Params().Get("serial")
	if len(serialNumber) > 0 {
		fmt.Println("selectedX509Certificate", serialNumber)
		s.serialNumber = serialNumber
		s.winSigner.DefaultCertSerialNumber = serialNumber
		s.displayLEARCredentials(ctx)
		return
	}

	winSigner, err := winsigner.New()
	if err != nil {
		renderPage(ctx, "error", iris.Map{"title": "Error retrieving signing certificates", "description": "There has been an error retrieving certificater from the Windows certification store.", "message": err.Error()})
		return
	}
	s.winSigner = winSigner

	renderPage(ctx, "selectcert", iris.Map{"validcerts": winSigner.ValidCerts})

}

func (s *server) displayLEARCredentials(ctx iris.Context) {
	var err error

	records, err := s.retrieveCredentialsToSign()
	if err != nil {
		renderPage(ctx, "error", iris.Map{"title": "Error retrieving credentials", "description": "The issuer server may be down.", "message": err.Error()})
		return
	}
	fmt.Println("index", "num records retrieved", len(records))
	s.records = records

	renderPage(ctx, "displaycredentials", iris.Map{"records": records})

}

func (s *server) displayCredentialDetails(ctx iris.Context) {
	var err error

	id := ctx.Params().Get("id")
	fmt.Println("displaycred", id)

	record := s.records[id]
	if record == nil {
		renderPage(ctx, "error", iris.Map{"title": "Error retrieving credentials", "description": "Credential identifier not specified or credential not found."})
		return
	}

	raw := record["raw"].(string)
	var learcred issuernew.LEARCredentialEmployeeJWTClaims
	parser := jwt.NewParser()
	_, _, err = parser.ParseUnverified(raw, &learcred)
	if err != nil {
		renderPage(ctx, "error", iris.Map{"title": "Error parsing the credential", "description": "The format of the credential seems wrong.", "message": err.Error()})
		return
	}

	renderPage(ctx, "displaycred", iris.Map{"credential": learcred, "credid": id})

}

func (s *server) signWithCertificate(ctx iris.Context) {
	var err error

	id := ctx.Params().Get("id")
	serialNumber := s.serialNumber
	fmt.Println("signWithCertificate", id, serialNumber)

	record := s.records[id]
	if record == nil {
		renderPage(ctx, "error", iris.Map{"title": "Error with certificate", "description": "The certificate is not found."})
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
				GetClientCertificate: s.winSigner.GetClientCertificate,
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

	url := "https://issuersec.mycredential.eu/apisigner/retrievecredentials"

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				GetClientCertificate: s.winSigner.GetClientCertificate,
				MinVersion:           tls.VersionTLS13,
				MaxVersion:           tls.VersionTLS13,
			},
		},
	}

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

	tlsCertificate, err := s.winSigner.GetTLSCertificate(serialNumber)
	if err != nil {
		return "", err
	}

	signer := tlsCertificate.PrivateKey
	// Sign the credential
	tok, err := issuernew.CreateLEARCredentialJWTtoken(learCred, tokensign.SigningMethodCert, signer)
	if err != nil {
		return "", err
	}

	return tok, nil
}

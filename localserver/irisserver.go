package localserver

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/evidenceledger/elsignerw/certstore"
	"github.com/evidenceledger/elsignerw/tokensign"
	"github.com/evidenceledger/vcdemo/issuernew"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/view"
)

type CredentialRecord map[string]any
type CredentialRecords map[string]CredentialRecord

func StartIrisServer() {
	startIrisServer()
}

type server struct {
	app          *iris.Application
	serialNumber string
	records      CredentialRecords
	certSigner   *certstore.CertStoreSigner
}

func startIrisServer() {

	// Load view templates
	tmpl := view.Blocks("./data", ".html").
		RootDir("views").
		Reload(true).
		LayoutDir("layouts").Layout("main")

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

	app.Listen("localhost:8080")
}

func (s *server) homePage(ctx iris.Context) {
	if len(s.serialNumber) == 0 {
		s.selectX509Certificates(ctx)
	} else {
		s.displayLEARCredentials(ctx)
	}
}

func (s *server) selectX509Certificates(ctx iris.Context) {

	serialNumber := ctx.Params().Get("serial")
	if len(serialNumber) > 0 {
		fmt.Println("selectedX509Certificate", serialNumber)
		s.serialNumber = serialNumber
		s.certSigner.DefaultCertSerialNumber = serialNumber
		s.displayLEARCredentials(ctx)
		return
	}

	certSigner, err := certstore.New()
	if err != nil {
		renderPage(ctx, "error", iris.Map{"title": "Error retrieving signing certificates", "description": "There has been an error retrieving certificater from the Windows certification store.", "message": err.Error()})
		return
	}
	s.certSigner = certSigner

	renderPage(ctx, "selectcert", iris.Map{"validcerts": certSigner.ValidCerts})

}

func renderPage(ctx iris.Context, page string, data any) {
	// Render template file: ./views/hi.html
	if err := ctx.View(page, data); err != nil {
		ctx.HTML("<h3>%s</h3>", err.Error())
		return
	}
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

func (s *server) retrieveCredentialsToSign() (CredentialRecords, error) {

	var recordArray []CredentialRecord
	records := CredentialRecords{}

	url := "https://issuersec.mycredential.eu/apiadmin/retrievecredentials"

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				GetClientCertificate: s.certSigner.GetClientCertificate,
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

func (s *server) signLEARCredential(serialNumber string, learCred issuernew.LEARCredentialEmployee) (string, error) {

	tlsCertificate, err := s.certSigner.GetTLSCertificate(serialNumber)
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

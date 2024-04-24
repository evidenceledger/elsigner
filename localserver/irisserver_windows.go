package localserver

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/evidenceledger/vcdemo/issuernew"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kataras/iris/v12"
)

// var recordsGlobal CredentialRecords

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
				GetClientCertificate: s.certSigner.GetClientCertificate,
				MinVersion:           tls.VersionTLS13,
				MaxVersion:           tls.VersionTLS13,
			},
		},
	}

	// Send the signed credential back to the server
	resp, err := client.Post("https://issuersec.mycredential.eu/apiadmin/updatesignedcredential", "application/json", buf)
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

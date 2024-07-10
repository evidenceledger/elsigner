package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/evidenceledger/elsigner/x509util"
	"github.com/hesusruiz/vcutils/yaml"
	"github.com/urfave/cli/v2"
	"software.sslmate.com/src/go-pkcs12"
)

const (
	defaultIssuerURLUpdate = "https://issuersec.mycredential.eu/apisigner/updatesignedcredential"

	defaultIssuerURLQuery = "https://issuersec.mycredential.eu/apisigner/retrievecredentials"
)

func main() {

	version := "v0.10.3"

	// Get the version control info, to embed in the program version
	rtinfo, ok := debug.ReadBuildInfo()
	if ok {
		buildSettings := rtinfo.Settings
		for _, setting := range buildSettings {
			if setting.Key == "vcs.time" {
				version = version + ", built on " + setting.Value
			}
			if setting.Key == "vcs.revision" {
				version = version + ", revision " + setting.Value
			}
		}

	}

	app := &cli.App{
		Name:     "elsigner",
		Version:  version,
		Compiled: time.Now(),
		Authors: []*cli.Author{
			{
				Name:  "Jesus Ruiz",
				Email: "hesus.ruiz@gmail.com",
			},
		},
		Usage: "sign a Verifiable Credential with an eIDAS certificate",
		// UsageText: "elsigner [options] [INPUT_FILE] (default input file is index.txt)",
		Action: sign,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "update",
				Required: false,
				Aliases:  []string{"u"},
				Usage:    "the URL of the Issuer update endpoint",
			},
			&cli.StringFlag{
				Name:     "query",
				Required: false,
				Aliases:  []string{"q"},
				Usage:    "the URL of the Issuer query endpoint",
			},
		},

		Commands: []*cli.Command{
			{
				Name:        "create",
				Aliases:     []string{"c"},
				Usage:       "create a test eIDAS certificate",
				Description: "creates a test eIDAs certificate from the data in the 'eidascert.yaml' file",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "password",
						Required: true,
						Aliases:  []string{"p"},
						Usage:    "the password to use for encrypting the resulting certificate file)",
					},
					&cli.StringFlag{
						Name:    "subject",
						Aliases: []string{"s"},
						Usage:   "subject input data `FILE`",
						Value:   "eidascert.yaml",
					},
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Usage:   "write certificate data to `FILE`",
						Value:   "mycert.p12",
					},
				},
				Action: createCACert,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Println("Error:", err)
	}

}

func sign(cCtx *cli.Context) error {
	// The Windows certstore is only available on Windows (obviously!)
	currentOS := runtime.GOOS

	if currentOS != "windows" {
		fmt.Println("This program only works in Windows")
		return nil
	}

	issuerURLQuery := cCtx.String("query")
	if len(issuerURLQuery) == 0 {
		issuerURLQuery = defaultIssuerURLQuery
	}
	issuerURLUpdate := cCtx.String("update")
	if len(issuerURLUpdate) == 0 {
		issuerURLUpdate = defaultIssuerURLUpdate
	}

	startIrisServer(issuerURLQuery, issuerURLUpdate)
	return nil
}

func createCACert(cCtx *cli.Context) error {

	fileName := cCtx.String("subject")
	cd, err := readCertData(fileName)
	if err != nil {
		fmt.Println("file", fileName, "not found, using default values")
		cd = yaml.New("")
	}

	subAttrs := x509util.ELSIName{
		OrganizationIdentifier: cd.String("OrganizationIdentifier", "VATES-55663399H"),
		Organization:           cd.String("Organization", "DOME Marketplace"),
		CommonName:             cd.String("CommonName", "RUIZ JESUS - 12345678V"),
		GivenName:              cd.String("GivenName", "JESUS"),
		Surname:                cd.String("Surname", "RUIZ"),
		EmailAddress:           cd.String("EmailAddress", "jesus@alastria.io"),
		SerialNumber:           cd.String("SerialNumber", "IDCES-12345678V"),
		Country:                cd.String("Country", "ES"),
	}
	fmt.Println(subAttrs)

	keyparams := x509util.KeyParams{
		RsaBits:   2048,
		ValidFrom: "Jan 1 15:04:05 2024",
		ValidFor:  365 * 24 * time.Hour,
	}

	privateKey, newCert, err := x509util.NewCAELSICertificateRaw(subAttrs, keyparams)
	if err != nil {
		return err
	}

	pfxData, err := pkcs12.Modern2023.Encode(privateKey, newCert, nil, cCtx.String("password"))
	if err != nil {
		panic(err)
	}

	outputFileName := cCtx.String("output")
	pfxFile, err := os.OpenFile(outputFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open %s for writing: %v", outputFileName, err)
	}
	_, err = pfxFile.Write(pfxData)
	if err != nil {
		log.Fatalf("Error writing to %s: %v", outputFileName, err)
	}

	if err := pfxFile.Close(); err != nil {
		log.Fatalf("Error closing %s: %v", outputFileName, err)
	}

	fmt.Printf("Certificate created in: %s", outputFileName)
	return nil
}

// readConfiguration reads a YAML file and creates an easy-to navigate structure
func readCertData(certDataFile string) (*yaml.YAML, error) {
	var cfg *yaml.YAML
	var err error

	cfg, err = yaml.ParseYamlFile(certDataFile)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

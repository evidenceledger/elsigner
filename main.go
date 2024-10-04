package main

import (
	"encoding/pem"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/evidenceledger/elsigner/filesigner"
	"github.com/evidenceledger/elsigner/x509util"
	"github.com/hesusruiz/vcutils/yaml"
	"github.com/urfave/cli/v2"
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

	usageText := `elsigner [global options] [command [command options]]

	Started without any command, the program allows the user to connect to a remote Issuer server,
	retrieve the credentials pending for signature, and sign each of them using a local eIDAS certificate.
	The default Issuer to which the program connects can be modified using the global options.

	The program can also generate a test eIDAS certificate to be used for testing, using the command 'create'.
	`

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
		Usage:     "sign a Verifiable Credential with an eIDAS certificate",
		UsageText: usageText,
		Action:    sign,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "update",
				Required: false,
				Aliases:  []string{"u"},
				Usage:    "the URL of the Issuer update endpoint",
				Value:    defaultIssuerURLUpdate,
			},
			&cli.StringFlag{
				Name:     "query",
				Required: false,
				Aliases:  []string{"q"},
				Usage:    "the URL of the Issuer query endpoint",
				Value:    defaultIssuerURLQuery,
			},
		},

		Commands: []*cli.Command{
			{
				Name:        "create",
				Aliases:     []string{"c"},
				Usage:       "create a test eIDAS certificate",
				Description: "creates a test eIDAs certificate from the data in a YAML file",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "password",
						Required: true,
						Aliases:  []string{"p"},
						EnvVars:  []string{"ELSIGNER_PASSWORD"},
						Usage:    "the password to use for encrypting the resulting certificate file",
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
						Value:   "eidascert.p12",
					},
				},
				Action: createCACert,
			},
			{
				Name:        "display",
				Aliases:     []string{"d"},
				Usage:       "display an eIDAS certificate",
				Description: "displays an eIDAs certificate from a PEM file",
				Flags: []cli.Flag{
					// &cli.StringFlag{
					// 	Name:     "password",
					// 	Required: true,
					// 	Aliases:  []string{"p"},
					// 	EnvVars:  []string{"ELSIGNER_PASSWORD"},
					// 	Usage:    "the password to use for decrypting the certificate file",
					// },
					&cli.StringFlag{
						Name:     "input",
						Aliases:  []string{"i"},
						Required: true,
						Usage:    "the name of the `FILE`",
					},
				},
				Action: displayCert,
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

	// Use the default values for the key parameters (RSA, 2048 bits)
	keyparams := x509util.KeyParams{}

	// Create the self-signed CA certificate
	privateKey, newCert, err := x509util.NewCAELSICertificateRaw(subAttrs, keyparams)
	if err != nil {
		return err
	}

	// Save to a file in pkcs12 format, including the private key and the certificate
	outputFileName := cCtx.String("output")
	pass := cCtx.String("password")
	err = filesigner.SaveCertificateToPkcs12File(outputFileName, privateKey, newCert, pass)
	if err != nil {
		return err
	}

	const pemFileName = "cacert_generated.pem"
	pemFile, err := os.OpenFile(pemFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %w", outputFileName, err)
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: newCert.Raw,
	}

	if err := pem.Encode(pemFile, block); err != nil {
		return err
	}

	if err := pemFile.Close(); err != nil {
		return err
	}

	fmt.Printf("Certificate created in: %s\n", outputFileName)
	return nil
}

func displayCert(cCtx *cli.Context) error {

	// Save to a file in pkcs12 format, including the private key and the certificate
	inputFileName := cCtx.String("input")

	pemData, err := os.ReadFile(inputFileName)
	if err != nil {
		return err
	}

	_, issuer, subject, err := x509util.ParseCertificateFromPEM(pemData)
	if err != nil {
		return err
	}

	fmt.Println(issuer)
	fmt.Println(subject)

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

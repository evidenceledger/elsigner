package main

import (
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/evidenceledger/elsigner/filesigner"
	"github.com/evidenceledger/elsigner/x509util"
	"github.com/hesusruiz/vcutils/yaml"
	"github.com/urfave/cli/v2"
)

const (
	defaultIssuerOrigin     = "issuersec.mycredential.eu"
	defaultIssuerQueryPath  = "/apisigner/retrievecredentials"
	defaultIssuerUpdatePath = "/apisigner/updatesignedcredential"
)

func main() {

	version := "v0.10.4"

	// Detect if the program has been invoked by the browser using the custom URI schema 'elsigner'
	if len(os.Args) > 1 {
		if strings.HasPrefix(os.Args[1], "elsigner:") {
			if err := signBrowser(os.Args[1]); err != nil {
				fmt.Println(err)
				return
			}
		}
	}

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
				Name:     "origin",
				Required: false,
				Aliases:  []string{"d"},
				Usage:    "the domain of the Issuer",
				Value:    defaultIssuerOrigin,
			},
			&cli.StringFlag{
				Name:     "query",
				Required: false,
				Aliases:  []string{"q"},
				Usage:    "the path of the Issuer query endpoint",
				Value:    defaultIssuerQueryPath,
			},
			&cli.StringFlag{
				Name:     "update",
				Required: false,
				Aliases:  []string{"u"},
				Usage:    "the path of the Issuer update endpoint",
				Value:    defaultIssuerUpdatePath,
			},
		},

		Commands: []*cli.Command{
			{
				Name:        "create",
				Usage:       "create a leaf test eIDAS certificate",
				Description: "creates a leaf test eIDAs certificate from the data in a YAML file",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "password",
						Required: true,
						Aliases:  []string{"p"},
						EnvVars:  []string{"ELSIGNER_PASSWORD"},
						Usage:    "the password to use for encrypting the resulting certificate file",
					},
					&cli.StringFlag{
						Name:    "cacert",
						Aliases: []string{"ca"},
						Usage:   "CA certificate file in PKCS12 format",
						Value:   "cert_ca.p12",
					},
					&cli.StringFlag{
						Name:    "subject",
						Aliases: []string{"s"},
						Usage:   "subject input data `FILE` in YAML format",
						Value:   "eidascert.yaml",
					},
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Usage:   "write certificate data to `FILE` in PKCS12 format",
						Value:   "eidascert.p12",
					},
				},
				Action: createCert,
			},

			{
				Name:        "createca",
				Usage:       "create a test eIDAS CA certificate as the root certificate",
				Description: "creates a test eIDAs CA certificate from the data in a YAML file",
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

// sign is called when the program is invoked from the command line or clicking on it
func sign(cCtx *cli.Context) error {
	// The Windows certstore is only available on Windows (obviously!)
	currentOS := runtime.GOOS

	if currentOS != "windows" {
		fmt.Println("This program only works in Windows")
		return nil
	}

	issuerOrigin := cCtx.String("origin")
	issuerQueryPath := cCtx.String("query")
	issuerUpdatePath := cCtx.String("update")

	startIrisServer(issuerOrigin, issuerQueryPath, issuerUpdatePath)
	return nil
}

// signBrowser is called when the program is invoked by the browser using the custom scheme
func signBrowser(argument string) error {

	parsedArg, err := url.Parse(argument)
	if err != nil {
		return err
	}
	queryValues := parsedArg.Query()

	issuerOrigin := queryValues.Get("origin")
	issuerQueryPath := queryValues.Get("query")
	issuerUpdatePath := queryValues.Get("update")

	startIrisServer(issuerOrigin, issuerQueryPath, issuerUpdatePath)
	return nil
}

func createCACert(cCtx *cli.Context) error {

	//*******************************
	// Create the CA certificate
	//*******************************

	// Read the data to include in the CA Certificate
	fileName := "cert_ca.yaml"
	cd, err := readCertData(fileName)
	if err != nil {
		fmt.Println("file", fileName, "not found, using default values")
		cd = yaml.New("")
	}

	subAttrs := x509util.ELSIName{
		OrganizationIdentifier: cd.String("OrganizationIdentifier", "VATES-55663399H"),
		Organization:           cd.String("Organization", "DOME Marketplace"),
		CommonName:             cd.String("CommonName", "RUIZ JESUS - 12345678V"),
		Country:                cd.String("Country", "ES"),
	}

	// Use the default values for the key parameters (RSA, 2048 bits)
	keyparams := x509util.KeyParams{}

	// Create the self-signed CA certificate
	privateCAKey, newCACert, err := x509util.NewCAELSICertificateRaw(subAttrs, keyparams)
	if err != nil {
		return err
	}

	// Save to a file in pkcs12 format, including the private key and the certificate
	outputFileName := "cert_ca.p12"
	pass := cCtx.String("password")
	err = filesigner.SaveCertificateToPkcs12File(outputFileName, privateCAKey, newCACert, pass)
	if err != nil {
		return err
	}

	// Save the certificate to a file in PEM format
	const pemFileName = "cert_ca.pem"
	pemFile, err := os.OpenFile(pemFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %w", outputFileName, err)
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: newCACert.Raw,
	}

	if err := pem.Encode(pemFile, block); err != nil {
		return err
	}

	if err := pemFile.Close(); err != nil {
		return err
	}

	//*******************************
	// Create the leaf certificate
	//*******************************

	fileName = "cert.yaml"
	cd, err = readCertData(fileName)
	if err != nil {
		fmt.Println("file", fileName, "not found, using default values")
		cd = yaml.New("")
	}

	subAttrs = x509util.ELSIName{
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

	// Create the entity certificate, signed by the CA certificate
	privateKey, newCert, err := x509util.NewELSICertificateRaw(
		newCACert,
		privateCAKey,
		subAttrs,
		keyparams)
	if err != nil {
		return err
	}

	// Save to a file in pkcs12 format, including the private key and the certificate
	outputFileName = "cert.p12"
	err = filesigner.SaveCertificateToPkcs12File(outputFileName, privateKey, newCert, pass)
	if err != nil {
		return err
	}

	fmt.Printf("Certificate created in: %s\n", outputFileName)
	return nil
}

func createCert(cCtx *cli.Context) error {

	//*******************************
	// Retrieve the CA certificate
	//*******************************

	// Read the data to include in the CA Certificate
	fileName := cCtx.String("cacert")
	pass := cCtx.String("password")

	privateCAKey, newCACert, _, err := filesigner.GetPrivateKeyFromFile(fileName, pass)
	if err != nil {
		return err
	}

	//*******************************
	// Create the leaf certificate
	//*******************************

	// Use the default values for the key parameters (RSA, 2048 bits)
	keyparams := x509util.KeyParams{}

	fileName = cCtx.String("subject")
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

	// Create the entity certificate, signed by the CA certificate
	privateKey, newCert, err := x509util.NewELSICertificateRaw(
		newCACert,
		privateCAKey,
		subAttrs,
		keyparams)
	if err != nil {
		return err
	}

	// Save to a file in pkcs12 format, including the private key and the certificate
	outputFileName := cCtx.String("output")

	err = filesigner.SaveCertificateToPkcs12File(outputFileName, privateKey, newCert, pass)
	if err != nil {
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

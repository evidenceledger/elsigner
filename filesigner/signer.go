package filesigner

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"software.sslmate.com/src/go-pkcs12"
)

// LookupEnvOrString gets a value from the environment or returns the specified default value
func LookupEnvOrString(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func SaveCertificateToPkcs12File(outputFileName string, privateKey any, cert *x509.Certificate, pass string) error {

	pfxData, err := pkcs12.Modern2023.Encode(privateKey, cert, nil, pass)
	if err != nil {
		panic(err)
	}

	pfxFile, err := os.OpenFile(outputFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %w", outputFileName, err)
	}
	_, err = pfxFile.Write(pfxData)
	if err != nil {
		return fmt.Errorf("error writing to %s: %w", outputFileName, err)
	}

	if err := pfxFile.Close(); err != nil {
		return fmt.Errorf("error closing %s: %w", outputFileName, err)
	}

	return nil

}

func GetPrivateKeyFromFile(fileName string, password string) (privateKey any, certificate *x509.Certificate, caCerts []*x509.Certificate, err error) {

	certBinary, err := os.ReadFile(fileName)
	if err != nil {
		return nil, nil, nil, err
	}

	return pkcs12.DecodeChain(certBinary, password)
}

// GetConfigPrivateKey retrieves the private key from a PKCS12 file in the following locations:
// 1) the location specified in the environment variable CERT_FILE_PATH.
// 2) $HOME/.certs/testcert.pfx.
//
// The password used is the following:
// 1) specified in the environment variable CERT_PASSWORD.
// 2) the content of the file specified in the env variable CERT_PASSWORD_FILE.
func GetConfigPrivateKey() (privateKey any, certificate *x509.Certificate, caCerts []*x509.Certificate, err error) {

	userHome, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	certFilePath := LookupEnvOrString("CERT_FILE_PATH", filepath.Join(userHome, ".certs", "testcert.pfx"))
	password := LookupEnvOrString("CERT_PASSWORD", "")
	if len(password) == 0 {
		passwordFilePath := LookupEnvOrString("CERT_PASSWORD_FILE", filepath.Join(userHome, ".certs", "pass.txt"))
		passwordBytes, err := os.ReadFile(passwordFilePath)
		if err != nil {
			return nil, nil, nil, err
		}
		password = string(bytes.TrimSpace(passwordBytes))
	}

	return GetPrivateKeyFromFile(certFilePath, password)
}

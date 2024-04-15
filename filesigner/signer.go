package filesigner

import (
	"bytes"
	"crypto/x509"
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

func GetPrivateKeyFromFile(fileName string, password string) (privateKey any, certificate *x509.Certificate, caCerts []*x509.Certificate, err error) {

	certBinary, err := os.ReadFile(fileName)
	if err != nil {
		return nil, nil, nil, err
	}

	return pkcs12.DecodeChain(certBinary, password)
}

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

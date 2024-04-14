package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/evidenceledger/elsignerw/signer"
	"github.com/evidenceledger/vcdemo/issuernew"
	"github.com/golang-jwt/jwt/v5"
	"software.sslmate.com/src/go-pkcs12"
)

var (
	SigningMethodCert *SigningMethodCertStore
)

func main() {

	// The Windows certstore is only available on Windows (obviously!)
	currentOS := runtime.GOOS

	if currentOS == "windows" {
		validCerts, err := signer.RetrieveValidCertsFromWindows()
		if err != nil {
			panic(err)
		}

		for _, certInfo := range validCerts {
			out, err := json.MarshalIndent(certInfo, "", "  ")
			if err != nil {
				panic(err)
			}
			fmt.Println(string(out))
		}
	}

	startIrisServer()
}

func (s *server) signLEARCredential(serialNumber string, learCred issuernew.LEARCredentialEmployee) (string, error) {

	tlsCertificate, err := s.winSigner.GetTLSCertificate(serialNumber)
	if err != nil {
		return "", err
	}

	signer := tlsCertificate.PrivateKey
	// Sign the credential
	tok, err := issuernew.CreateLEARCredentialJWTtoken(learCred, SigningMethodCert, signer)
	if err != nil {
		return "", err
	}

	return tok, nil
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

// LookupEnvOrString gets a value from the environment or returns the specified default value
func LookupEnvOrString(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

// SigningMethodCertStore implements the RSA family of signing methods.
type SigningMethodCertStore struct {
	Name string
	Hash crypto.Hash
}

func init() {
	// RS256
	SigningMethodCert = &SigningMethodCertStore{"CERTRS256", crypto.SHA256}
	jwt.RegisterSigningMethod(SigningMethodCert.Alg(), func() jwt.SigningMethod {
		return SigningMethodCert
	})

}

func (m *SigningMethodCertStore) Alg() string {
	return m.Name
}

// Verify implements token verification for the SigningMethod
// For this signing method, must be an *rsa.PublicKey structure.
func (m *SigningMethodCertStore) Verify(signingString string, sig []byte, key interface{}) error {
	var rsaKey *rsa.PublicKey
	var ok bool

	if rsaKey, ok = key.(*rsa.PublicKey); !ok {
		return fmt.Errorf("RSA verify expects *rsa.PublicKey")
	}

	// Create hasher
	if !m.Hash.Available() {
		return jwt.ErrHashUnavailable
	}
	hasher := m.Hash.New()
	hasher.Write([]byte(signingString))

	// Verify the signature
	return rsa.VerifyPKCS1v15(rsaKey, m.Hash, hasher.Sum(nil), sig)
}

// Sign implements token signing for the SigningMethod
// For this signing method, must be an *rsa.PrivateKey structure.
func (m *SigningMethodCertStore) Sign(signingString string, key any) ([]byte, error) {
	var ok bool
	var signer crypto.Signer

	if signer, ok = key.(crypto.Signer); !ok {
		return nil, fmt.Errorf("expecting a crypto.Signer key")
	}

	// Digest and sign our message.
	digest := sha256.Sum256([]byte(signingString))
	opt := &rsa.PSSOptions{
		Hash:       crypto.SHA256,
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	}
	signature, err := signer.Sign(rand.Reader, digest[:], opt)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

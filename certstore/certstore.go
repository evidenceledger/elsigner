package certstore

import (
	"crypto/tls"
	"fmt"
	"math/big"
)

type CertInfo struct {
	CommonName       string
	IssuerCommonName string
	KeyUsage         int
	NotAfter         string
	SerialNumber     *big.Int
}

type CertStoreSigner struct {
	ValidCerts              map[string]CertInfo
	DefaultCertSerialNumber string
	DefaultSigner           *CustomSigner
}

func RetrieveValidCertsFromWindows() (map[string]CertInfo, error) {
	return retrieveValidCertsFromWindows()
}

func New() (*CertStoreSigner, error) {
	validCerts, err := retrieveValidCertsFromWindows()
	if err != nil {
		return nil, err
	}

	ws := &CertStoreSigner{}
	ws.ValidCerts = validCerts

	return ws, nil
}

func (ws *CertStoreSigner) GetClientCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	fmt.Printf("Server requested certificate\n")

	serialNumber := ws.DefaultCertSerialNumber
	if len(serialNumber) == 0 {
		return nil, fmt.Errorf("defaultCertSerialNumber not set")
	}
	fmt.Println("GetClientCertificate: serialNumber", serialNumber)

	return ws.GetTLSCertificate(serialNumber)

}

func (ws *CertStoreSigner) GetTLSCertificate(serialNumber string) (*tls.Certificate, error) {
	return ws.getTLSCertificate(serialNumber)
}

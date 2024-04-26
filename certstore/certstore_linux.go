package certstore

import (
	"crypto/tls"
	"fmt"
)

// New connects to the Windows certstore, retrieves all valid certificates and returns them to the caller
func New() (*CertStore, error) {
	return nil, fmt.Errorf("certstore des not exist in Linux")
}

// GetClientCertificate is called by the TLS handshake process, to get a certificate to authenticate to the server
func (ws *CertStore) GetClientCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return nil, fmt.Errorf("certstore des not exist in Linux")
}

package certstore

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"math/big"
)

// TLS cipher suites: https://www.rfc-editor.org/rfc/rfc8446.html#section-9.1
const SupportedAlgorithm = tls.PSSWithSHA256

type CertInfo struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.Signer

	CommonName       string
	IssuerCommonName string
	KeyUsage         int
	NotAfter         string
	SerialNumber     *big.Int
}

type CertStore struct {
	ValidCerts map[string]CertInfo
}

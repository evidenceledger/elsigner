package certstore

import (
	"crypto"
	"crypto/x509"
	"math/big"
)

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
	ValidCerts           map[string]CertInfo
	SelectedSerialNumber string
}

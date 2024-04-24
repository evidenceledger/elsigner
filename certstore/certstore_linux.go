package certstore

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
)

// CustomSigner is a crypto.Signer that uses the client certificate and key to sign
type CustomSigner struct {
	x509Cert *x509.Certificate
}

func (k *CustomSigner) Public() crypto.PublicKey {
	return k.x509Cert.PublicKey
}

func (k *CustomSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	fmt.Printf("crypto.Signer.Sign with key type %T, opts type %T, hash %s\n", k.Public(), opts, opts.HashFunc().String())

	return signature, nil
}

func retrieveValidCertsFromWindows() (map[string]CertInfo, error) {
	// This is not implemented in Linux
	panic("Not implemented in Linux")
}

func (ws *CertStoreSigner) getTLSCertificate(serialNumber string) (*tls.Certificate, error) {
	return nil, nil
}

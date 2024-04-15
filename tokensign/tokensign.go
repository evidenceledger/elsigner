package tokensign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

var (
	SigningMethodCert *SigningMethodCertStore
)

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

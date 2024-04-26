package certstore

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	CRYPT_E_NOT_FOUND = 0x80092004
	// TLS cipher suites: https://www.rfc-editor.org/rfc/rfc8446.html#section-9.1
	supportedAlgorithm = tls.PSSWithSHA256
	windowsStoreName   = "MY"
	nCryptSilentFlag   = 0x00000040 // ncrypt.h NCRYPT_SILENT_FLAG
	bCryptPadPss       = 0x00000008 // bcrypt.h BCRYPT_PAD_PSS
)

var (
	nCrypt         = windows.MustLoadDLL("ncrypt.dll")
	nCryptSignHash = nCrypt.MustFindProc("NCryptSignHash")
)

// New connects to the Windows certstore, retrieves all valid certificates and returns them to the caller
func New() (*CertStore, error) {
	var err error
	ws := &CertStore{}
	ws.ValidCerts, err = ws.RetrieveValidCertsFromWindows()
	if err != nil {
		return nil, err
	}

	return ws, nil
}

func (ws *CertStore) RetrieveValidCertsFromWindows() (map[string]CertInfo, error) {

	// Open the MY certificate store for the current user
	storePtr, err := windows.UTF16PtrFromString(windowsStoreName)
	if err != nil {
		return nil, err
	}
	store, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM,
		0,
		uintptr(0),
		windows.CERT_SYSTEM_STORE_CURRENT_USER,
		uintptr(unsafe.Pointer(storePtr)),
	)
	if err != nil {
		return nil, err
	}

	// Get the current time to check for validity of the certificates
	now := time.Now()

	// Iterate through all certificates in the Windows certstore, selection the ones we want
	validCerts := map[string]CertInfo{}
	var certContext *windows.CertContext
	for {
		certContext, err = windows.CertEnumCertificatesInStore(store, certContext)
		if err != nil {
			if errno, ok := err.(windows.Errno); ok {
				if errno == CRYPT_E_NOT_FOUND {
					break
				}
			}
			fmt.Println(windows.GetLastError())
		}
		if certContext == nil {
			break
		}

		// Create a local copy (ouside of the Windows certstore) of the certificate
		thisEncodedCert := unsafe.Slice(certContext.EncodedCert, certContext.Length)
		buf := bytes.Clone(thisEncodedCert)
		thisX509Cert, err := x509.ParseCertificate(buf)
		if err != nil {
			return nil, err
		}

		// We are interested in not expired certificates (and those that can be used now, so we check for the NotBefore date).
		// And also only in the ones which can be used for signing
		if now.After(thisX509Cert.NotBefore) && now.Before(thisX509Cert.NotAfter) && (thisX509Cert.KeyUsage&x509.KeyUsageDigitalSignature) > 0 {
			fmt.Printf("FOUND!! %s - %v\n", thisX509Cert.Subject.CommonName, thisX509Cert.NotAfter)
			certInfo := CertInfo{
				Certificate:      thisX509Cert,
				CommonName:       thisX509Cert.Subject.CommonName,
				IssuerCommonName: thisX509Cert.Issuer.CommonName,
				KeyUsage:         int(thisX509Cert.KeyUsage),
				NotAfter:         thisX509Cert.NotAfter.Format("2006-01-02"),
				SerialNumber:     thisX509Cert.SerialNumber,
			}

			// Duplicate the Windows certificate context, because it would be freed while iterating the certstore
			dupContext := windows.CertDuplicateCertificateContext(certContext)

			// Create a custom crypto.Signer which is a wrapper to the private key inside the certstore.
			// We do not really have the private key in our program memory, but instead the signature will be
			// performed inside the certstore
			customSigner := &WindowsCertstoreSigner{
				windowsCertContext: dupContext,
				x509Cert:           thisX509Cert,
			}
			certInfo.PrivateKey = customSigner

			validCerts[thisX509Cert.SerialNumber.String()] = certInfo
		}

	}

	return validCerts, nil
}

// WindowsCertstoreSigner is a crypto.Signer that wraps the Windows Certificate Store private keys to enable signatures
type WindowsCertstoreSigner struct {
	windowsCertContext *windows.CertContext
	x509Cert           *x509.Certificate
}

func (k *WindowsCertstoreSigner) Public() crypto.PublicKey {
	return k.x509Cert.PublicKey
}

func (k *WindowsCertstoreSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	fmt.Printf("crypto.Signer.Sign with key type %T, opts type %T, hash %s\n", k.Public(), opts, opts.HashFunc().String())

	// Get private key
	var (
		privateKey                  windows.Handle
		pdwKeySpec                  uint32
		pfCallerFreeProvOrNCryptKey bool
	)
	err = windows.CryptAcquireCertificatePrivateKey(
		k.windowsCertContext,
		windows.CRYPT_ACQUIRE_CACHE_FLAG|windows.CRYPT_ACQUIRE_SILENT_FLAG|windows.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
		nil,
		&privateKey,
		&pdwKeySpec,
		&pfCallerFreeProvOrNCryptKey,
	)
	if err != nil {
		return nil, err
	}

	// We always use RSA-PSS padding
	flags := nCryptSilentFlag | bCryptPadPss
	pPaddingInfo, err := getRsaPssPadding(opts)
	if err != nil {
		return nil, err
	}

	// Sign the digest
	// The first call to NCryptSignHash retrieves the size of the signature
	var size uint32
	success, _, _ := nCryptSignHash.Call(
		uintptr(privateKey),
		uintptr(pPaddingInfo),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(&size)),
		uintptr(flags),
	)
	if success != 0 {
		return nil, fmt.Errorf("NCryptSignHash: failed to get signature length: %#x", success)
	}

	// The second call to NCryptSignHash retrieves the signature
	signature = make([]byte, size)
	success, _, _ = nCryptSignHash.Call(
		uintptr(privateKey),
		uintptr(pPaddingInfo),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(unsafe.Pointer(&signature[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		uintptr(flags),
	)
	if success != 0 {
		return nil, fmt.Errorf("NCryptSignHash: failed to generate signature: %#x", success)
	}
	return signature, nil
}

func getRsaPssPadding(opts crypto.SignerOpts) (unsafe.Pointer, error) {
	pssOpts, ok := opts.(*rsa.PSSOptions)
	if !ok || pssOpts.Hash != crypto.SHA256 {
		return nil, fmt.Errorf("unsupported hash function %s", opts.HashFunc().String())
	}
	if pssOpts.SaltLength != rsa.PSSSaltLengthEqualsHash {
		return nil, fmt.Errorf("unsupported salt length %d", pssOpts.SaltLength)
	}
	sha256, _ := windows.UTF16PtrFromString("SHA256")
	// Create BCRYPT_PSS_PADDING_INFO structure:
	// typedef struct _BCRYPT_PSS_PADDING_INFO {
	// 	LPCWSTR pszAlgId;
	// 	ULONG   cbSalt;
	// } BCRYPT_PSS_PADDING_INFO;
	return unsafe.Pointer(
		&struct {
			pszAlgId *uint16
			cbSalt   uint32
		}{
			pszAlgId: sha256,
			cbSalt:   uint32(pssOpts.HashFunc().Size()),
		},
	), nil
}

package certstore

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"runtime"
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

func (ws *CertStoreSigner) getTLSCertificate(serialNumber string) (*tls.Certificate, error) {

	// Open the certificate store
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

		// Copy the certificate data so that we have our own copy outside the windows context
		encodedCert := unsafe.Slice(certContext.EncodedCert, certContext.Length)
		buf := bytes.Clone(encodedCert)
		foundCert, err := x509.ParseCertificate(buf)
		if err != nil {
			return nil, err
		}
		fmt.Printf("%s - %v\n", foundCert.Subject.CommonName, foundCert.NotAfter)
		if foundCert.SerialNumber.String() == serialNumber {
			fmt.Printf("FOUND!! %s - %v\n", foundCert.Subject.CommonName, foundCert.NotAfter)
			break
		}

	}

	customSigner := &CustomSigner{
		store:              store,
		windowsCertContext: certContext,
	}
	// Set a finalizer to release Windows resources when the CustomSigner is garbage collected.
	runtime.SetFinalizer(
		customSigner, func(c *CustomSigner) {
			_ = windows.CertFreeCertificateContext(c.windowsCertContext)
			_ = windows.CertCloseStore(c.store, 0)
		},
	)

	// Copy the certificate data so that we have our own copy outside the windows context
	encodedCert := unsafe.Slice(certContext.EncodedCert, certContext.Length)
	buf := bytes.Clone(encodedCert)
	foundCert, err := x509.ParseCertificate(buf)
	if err != nil {
		return nil, err
	}

	customSigner.x509Cert = foundCert

	certificate := tls.Certificate{
		Certificate:                  [][]byte{foundCert.Raw},
		PrivateKey:                   customSigner,
		SupportedSignatureAlgorithms: []tls.SignatureScheme{supportedAlgorithm},
	}
	fmt.Printf("Found certificate with common name %s\n", foundCert.Subject.CommonName)
	return &certificate, nil

}

func retrieveValidCertsFromWindows() (map[string]CertInfo, error) {

	// Open the certificate store
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

	// Select valid certificates

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

		// Copy the certificate data so that we have our own copy outside the windows context
		encodedCert := unsafe.Slice(certContext.EncodedCert, certContext.Length)
		buf := bytes.Clone(encodedCert)
		foundCert, err := x509.ParseCertificate(buf)
		if err != nil {
			return nil, err
		}
		fmt.Printf("%s - %v\n", foundCert.Subject.CommonName, foundCert.NotAfter)
		if now.After(foundCert.NotBefore) && now.Before(foundCert.NotAfter) && (foundCert.KeyUsage&x509.KeyUsageDigitalSignature) > 0 {
			fmt.Printf("FOUND!! %s - %v\n", foundCert.Subject.CommonName, foundCert.NotAfter)
			cert := CertInfo{
				CommonName:       foundCert.Subject.CommonName,
				IssuerCommonName: foundCert.Issuer.CommonName,
				KeyUsage:         int(foundCert.KeyUsage),
				NotAfter:         foundCert.NotAfter.Format("2006-01-02"),
				SerialNumber:     foundCert.SerialNumber,
			}

			validCerts[foundCert.SerialNumber.String()] = cert
		}

	}

	return validCerts, nil
}

func (ws *CertStoreSigner) getClientCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	fmt.Printf("Server requested certificate\n")

	serialNumber := ws.DefaultCertSerialNumber
	if len(serialNumber) == 0 {
		return nil, fmt.Errorf("defaultCertSerialNumber not set")
	}
	fmt.Println("GetClientCertificate: serialNumber", serialNumber)

	return ws.getTLSCertificate(serialNumber)

	// // Validate the supported signature schemes.
	// signatureSchemeSupported := false
	// for _, scheme := range info.SignatureSchemes {
	// 	if scheme == supportedAlgorithm {
	// 		signatureSchemeSupported = true
	// 		break
	// 	}
	// }
	// if !signatureSchemeSupported {
	// 	return nil, fmt.Errorf("unsupported signature scheme")
	// }

	// // Open the certificate store
	// storePtr, err := windows.UTF16PtrFromString(windowsStoreName)
	// if err != nil {
	// 	return nil, err
	// }
	// store, err := windows.CertOpenStore(
	// 	windows.CERT_STORE_PROV_SYSTEM,
	// 	0,
	// 	uintptr(0),
	// 	windows.CERT_SYSTEM_STORE_CURRENT_USER,
	// 	uintptr(unsafe.Pointer(storePtr)),
	// )
	// if err != nil {
	// 	return nil, err
	// }

	// // Find the certificate
	// var certContext *windows.CertContext

	// now := time.Now()

	// for {
	// 	certContext, err = windows.CertEnumCertificatesInStore(store, certContext)
	// 	if err != nil {
	// 		if errno, ok := err.(windows.Errno); ok {
	// 			if errno == CRYPT_E_NOT_FOUND {
	// 				break
	// 			}
	// 		}
	// 		fmt.Println(windows.GetLastError())
	// 	}
	// 	if certContext == nil {
	// 		break
	// 	}

	// 	// Copy the certificate data so that we have our own copy outside the windows context
	// 	encodedCert := unsafe.Slice(certContext.EncodedCert, certContext.Length)
	// 	buf := bytes.Clone(encodedCert)
	// 	foundCert, err := x509.ParseCertificate(buf)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	fmt.Printf("%s - %v\n", foundCert.Subject.CommonName, foundCert.NotAfter)
	// 	if now.Before(foundCert.NotAfter) && foundCert.Subject.CommonName == commonName {
	// 		fmt.Printf("FOUND!! %s - %v\n", foundCert.Subject.CommonName, foundCert.NotAfter)
	// 		break
	// 	}

	// }

	// customSigner := &CustomSigner{
	// 	store:              store,
	// 	windowsCertContext: certContext,
	// }
	// // Set a finalizer to release Windows resources when the CustomSigner is garbage collected.
	// runtime.SetFinalizer(
	// 	customSigner, func(c *CustomSigner) {
	// 		_ = windows.CertFreeCertificateContext(c.windowsCertContext)
	// 		_ = windows.CertCloseStore(c.store, 0)
	// 	},
	// )

	// // Copy the certificate data so that we have our own copy outside the windows context
	// encodedCert := unsafe.Slice(certContext.EncodedCert, certContext.Length)
	// buf := bytes.Clone(encodedCert)
	// foundCert, err := x509.ParseCertificate(buf)
	// if err != nil {
	// 	return nil, err
	// }

	// customSigner.x509Cert = foundCert

	// certificate := tls.Certificate{
	// 	Certificate:                  [][]byte{foundCert.Raw},
	// 	PrivateKey:                   customSigner,
	// 	SupportedSignatureAlgorithms: []tls.SignatureScheme{supportedAlgorithm},
	// }
	// fmt.Printf("Found certificate with common name %s\n", foundCert.Subject.CommonName)
	// return &certificate, nil
}

// CustomSigner is a crypto.Signer that uses the client certificate and key to sign
type CustomSigner struct {
	store              windows.Handle
	windowsCertContext *windows.CertContext
	x509Cert           *x509.Certificate
}

func (k *CustomSigner) Public() crypto.PublicKey {
	return k.x509Cert.PublicKey
}

func (k *CustomSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
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

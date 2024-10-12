package certstore

import (
	"fmt"
)

// New connects to the Windows certstore, retrieves all valid certificates and returns them to the caller
func New() (*CertStore, error) {
	return nil, fmt.Errorf("certstore does not exist in Linux")
}

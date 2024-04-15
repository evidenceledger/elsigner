package main

import (
	"encoding/json"
	"fmt"
	"runtime"

	"github.com/evidenceledger/elsignerw/winsigner"
)

func main() {

	// The Windows certstore is only available on Windows (obviously!)
	currentOS := runtime.GOOS

	if currentOS != "windows" {
		fmt.Println("This program only works in Windows")
		return
	}

	if currentOS == "windows" {
		validCerts, err := winsigner.RetrieveValidCertsFromWindows()
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

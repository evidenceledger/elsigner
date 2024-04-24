package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"runtime"

	"github.com/evidenceledger/elsignerw/winsigner"
)

var debug bool

func init() {
	flag.BoolVar(&debug, "debug", false, "debug mode")
}

func main() {

	flag.Parse()

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

	startIrisServer(debug)
}

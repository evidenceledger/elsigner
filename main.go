package main

import (
	"flag"
	"fmt"
	"runtime"
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

	startIrisServer(debug)
}

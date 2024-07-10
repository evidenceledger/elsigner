package main

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/evidenceledger/elsigner/filesigner"
	"github.com/urfave/cli/v2"
)

func main() {

	version := "v0.10.3"

	// Get the version control info, to embed in the program version
	rtinfo, ok := debug.ReadBuildInfo()
	if ok {
		buildSettings := rtinfo.Settings
		for _, setting := range buildSettings {
			if setting.Key == "vcs.time" {
				version = version + ", built on " + setting.Value
			}
			if setting.Key == "vcs.revision" {
				version = version + ", revision " + setting.Value
			}
		}

	}

	app := &cli.App{
		Name:     "certification",
		Version:  version,
		Compiled: time.Now(),
		Authors: []*cli.Author{
			{
				Name:  "Jesus Ruiz",
				Email: "hesus.ruiz@gmail.com",
			},
		},
		Usage: "sign a Verifiable Certification with an eIDAS certificate",
		// UsageText: "elsigner [options] [INPUT_FILE] (default input file is index.txt)",
		Action: sign,
		Commands: []*cli.Command{
			{
				Name:        "verify",
				Aliases:     []string{"c"},
				Usage:       "verify a Verifiable Certification",
				Description: "perform some verifications on a provided Verifiable Certification",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "password",
						Required: true,
						Aliases:  []string{"p"},
						Usage:    "the password to use for encrypting the resulting certificate file)",
					},
					&cli.StringFlag{
						Name:    "subject",
						Aliases: []string{"s"},
						Usage:   "subject input data `FILE`",
						Value:   "eidascert.yaml",
					},
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Usage:   "write certificate data to `FILE`",
						Value:   "mycert.p12",
					},
				},
				Action: sign,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Println("Error:", err)
	}

}

func sign(cCtx *cli.Context) error {
	// The Windows certstore is only available on Windows (obviously!)
	currentOS := runtime.GOOS

	if currentOS != "windows" {
		fmt.Println("This program only works in Windows")
		return nil
	}

	fmt.Println("Hello")

	privateKey, _, _, err := filesigner.GetConfigPrivateKey()
	if err != nil {
		return err
	}

	fmt.Println(privateKey)
	return nil
}

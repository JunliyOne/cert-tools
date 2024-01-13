package cmd

import (
	"cert-tools/certs"
	"flag"
	"fmt"
	"os"
)

var (
	config  string
	output  string
	withP12 bool
)

func init() {
	flag.StringVar(&config, "f", "", "cert config : toml | yaml")
	flag.StringVar(&output, "o", "", "output default config : toml | yaml")
	flag.BoolVar(&withP12, "p12", false, "gen p12")
	flag.Parse()
	if output != "" {
		certs.PrintConfTemp(output)
		os.Exit(0)
	}
	if config == "" {
		fmt.Println("use -h or --help to get more info.")
		os.Exit(0)
	}
}
func Run() {
	c := certs.NewCerts()
	certs.CheckError(certs.ParseFile(c, config))
	for _, cert := range c {
		certs.CheckError(certs.GenCertKeyPair(cert, withP12))
	}
}

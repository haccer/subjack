package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/haccer/subjack/subjack"
)

func main() {
	GOPATH := os.Getenv("GOPATH")
	Project := "/src/github.com/haccer/subjack/"
	configFile := "fingerprints.json"
	defaultConfig := GOPATH + Project + configFile
	defaultDNS := "8.8.8.8"

	o := subjack.Options{}

	flag.StringVar(&o.Domain, "d", "", "Domain.")
	flag.StringVar(&o.Wordlist, "w", "", "Path to wordlist.")
	flag.IntVar(&o.Threads, "t", 10, "Number of concurrent threads (Default: 10).")
	flag.IntVar(&o.Timeout, "timeout", 10, "Seconds to wait before connection timeout (Default: 10).")
	flag.StringVar(&o.DNS, "dns", defaultDNS, "IP of DNS server to use (Default: 8.8.8.8).")
	flag.BoolVar(&o.Ssl, "ssl", false, "Force HTTPS connections (May increase accuracy (Default: http://).")
	flag.BoolVar(&o.All, "a", false, "Find those hidden gems by sending requests to every URL. (Default: Requests are only sent to URLs with identified CNAMEs).")
	flag.BoolVar(&o.Verbose, "v", false, "Display more information per each request.")
	flag.StringVar(&o.Output, "o", "", "Output results to file (Subjack will write JSON if file ends with '.json').")
	flag.StringVar(&o.Config, "c", defaultConfig, "Path to configuration file.")
	flag.BoolVar(&o.Manual, "m", false, "Flag the presence of a dead record, but valid CNAME entry.")

	flag.Parse()

	flag.Usage = func() {
		fmt.Printf("Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	if flag.NFlag() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	subjack.Process(&o)
}

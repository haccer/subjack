package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/haccer/subjack/subjack"
)

func main() {
	o := subjack.Options{}

	flag.StringVar(&o.Domain, "d", "", "Single domain to check.")
	flag.StringVar(&o.Wordlist, "w", "", "Path to wordlist.")
	flag.IntVar(&o.Threads, "t", 10, "Number of concurrent threads.")
	flag.IntVar(&o.Timeout, "timeout", 10, "Seconds to wait before connection timeout.")
	flag.BoolVar(&o.Ssl, "ssl", false, "Force HTTPS connections (may increase accuracy).")
	flag.BoolVar(&o.All, "a", false, "Send requests to every URL, not just those with identified CNAMEs.")
	flag.BoolVar(&o.Verbose, "v", false, "Display more information per request.")
	flag.StringVar(&o.Output, "o", "", "Output results to file (use .json extension for JSON output).")
	flag.BoolVar(&o.Manual, "m", false, "Flag dead CNAME records even if the domain is not available for registration.")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NFlag() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	subjack.Process(&o)
}

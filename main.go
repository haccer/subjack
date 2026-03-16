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
	flag.StringVar(&o.ResolverList, "r", "", "Path to a list of DNS resolvers.")
	flag.BoolVar(&o.Manual, "m", false, "Flag dead CNAME records even if the domain is not available for registration.")
	flag.BoolVar(&o.CheckNS, "ns", false, "Check if nameservers are available for purchase (NS takeover).")
	flag.BoolVar(&o.CheckAR, "ar", false, "Check for stale A records pointing to dead IPs (may require root for ICMP).")
	flag.BoolVar(&o.CheckAXFR, "axfr", false, "Check for zone transfers (AXFR) including NS bruteforce.")
	flag.BoolVar(&o.CheckMail, "mail", false, "Check for SPF include and MX record takeovers.")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	stat, _ := os.Stdin.Stat()
	o.Stdin = (stat.Mode() & os.ModeCharDevice) == 0

	if flag.NFlag() == 0 && !o.Stdin {
		flag.Usage()
		os.Exit(1)
	}

	subjack.Process(&o)
}

package subjack

import (
	"fmt"
	"github.com/miekg/dns"
	"strings"
)

func (s *Subdomain) dns(o *Options) {
	if o.All {
		detect(s.Url, o.Output, o.Ssl, o.Verbose, o.Timeout)
	} else {
		if VerifyCNAME(s.Url) {
			detect(s.Url, o.Output, o.Ssl, o.Verbose, o.Timeout)
		}

		if o.Verbose {
			result := fmt.Sprintf("[Not Vulnerable] %s\n", s.Url)
			c := "\u001b[31;1mNot Vulnerable\u001b[0m"
			out := strings.Replace(result, "Not Vulnerable", c, -1)
			fmt.Printf(out)

			if o.Output != "" {
				if chkJSON(o.Output) {
					writeJSON("", s.Url, o.Output)
				} else {
					write(result, o.Output)
				}
			}
		}
	}
}

func resolve(url string) (cname string) {
	cname = ""
	d := new(dns.Msg)
	d.SetQuestion(url+".", dns.TypeCNAME)
	ret, err := dns.Exchange(d, "8.8.8.8:53")
	if err != nil {
		return
	}

	for _, a := range ret.Answer {
		if t, ok := a.(*dns.CNAME); ok {
			cname = t.Target
		}
	}

	return cname
}

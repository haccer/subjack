package subjack

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/haccer/available"
	"github.com/miekg/dns"
	http "github.com/valyala/fasthttp"
)

type Options struct {
	Wordlist string
	Threads  int
	Timeout  int
	Output   string
	Ssl      bool
	All      bool
	Verbose  bool
}

type Subdomain struct {
	Url string
}

func open(path string) (lines []string, Error error) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalln(err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines, scanner.Err()
}

func Process(o *Options) {
	urls := make(chan *Subdomain, o.Threads*10)
	list, err := open(o.Wordlist)
	if err != nil {
		log.Fatalln(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < o.Threads; i++ {
		wg.Add(1)
		go func() {
			for url := range urls {
				url.dns(o)
			}

			wg.Done()
		}()
	}

	for i := 0; i < len(list); i++ {
		urls <- &Subdomain{Url: list[i]}
	}

	close(urls)
	wg.Wait()
}

func (s *Subdomain) dns(o *Options) {
	if o.All {
		detect(s.Url, o.Output, o.Ssl, o.Verbose, o.Timeout)
	} else {
		if VerifyCNAME(s.Url) {
			detect(s.Url, o.Output, o.Ssl, o.Verbose, o.Timeout)
		}
	}
}

/*
* Triage step to check whether the CNAME matches
* the fingerprinted CNAME of a vulnerable cloud service.
 */
func VerifyCNAME(subdomain string) (match bool) {
	cname := resolve(subdomain)
	match = false

	cnames := []string{
		".cloudfront.net",
		"amazonaws",
		"heroku",
		"wordpress.com",
		"pantheonsite.io",
		"domains.tumblr.com",
		"desk.com",
		"zendesk.com",
		"github.io",
		"fastly",
		"helpjuice.com",
		"helpscoutdocs.com",
		"ghost.io",
		"cargocollective.com",
		"redirect.feedpress.me",
		"myshopify.com",
		"statuspage.io",
		"uservoice.com",
		"surge.sh",
		"bitbucket.io",
		"custom.intercom.help",
		"proxy.webflow.com",
		"landing.subscribepage.com",
		"endpoint.mykajabi.com",
		"thinkific.com",
		"teamwork.com",
		"clientaccess.tave.com",
		"wishpond.com",
		"aftership.com",
		"ideas.aha.io",
		"domains.tictail.com",
		"cname.mendix.net",
		"bcvp0rtal.com",
		"brightcovegallery.com",
		"gallery.video",
		"bigcartel.com",
		"activehosted.com",
		"createsend.com",
		"acquia-test.co",
		"proposify.biz",
		"simplebooklet.com",
		".gr8.com",
		"vendecommerce.com",
		"myjetbrains.com",
		".azurewebsites.net",
		".cloudapp.net",
		".trafficmanager.net",
		".blob.core.windows.net",
	}

	for _, cn := range cnames {
		if strings.Contains(cname, cn) {
			match = true
			break
		}
	}

	return match
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

func detect(url, output string, ssl, verbose bool, timeout int) {
	service := Identify(url, ssl, timeout)

	if service != "" {
		result := fmt.Sprintf("[%s] %s\n", service, url)
		c := fmt.Sprintf("\u001b[32;1m%s\u001b[0m", service)
		out := strings.Replace(result, service, c, -1)
		fmt.Printf(out)

		if output != "" {
			write(result, output)
		}
	}

	if service == "" && verbose {
		result := fmt.Sprintf("[Not Vulnerable] %s\n", url)
		c := "\u001b[31;1mNot Vulnerable\u001b[0m"
		out := strings.Replace(result, "Not Vulnerable", c, -1)
		fmt.Printf(out)

		if output != "" {
			write(result, output)
		}
	}
}

/*
* This function aims to identify whether the subdomain
* is attached to a vulnerable cloud service and able to
* be taken over.
 */
func Identify(subdomain string, forceSSL bool, timeout int) (service string) {
	body := get(subdomain, forceSSL, timeout)

	cname := resolve(subdomain)

	if len(cname) <= 3 {
		cname = ""
	}

	service = ""

	azure := []string{
		".azurewebsites.net",
		".cloudapp.net",
		".trafficmanager.net",
		".blob.core.windows.net",
	}

	if _, err := net.LookupHost(subdomain); err != nil {
		if strings.Contains(fmt.Sprintln(err), "no such host") {
			for _, az := range azure {
				if strings.Contains(cname, az) {
					service = "AZURE"
					break
				}
			}

			dead := available.Domain(cname)
			if dead {
				service = "DOMAIN - " + subdomain
			}
		}
	}

	fingerprints := map[string]string{
		"ERROR: The request could not be satisfied":                                                  "CLOUDFRONT",
		"Fastly error: unknown domain":                                                               "FASTLY",
		"There isn't a Github Pages site here.":                                                      "GITHUB",
		"herokucdn.com/error-pages/no-such-app.html":                                                 "HEROKU",
		"The gods are wise, but do not know of the site which you seek.":                             "PANTHEON",
		"Whatever you were looking for doesn't currently exist at this address.":                     "TUMBLR",
		"Do you want to register":                                                                    "WORDPRESS",
		"Sorry, We Couldn't Find That Page":                                                          "DESK",
		"Help Center Closed":                                                                         "ZENDESK",
		"Oops - We didn't find your site.":                                                           "TEAMWORK",
		"We could not find what you're looking for.":                                                 "HELPJUICE",
		"No settings were found for this company:":                                                   "HELPSCOUT",
		"The specified bucket does not exist":                                                        "S3 BUCKET",
		"The thing you were looking for is no longer here, or never was":                             "GHOST",
		"<title>404 &mdash; File not found</title>":                                                  "CARGO",
		"The feed has not been found.":                                                               "FEEDPRESS",
		"Sorry, this shop is currently unavailable.":                                                 "SHOPIFY",
		"You are being <a href=\"https://www.statuspage.io\">redirected":                             "STATUSPAGE",
		"This UserVoice subdomain is currently available!":                                           "USERVOICE",
		"project not found":                                                                          "SURGE",
		"Repository not found":                                                                       "BITBUCKET",
		"This page is reserved for artistic dogs.":                                                   "INTERCOM",
		"<h1 class=\"headline\">Uh oh. That page doesn’t exist.</h1>":                                "INTERCOM",
		"<p class=\"description\">The page you are looking for doesn't exist or has been moved.</p>": "WEBFLOW",
		"Not found": "MAILERLITE",
		"<h1>The page you were looking for doesn't exist.</h1>":                                   "KAJABI",
		"You may have mistyped the address or the page may have moved.":                           "THINKIFIC",
		"<h1>Error 404: Page Not Found</h1>":                                                      "TAVE",
		"https://www.wishpond.com/404?campaign=true":                                              "WISHPOND",
		"Oops.</h2><p class=\"text-muted text-tight\">The page you're looking for doesn't exist.": "AFTERSHIP",
		"There is no portal here ... sending you back to Aha!":                                    "AHA",
		"to target URL: <a href=\"https://tictail.com":                                            "TICTAIL",
		"Start selling on Tictail.":                                                               "TICTAIL",
		"<p class=\"bc-gallery-error-code\">Error Code: 404</p>":                                  "BRIGHTCOVE",
		"<h1>Oops! We couldn&#8217;t find that page.</h1>":                                        "BIGCARTEL",
		"alt=\"LIGHTTPD - fly light.\"":                                                           "ACTIVECAMPAIGN",
		"Double check the URL or <a href=\"mailto:help@createsend.com":                            "CAMPAIGNMONITOR",
		"The site you are looking for could not be found.":                                        "ACQUIA",
		"If you need immediate assistance, please contact <a href=\"mailto:support@proposify.biz": "PROPOSIFY",
		"We can't find this <a href=\"https://simplebooklet.com":                                  "SIMPLEBOOKLET",
		"With GetResponse Landing Pages, lead generation has never been easier":                   "GETRESPONSE",
		"Looks like you've traveled too far into cyberspace.":                                     "VEND",
		"is not a registered InCloud YouTrack.":                                                   "JETBRAINS",
	}

	for f, _ := range fingerprints {
		if bytes.Contains(body, []byte(f)) {
			service = fingerprints[f]
			break
		}
	}

	// 2nd round - Ruling out false positives.
	switch service {
	case "CARGO":
		if !bytes.Contains(body, []byte("cargocollective.com")) {
			service = ""
		}
	case "CLOUDFRONT":
		if !bytes.Contains(body, []byte("Bad request.")) {
			service = ""
		} else {
			if !forceSSL {
				bd := https(subdomain, forceSSL, timeout)
				if len(bd) != 0 && !bytes.Contains(bd, []byte("Bad request.")) {
					service = ""
				}
			}
		}
	case "KAJABI":
		if !bytes.Contains(body, []byte("Use title if it's in the page YAML frontmatter")) {
			service = ""
		}
	case "THINKIFIC":
		if !bytes.Contains(body, []byte("iVBORw0KGgoAAAANSUhEUgAAAf")) {
			service = ""
		}
	case "TAVE":
		if !bytes.Contains(body, []byte("tave.com")) {
			service = ""
		}
	case "PROPOSIFY":
		if !bytes.Contains(body, []byte("The page you requested was not found.")) {
			service = ""
		}
	case "MAILERLITE":
		size := len(body)
		if size != 9 && !strings.Contains("landing.subscribepage.com", cname) {
			service = ""
		}
	case "ACTIVECAMPAIGN":
		size := len(body)
		if size != 844 {
			service = ""
		}
	}

	return service
}

func get(url string, ssl bool, timeout int) (body []byte) {
	req := http.AcquireRequest()
	req.SetRequestURI(site(url, ssl))
	resp := http.AcquireResponse()

	client := &http.Client{}
	client.DoTimeout(req, resp, time.Duration(timeout)*time.Second)

	return resp.Body()
}

func https(url string, ssl bool, timeout int) (body []byte) {
	newUrl := "https://" + url
	body = get(newUrl, ssl, timeout)

	return body
}

func site(url string, ssl bool) (site string) {
	site = "http://" + url
	if ssl {
		site = "https://" + url
	}

	return site
}

func write(result, output string) {
	f, err := os.OpenFile(output, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		log.Fatalln(err)
	}

	defer f.Close()

	_, err = f.WriteString(result)
	if err != nil {
		log.Fatalln(err)
	}
}

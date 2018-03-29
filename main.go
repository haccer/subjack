package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/caffix/amass/amass"
)

type Options struct {
	Domain     string
	Wordlist   string
	Threads    int
	Timeout    int
	Output     string
	Ssl        bool
	All        bool
	SaveSubs   string
	DomainList string
	Brute      bool
	Recursive  bool
	Alts       bool
}

type Subdomain struct {
	Url string
}

type Enum struct {
	Results chan *amass.AmassRequest
	Finish  chan struct{}
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

func site(url string, ssl bool) (site string) {
	if ssl {
		site = fmt.Sprintf("https://%s", url)
	} else {
		site = fmt.Sprintf("http://%s", url)
	}

	return site
}

func get(url string, ssl bool, timeout int) (body []byte) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	req, err := http.NewRequest("GET", site(url, ssl), nil)
	if err != nil {
		return
	}

	req.Header.Add("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		return
	}

	defer resp.Body.Close()

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	return body
}

func https(url string, ssl bool, timeout int) (body []byte) {
	newUrl := fmt.Sprintf("https://%s", url)
	body = get(newUrl, ssl, timeout)

	return body
}

func identify(url string, ssl bool, timeout int) (service string) {
	body := get(url, ssl, timeout)

	service = ""

	// First round
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
		"Unrecognized domain <strong>":                                                               "MASHERY",
		"Repository not found":                                                                       "BITBUCKET",
		"The requested URL was not found on this server.":                                            "UNBOUNCE",
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
		"is not a registered InCloud YouTrack.": "JETBRAINS",
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
			if ssl {
				bd := https(url, ssl, timeout)
				if bytes.Contains(bd, []byte("<Code>AccessDenied</Code>")) {
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
		if size != 9 {
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

func detect(url, output string, ssl bool, timeout int) {
	service := identify(url, ssl, timeout)

	if service != "" {
		result := fmt.Sprintf("[%s] %s\n", service, url)

		fmt.Printf(result)

		if output != "" {
			write(result, output)
		}
	}
}

func (s *Subdomain) DNS(a *Options) {
	if a.All {
		detect(s.Url, a.Output, a.Ssl, a.Timeout)
	} else {
		cname, err := net.LookupCNAME(s.Url)
		if err != nil {
			return
		}

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
			"mashery.com",
			"bitbucket.io",
			"unbouncepages.com",
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
		}

		for _, cn := range cnames {
			if strings.Contains(cname, cn) {
				detect(s.Url, a.Output, a.Ssl, a.Timeout)
			}
		}
	}
}

func enumOut(e *Enum, a *Options) {
	for {
		select {
		case result := <-e.Results:
			if a.SaveSubs != "" {
				saveResult := fmt.Sprintf("%s\n", result.Name)
				write(saveResult, a.SaveSubs)
			}

			url := &Subdomain{Url: result.Name}
			url.DNS(a)
		case <-e.Finish:
			break
		}
	}
}

func enumerate(a *Options) {
	results := make(chan *amass.AmassRequest, a.Threads*10)
	finish := make(chan struct{})
	var err error

	go enumOut(&Enum{
		Results: results,
		Finish:  finish,
	}, a)

	var wordlist []string
	if a.Wordlist != "" {
		wordlist, err = open(a.Wordlist)
		if err != nil {
			log.Fatalln(err)
		}
	}

	rand.Seed(time.Now().UTC().UnixNano())
	config := amass.CustomConfig(&amass.AmassConfig{
		Output:       results,
		Wordlist:     wordlist,
		BruteForcing: a.Brute,
		Recursive:    a.Recursive,
		Alterations:  a.Alts,
	})

	domains := []string{a.Domain}

	if a.DomainList != "" {
		domains, err = open(a.DomainList)
		if err != nil {
			log.Fatalln(err)
		}
	}

	config.AddDomains(domains)
	amass.StartEnumeration(config)
}

func process(a *Options) {
	urls := make(chan *Subdomain, a.Threads*10)
	list, err := open(a.Wordlist)
	if err != nil {
		log.Fatalln(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < a.Threads; i++ {
		wg.Add(1)
		go func() {
			for url := range urls {
				url.DNS(a)
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

func conflict(msg string) {
	fmt.Println(msg)
	os.Exit(1)
}

func main() {
	a := Options{}

	flag.StringVar(&a.Domain, "d", "", "Use amass to enumerate DNS and check subdomains.")
	flag.StringVar(&a.Wordlist, "w", "", "Path to wordlist.")
	flag.IntVar(&a.Threads, "t", 10, "Number of concurrent threads (Default: 10).")
	flag.IntVar(&a.Timeout, "timeout", 10, "Seconds to wait before connection timeout (Default: 10).")
	flag.StringVar(&a.Output, "o", "", "Output file to write results to.")
	flag.BoolVar(&a.Ssl, "ssl", false, "Force HTTPS connections (May increase accuracy. Default: http://).")
	flag.BoolVar(&a.All, "a", false, "Find those hidden gems by sending requests to every URL. (Default: Requests are only sent to URLs with identified CNAMEs).")

	// Enumeration options
	flag.StringVar(&a.SaveSubs, "save", "", "Output file to write subdomains saved with amass to.")
	flag.StringVar(&a.DomainList, "dL", "", "Path to domains list.")
	flag.BoolVar(&a.Brute, "brute", false, "Enable subdomain brute forcing.")
	flag.BoolVar(&a.Recursive, "r", false, "Enable recursive subdomain brute forcing.")
	flag.BoolVar(&a.Alts, "alts", false, "Enable subdomain alterations.")

	flag.Parse()

	flag.Usage = func() {
		fmt.Printf("Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	if flag.NFlag() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	if a.Domain != "" || a.DomainList != "" {
		if a.Domain != "" && a.DomainList != "" {
			conflict("[-] Please use -d or -dL.")
		}

		if a.Wordlist != "" && !a.Brute {
			conflict("[-] Please enable brute forcing with -w, or use -d alone.")
		}

		if a.Brute {
			if a.Wordlist != "" {
				conflict("[-] Please specify a wordlist to brute force with.")
			}
		}

		enumerate(&a)
	} else {
		if a.SaveSubs != "" {
			conflict("[-] Please use -save with -d.")
		}

		if a.DomainList != "" {
			conflict("[-] Please use -dL with -d.")
		}

		if a.Brute {
			conflict("[-] Please use -brute with -d.")
		}

		if a.Recursive {
			conflict("[-] Please use -r with -d.")
		}

		if a.Alts {
			conflict("[-] Please use -alts with -d.")
		}

		process(&a)
	}
}

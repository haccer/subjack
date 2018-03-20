package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	Wordlist = flag.String("w", "", "Path to wordlist.")
	Threads  = flag.Int("t", 10, "Number of concurrent threads (Default: 10).")
	Timeout  = flag.Int("timeout", 10, "Seconds to wait before connection timeout (Default: 10).")
	Output   = flag.String("o", "", "Output file to write results to.")
	Https    = flag.Bool("https", false, "Force HTTPS connections (May increase accuracy. Default: http://).")
	Strict   = flag.Bool("strict", false, "Find those hidden gems by sending HTTP requests to ever URL. (Default: HTTP requests are only sent to URLs with cloud CNAMEs).")
)

type Http struct {
	Url string
}

func getDomains(path string) (lines []string, Error error) {
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

func write(result string) {
	f, err := os.OpenFile(*Output, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		log.Fatalln(err)
	}

	defer f.Close()

	_, err = f.WriteString(result)
	if err != nil {
		log.Fatalln(err)
	}
}

func Site(url string) (site string) {
	if *Https {
		site = fmt.Sprintf("https://%s", url)
	} else {
		site = fmt.Sprintf("http://%s", url)
	}

	return site
}

func get(url string) (body []byte) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(*Timeout) * time.Second,
	}

	req, err := http.NewRequest("GET", Site(url), nil)
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

func Identify(url string) (service string) {
	body := get(url)

	service = ""

	// First round
	fingerprints := map[string]string{
		"ERROR: The request could not be satisfied":                              "CLOUDFRONT",
		"Fastly error: unknown domain":                                           "FASTLY",
		"There isn't a Github Pages site here.":                                  "GITHUB",
		"herokucdn.com/error-pages/no-such-app.html":                             "HEROKU",
		"The gods are wise, but do not know of the site which you seek.":         "PANTHEON",
		"Whatever you were looking for doesn't currently exist at this address.": "TUMBLR",
		"Do you want to register":                                                "WORDPRESS",
		"Sorry, We Couldn't Find That Page":                                      "DESK",
		"Help Center Closed":                                                     "ZENDESK",
		"Oops - We didn't find your site.":                                       "TEAMWORK",
		"We could not find what you're looking for.":                             "HELPJUICE",
		"No settings were found for this company:":                               "HELPSCOUT",
		"The specified bucket does not exist":                                    "S3 BUCKET",
		"The thing you were looking for is no longer here, or never was":         "GHOST",
		"<title>404 &mdash; File not found</title>":                              "CARGO",
		"The feed has not been found.":                                           "FEEDPRESS",
		"May be this is still fresh!":                                            "FRESHDESK",
		"Sorry, this shop is currently unavailable.":                             "SHOPIFY",
		"You are being <a href=\"https://www.statuspage.io\">redirected":         "STATUSPAGE",
		"This UserVoice subdomain is currently available!":                       "USERVOICE",
		"project not found":                                                      "SURGE",
		"Unrecognized domain <strong>":                                           "MASHERY",
		"Repository not found":                                                   "BITBUCKET",
		"The requested URL was not found on this server.":                        "UNBOUNCE",
	}

	for f, _ := range fingerprints {
		if bytes.Contains(body, []byte(f)) {
			service = fingerprints[f]
			break
		}
	}

	// 2nd round
	switch service {
	case "CARGO":
		if !bytes.Contains(body, []byte("cargocollective.com")) {
			service = ""
		}
	}

	return service
}

func Detect(url string) {
	service := Identify(url)

	if service != "" {
		result := fmt.Sprintf("[%s] %s\n", service, url)

		fmt.Printf(result)

		if *Output != "" {
			write(result)
		}
	}
}

func (s *Http) DNS() {
	if *Strict {
		Detect(s.Url)
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
			"freshdesk.com",
			"myshopify.com",
			"statuspage.io",
			"uservoice.com",
			"surge.sh",
			"mashery.com",
			"bitbucket.io",
			"unbouncepages.com",
		}

		for _, cn := range cnames {
			if strings.Contains(cname, cn) {
				Detect(s.Url)
			}
		}
	}
}

func Process() {
	urls := make(chan *Http, *Threads*10)
	list, err := getDomains(*Wordlist)
	if err != nil {
		log.Fatalln(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < *Threads; i++ {
		wg.Add(1)
		go func() {
			for url := range urls {
				url.DNS()
			}

			wg.Done()
		}()
	}

	for i := 0; i < len(list); i++ {
		urls <- &Http{Url: list[i]}
	}

	close(urls)

	wg.Wait()
}

func main() {
	flag.Parse()

	flag.Usage = func() {
		fmt.Printf("Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	if flag.NFlag() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	Process()
}

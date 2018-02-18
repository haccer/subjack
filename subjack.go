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
	Url, Num string
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

	if _, err = f.WriteString(result); err != nil {
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

	fingerprints := map[string]string{
		"ERROR: The request could not be satisfied":                                                              "CLOUDFRONT",
		"Fastly error: unknown domain":                                                                           "FASTLY",
		"There isn't a Github Pages site here.":                                                                  "GITHUB",
		"herokucdn.com/error-pages/no-such-app.html":                                                             "HEROKU",
		"The gods are wise, but do not know of the site which you seek.":                                         "PANTHEON",
		"Whatever you were looking for doesn't currently exist at this address.":                                 "TUMBLR",
		"Do you want to register":                                                                                "WORDPRESS",
		"Sorry, We Couldn't Find That Page":                                                                      "DESK",
		"Help Center Closed":                                                                                     "ZENDESK",
		"Oops - We didn't find your site.":                                                                       "TEAMWORK",
		"We could not find what you're looking for.":                                                             "HELPJUICE",
		"No settings were found for this company:":                                                               "HELPSCOUT",
		"The specified bucket does not exist":                                                                    "S3 BUCKET",
		"The thing you were looking for is no longer here, or never was":                                         "GHOST",
		"If you're moving your domain away from Cargo you must make this configuration through your registrar":   "CARGO",
		"The feed has not been found.":                                                                           "FEEDPRESS",
		"May be this is still fresh!":                                                                            "FRESHDESK",
		"Sorry, this shop is currently unavailable.":                                                             "SHOPIFY",
		"You are being <a href=\"https://www.statuspage.io\">redirected":                                         "STATUSPAGE",
		"This domain is successfully pointed at WP Engine, but is not configured for an account on our platform": "WPENGINE",
		"This UserVoice subdomain is currently available!":                                                       "USERVOICE",
		"project not found":                                                                                      "SURGE",
		"Unrecognized domain <strong>":                                                                           "MASHERY",
	}

	for f, _ := range fingerprints {
		if bytes.Contains(body, []byte(f)) {
			service = fingerprints[f]
			break
		}
	}

	return service
}

func RandChar() string {
	chars := []string{
		"ｦ", "ｧ", "ｨ", "ｩ", "ｪ",
		"ｫ", "ｬ", "ｭ", "ｮ", "ｯ",
		"ｱ", "ｲ", "ｳ", "ｴ", "ｵ",
		"ｶ", "ｷ", "ｸ", "ｹ", "ｺ",
		"ｻ", "ｼ", "ｽ", "ｾ", "ｿ",
		"ﾀ", "ﾁ", "ﾂ", "ﾃ", "ﾄ",
		"ﾅ", "ﾆ", "ﾇ", "ﾈ", "ﾉ",
		"ﾊ", "ﾋ", "ﾌ", "ﾍ", "ﾎ",
		"ﾏ", "ﾐ", "ﾑ", "ﾒ", "ﾓ",
		"ﾔ", "ﾕ", "ﾖ", "ﾗ", "ﾘ",
		"ﾙ", "ﾚ", "ﾛ", "ﾜ", "ﾝ",
	}

	rand.Seed(time.Now().Unix())
	num := rand.Int() % len(chars)

	return chars[num]
}

func Detect(url, num string) {
	service := Identify(url)

	// Clears previous line -- needs to be optimized in the future.
	fmt.Printf("\r%s", strings.Repeat(" ", 100))

	if service != "" {
		result := fmt.Sprintf("[%s] %s\n", service, url)

		fmt.Printf("\r%s", result)

		if *Output != "" {
			write(result)
		}
	} else {
		fmt.Printf("\r")
	}

	fmt.Printf("\r[ \u001b[34m%s\u001b[0m Domains \001b[31m%s\u001b[0m - Last Request to %s ]", RandChar(), num, url)
}

func (s *Http) DNS() {
	if *Strict {
		Detect(s.Url, s.Num)
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
			"wpengine.com",
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
		}

		for _, cn := range cnames {
			if strings.Contains(cname, cn) {
				Detect(s.Url, s.Num)
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
		Progress := fmt.Sprintf("%d", len(list))
		urls <- &Http{Url: list[i], Num: Progress}
	}

	close(urls)

	wg.Wait()

	fmt.Printf("\r%s", strings.Repeat(" ", 100))
	fmt.Printf("\rTask completed.\n")
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

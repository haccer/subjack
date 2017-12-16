package main

import (
  "bufio"
  "bytes"
  "crypto/tls"
  "fmt"
  "flag"
  "io/ioutil"
  "log"
  "net"
  "net/http"
  "os"
  "strings"
  "sync"
  "syscall"
  "time"
)

var (
  Wordlist = flag.String("w", "", "Path to the wordlist.")
  Threads  = flag.Int("t", 10, "Number of concurrent threads.")
  Timeout  = flag.Int("timeout", 10, "Seconds to wait before timeout connection.")
  Output   = flag.String("o", "", "Output file to write results to.")
  Https    = flag.Bool("https", false, "Force HTTPS (May increase accuracy. Default: http://).")
  Strict   = flag.Bool("strict", false, "Find those hidden gems by sending HTTP requests to every URL. (Default: HTTP requests are only sent to URLs with cloud CNAMEs).")
)

type Http struct {
  Url string
}

func getDomains(path string) ([]string, error) {
  file, err := os.Open(path)
  if err != nil {
    log.Fatalln(err)
  }
  defer file.Close()

  var lines []string
  scanner := bufio.NewScanner(file)
  for scanner.Scan() {
    lines = append(lines, scanner.Text())
  }
  return lines, scanner.Err()
}

func write(result string) {
  f, err := os.OpenFile(*Output, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0660)
  if err != nil {
    log.Fatalln(err)
  }
  defer f.Close()

  if _, err = f.WriteString(result); err != nil {
    log.Fatalln(err)
  }
}

func get(url string) {
  var site string
  if *Https {
    site = fmt.Sprintf("https://%s", url)
  } else {
    site = fmt.Sprintf("http://%s", url)
  }

  tr := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
  }
  client := &http.Client{
    Transport: tr,
    Timeout: time.Duration(*Timeout) * time.Second,
  }
  resp, err := client.Get(site)
  if err != nil {
    return
  }
  defer resp.Body.Close()
  body, err := ioutil.ReadAll(resp.Body)
  if err != nil {
    return
  }

  var result string
  if bytes.Contains(body, []byte("ERROR: The request could not be satisfied")) {
    if bytes.Contains(body, []byte("Bad request.")) {
      result = fmt.Sprintf("[CLOUDFRONT]  %s \n", url)
    }
  }
  if bytes.Contains(body, []byte("Fastly error: unknown domain")) {
    result = fmt.Sprintf("[FASTLY]  %s \n", url)
  }
  if bytes.Contains(body, []byte("There isn't a GitHub Pages site here.")) {
    result = fmt.Sprintf("[GITHUB]  %s \n", url)
  }
  if bytes.Contains(body, []byte("herokucdn.com/error-pages/no-such-app.html")) {
    result = fmt.Sprintf("[HEROKU]  %s \n", url)
  }
  if bytes.Contains(body, []byte("The gods are wise, but do not know of the site which you seek.")) {
    result = fmt.Sprintf("[PANTHEON]  %s \n", url)
  }
  if bytes.Contains(body, []byte("Whatever you were looking for doesn't currently exist at this address.")) {
    result = fmt.Sprintf("[TUMBLR]  %s \n", url)
  }
  if bytes.Contains(body, []byte("Do you want to register")) {
    result = fmt.Sprintf("[WORDPRESS]  %s \n", url)
  }
  if bytes.Contains(body, []byte("Sorry, We Couldn't Find That Page")) {
    result = fmt.Sprintf("[DESK]  %s \n", url)
  }
  if bytes.Contains(body, []byte("Help Center Closed")) {
    result = fmt.Sprintf("[ZENDESK]  %s \n", url)
  }
  if bytes.Contains(body, []byte("Oops - We didn't find your site.")) {
    result = fmt.Sprintf("[TEAMWORK]  %s \n", url)
  }
  if bytes.Contains(body, []byte("We could not find what you're looking for.")) {
    result = fmt.Sprintf("[HELPJUICE]  %s \n", url)
  }
  if bytes.Contains(body, []byte("No settings were found for this company:")) {
    result = fmt.Sprintf("[HELPSCOUT]  %s \n", url)
  }
  if bytes.Contains(body, []byte("The specified bucket does not exist")) {
    result = fmt.Sprintf("[S3 BUCKET]  %s \n", url)
  }
  if bytes.Contains(body, []byte("The thing you were looking for is no longer here, or never was")) {
    result = fmt.Sprintf("[GHOST]  %s \n", url)
  }
  if bytes.Contains(body, []byte("If you're moving your domain away from Cargo you must make this configuration through your registrar's DNS control panel.")) {
    result = fmt.Sprintf("[CARGO]  %s \n", url)
  }
  if bytes.Contains(body, []byte("The feed has not been found.")) {
    result = fmt.Sprintf("[FEEDPRESS]  %s \n", url)
  }
  if bytes.Contains(body, []byte("May be this is still fresh!")) {
    result = fmt.Sprintf("[FRESHDESK]  %s \n", url)
  }
  if bytes.Contains(body, []byte("Sorry, this shop is currently unavailable.")) {
    result = fmt.Sprintf("[SHOPIFY]  %s \n", url)
  }
  if bytes.Contains(body, []byte("You are being <a href=\"https://www.statuspage.io\">redirected")) {
    result = fmt.Sprintf("[STATUSPAGE]  %s \n", url)
  }
  if bytes.Contains(body, []byte("This domain is successfully pointed at WP Engine, but is not configured for an account on our platform")) {
    result = fmt.Sprintf("[WPENGINE]  %s \n", url)
  }
  if bytes.Contains(body, []byte("This UserVoice subdomain is currently available!")) {
    result = fmt.Sprintf("[USERVOICE]  %s \n", url)
  }
  if bytes.Contains(body, []byte("project not found")) {
    result = fmt.Sprintf("[SURGE]  %s \n", url)
  }

  if strings.ContainsAny(result, "[]") {
    fmt.Printf(result)

    if *Output != "" {
      write(result)
    }
  }
}

func (s *Http) DNS() {

  if *Strict {
    get(s.Url)
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
      ".freshdesk.com",
      ".myshopify.com",
      ".statuspage.io",
      ".uservoice.com",
      ".surge.sh",
    }

    for _, cn := range cnames {
      if strings.Contains(cname, cn) {
        get(s.Url)
      }
    }
  }
}

func magic() {
  /* For large files: This raises the system's ulimit. */
  var rLimit syscall.Rlimit
  err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
  if err != nil {
    fmt.Println("Error Getting Rlimit ", err)
  }
  // In the special case your domain list is over 1 mil, increase these numbers.
  rLimit.Max = 999999
  rLimit.Cur = 999999
  err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
  if err != nil {
    fmt.Println("Error Setting Rlimit ", err)
  }
  err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
  if err != nil {
    fmt.Println("Error Getting Rlimit ", err)
  }
}

func main() {
  flag.Parse()
  
  flag.Usage = func() {
    fmt.Printf("Usage of %s:\n", os.Args[0])
    flag.PrintDefaults()
  }

  if flag.NArg() == 0 {
    flag.Usage()
    os.Exit(1)
  }
  
  urls := make(chan *Http, *Threads * 10)
  list, err := getDomains(*Wordlist)
  if err != nil {
    log.Fatalln(err)
  }
  
  if len(list) > 1024 {
    magic()
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

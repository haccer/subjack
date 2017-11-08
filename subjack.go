package main

import (
  "bufio"
  "bytes"
  "crypto/tls"
  "fmt"
  "flag"
  "io/ioutil"
  "log"
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

func (s *Http) Get() {
  var site string
  if *Https {
    site = fmt.Sprintf("https://%v", s.Url)
  } else {
    site = fmt.Sprintf("http://%v", s.Url)
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
      result = fmt.Sprintf("[CLOUDFRONT]  %v \n", s.Url)
    }
  }
  if bytes.Contains(body, []byte("Fastly error: unknown domain")) {
    result = fmt.Sprintf("[FASTLY]  %v \n", s.Url)
  }
  if bytes.Contains(body, []byte("There isn't a GitHub Pages site here.")) {
    result = fmt.Sprintf("[GITHUB]  %v \n", s.Url)
  }
  if bytes.Contains(body, []byte("herokucdn.com/error-pages/no-such-app.html")) {
    result = fmt.Sprintf("[HEROKU]  %v \n", s.Url)
  }
  if bytes.Contains(body, []byte("The gods are wise, but do not know of the site which you seek.")) {
    result = fmt.Sprintf("[PANTHEON]  %v \n", s.Url)
  }
  if bytes.Contains(body, []byte("Whatever you were looking for doesn't currently exist at this address.")) {
    result = fmt.Sprintf("[TUMBLR]  %v \n", s.Url)
  }
  if bytes.Contains(body, []byte("Do you want to register")) {
    result = fmt.Sprintf("[WORDPRESS]  %v \n", s.Url)
  }
  if bytes.Contains(body, []byte("Sorry, We Couldn't Find That Page")) {
    result = fmt.Sprintf("[DESK]  %v \n", s.Url)
  }
  if bytes.Contains(body, []byte("Help Center Closed")) {
    result = fmt.Sprintf("[ZENDESK]  %v \n", s.Url)
  }
  if bytes.Contains(body, []byte("Oops - We didn't find your site.")) {
    result = fmt.Sprintf("[TEAMWORK]  %v \n", s.Url)
  }
  if bytes.Contains(body, []byte("We could not find what you're looking for.")) {
    result = fmt.Sprintf("[HELPJUICE]  %v \n", s.Url)
  }
  if bytes.Contains(body, []byte("No settings were found for this company:")) {
    result = fmt.Sprintf("[HELPSCOUT]  %v \n", s.Url)
  }
  if bytes.Contains(body, []byte("The specified bucket does not exist")) {
    result = fmt.Sprintf("[S3 BUCKET]  %v \n", s.Url)
  }
  if bytes.Contains(body, []byte("The thing you were looking for is no longer here, or never was")) {
    result = fmt.Sprintf("[GHOST]  %v \n", s.Url)
  }
  if bytes.Contains(body, []byte("If you're moving your domain away from Cargo you must make this configuration through your registrar's DNS control panel.")) {
    result = fmt.Sprintf("[CARGO]  %v \n", s.Url)
  }
  if bytes.Contains(body, []byte("The feed has not been found.")) {
    result = fmt.Sprintf("[FEEDPRESS]  %v \n", s.Url)
  }
  if bytes.Contains(body, []byte("May be this is still fresh!")) {
    result = fmt.Sprintf("[FRESHDESK]  %v \n", s.Url)
  }
  if bytes.Contains(body, []byte("Sorry, this shop is currently unavailable.")) {
    result = fmt.Sprintf("[SHOPIFY]  %v \n", s.Url)
  }
  if bytes.Contains(body, []byte("You are being <a href=\"https://www.statuspage.io\">redirected")) {
    result = fmt.Sprintf("[STATUSPAGE]  %v \n", s.Url)
  }
  if bytes.Contains(body, []byte("This domain is successfully pointed at WP Engine, but is not configured for an account on our platform")) {
    result = fmt.Sprintf("[WPENGINE]  %v \n", s.Url)
  }
  if bytes.Contains(body, []byte("This UserVoice subdomain is currently available!")) {
    result = fmt.Sprintf("[USERVOICE]  %v \n", s.Url)
  }
  if bytes.Contains(body, []byte("project not found")) {
    result = fmt.Sprintf("[SURGE]  %v \n", s.Url)
  }

  if strings.ContainsAny(result, "[]") {
    fmt.Printf(result)

    if *Output != "" {
      write(result)
    }
  }
}

func magic() {
  /* For large files */
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

func banner() {
  blue := "\x1b[1;36m"
  red := "\x1b[1;31m"
  clear := "\x1b[0m"

  ascii := fmt.Sprintf(`%s
    ████████  ███    ███ █████████  ███████████ ███      ████████  ███    ███
   █▒█    ███ █▒█    ███ ███    ███     ███   ███ ███   ███    ███ ███   ███
   ██▒        ███    ██▒ ▒█▒    ██▒     ██▒  ▒█▒   ▒█▒  ███        ██▒  ▒██
   █▒█▒█▒▒▒▒▒ █▒▒    ▒██ █████▒▒▒▒      ▒▒█ ▒▒▒▒█▒▒▒▒▒█ ▒██        ██▒▒██▒
          ▒▒▒ ▒░▒    ▒▒█ ▒█▒    ▒░▒     ▒░█ ▒░▒     ▒▒▒ ▒█▒        ▒▒▒  ▒▒▒
   ░▒░    ░▒░ ░▒░    ░▒░ ░▒░    ░▒░ ░▒░ ░▒░ ░▒░     ░▒░ ░▒░    ░▒░ ░▒░   ░▒░
     ░░░░░░     ░░░░░░    ░░░░░░░     ░░░    ░       ░    ░░░░░░    ░      ░

        %s~[ H 0 S T I L E  S U B D 0 M A I N  T A K E 0 V E R  T 0 0 L ]~
                    For support, ping me on Twitter: @now
  %s`, blue, red, clear)

  fmt.Println(ascii)
}

func main() {
  flag.Parse()
  
  banner()

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
        url.Get()
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

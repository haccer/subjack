package subjack

import (
	"bufio"
	"log"
	"os"
	"sync"
)

type Options struct {
	Domain       string
	Wordlist     string
	Threads      int
	Timeout      int
	Output       string
	Ssl          bool
	All          bool
	Verbose      bool
	Manual       bool
	CheckNS      bool
	CheckAR      bool
	CheckAXFR    bool
	CheckMail    bool
	CheckSRV     bool
	ResolverList string
	Stdin        bool
	fingerprints []Fingerprint
	resolvers    []string
	sem          chan struct{}
	// checkAvailable overrides domain-availability lookups; used by tests.
	checkAvailable func(domain string) bool
}

func Process(o *Options) {
	var list []string
	var err error

	if o.Threads <= 0 {
		o.Threads = 10
	}
	if o.Timeout <= 0 {
		o.Timeout = 10
	}

	if len(o.Domain) > 0 {
		list = append(list, o.Domain)
	} else if o.Wordlist != "" {
		list, err = readLines(o.Wordlist)
		if err != nil {
			log.Fatalln(err)
		}
	}

	o.fingerprints = loadFingerprints()

	if o.Output != "" {
		initOutput(o.Output)
	}

	if o.ResolverList != "" {
		o.resolvers, err = readLines(o.ResolverList)
		if err != nil {
			log.Fatalln(err)
		}
	}

	o.sem = make(chan struct{}, o.Threads)

	urls := make(chan string, o.Threads*10)
	wg := new(sync.WaitGroup)

	for i := 0; i < o.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range urls {
				check(url, o)
			}
		}()
	}

	if o.Stdin {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			urls <- scanner.Text()
		}
	} else {
		for _, u := range list {
			urls <- u
		}
	}

	close(urls)
	wg.Wait()
}

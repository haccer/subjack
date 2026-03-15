package subjack

import (
	"log"
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
	ResolverList string
	fingerprints []Fingerprint
	resolvers    []string
}

func Process(o *Options) {
	var list []string
	var err error

	if len(o.Domain) > 0 {
		list = append(list, o.Domain)
	} else {
		list, err = readLines(o.Wordlist)
	}

	if err != nil {
		log.Fatalln(err)
	}

	o.fingerprints = loadFingerprints()

	if o.ResolverList != "" {
		o.resolvers, err = readLines(o.ResolverList)
		if err != nil {
			log.Fatalln(err)
		}
	}

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

	for _, u := range list {
		urls <- u
	}

	close(urls)
	wg.Wait()
}

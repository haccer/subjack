package subjack

import (
	"log"
	"sync"
)

type Options struct {
	Domain   string
	Wordlist string
	Threads  int
	Timeout  int
	Output   string
	Ssl      bool
	All      bool
	Verbose  bool
	Config   string
	Manual   bool
	NoColor  bool
}

type Subdomain struct {
	Url string
}

/* Start processing subjack from the defined options. */
func Process(o *Options) {
	urls := make(chan *Subdomain, o.Threads*10)
	list, err := open(o.Wordlist)
	if err != nil {
		log.Fatalln(err)
	}

	wg := new(sync.WaitGroup)

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

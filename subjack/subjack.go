package subjack

import (
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
	Config       string
	ConfigFile   string
	Manual       bool
	Fingerprints []Fingerprints
}

type Subdomain struct {
	Url string
}

/* Start processing subjack from the defined options. */
func Process(o *Options) (err error) {
	var list []string

	urls := make(chan *Subdomain, o.Threads*10)

	// Load fingerprints
	if o.ConfigFile != "" {
		custom_fingerprints, err := readFile(o.ConfigFile)
		if err != nil {
			return err
		}
		o.Fingerprints, err = fingerprints(custom_fingerprints)
		if err != nil {
			return err
		}
	} else {
		// No error checking here because the default fingerprints are
		// hard-coded into the binary.
		o.Fingerprints, _ = fingerprints([]byte(o.Config))
	}

	// Load domain list
	if len(o.Domain) > 0 {
		list = append(list, o.Domain)
	} else {
		list, err = readFileLines(o.Wordlist)
	}

	if err != nil {
		return err
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
	return nil
}

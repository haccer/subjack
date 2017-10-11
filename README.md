# subjack

subjack is a Hostile Subdomain Takeover tool written in Go designed to scan a list of subdomains concurrently and identify ones that are able to be hijacked. With Go's speed and efficiency, this tool really stands out when it comes to mass-testing. Always double check the results manually to rule out false positives. 

## Installing

You need have [Go](https://golang.org/) installed. Full details of installation and set up can be found [here](https://golang.org/doc/install). 

`go build subjack.go`

## How To Use:

`./subjack -w domains.txt -t 100 -timeout 30 -o results.txt -https`
- `-w domains.txt` is your list of subdomains. I recommend using `cname.sh` (included in repository) to sift through your subdomain list for ones that have CNAME records attached and use that list to optimize and speed up testing.
- `-t` is the number of threads (Default: 10 threads). 
- `-timeout` is the seconds to wait before timeout connection (Default: 10 seconds).
- `-o results.txt` where to save results to (Optional).
- `-https` enforces https requests which may return a different set of results and increase accuracy (Optional).

Currently checks for:
- Amazon S3 Bucket
- Amazon Cloudfront
- Cargo
- Fastly
- FeedPress 
- Ghost
- Github 
- Helpjuice 
- Help Scout
- Heroku 
- Pantheon.io
- Shopify
- Surge 
- Tumblr
- UserVoice
- WordPress  
- WP Engine

## Screenshots

<img src="https://i.imgur.com/2bZF0Ge.png" />

## Practical Use

I've included `scanio.sh` which is kind of a PoC script to mass-locate vulnerable subdomains using results from Rapid7's Project Sonar. This script parses and greps through the dump for desired CNAME records and makes a large list of subdomains to check with subjack if they're vulnerable to Hostile Subdomain Takeover. Of course this isn't the only method to get a large amount of data to test. **Please use this responsibly ;)**

## Contact

Shout me out on Twitter: [@now](https://twitter.com/now)

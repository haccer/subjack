# subjack

[![Build Status](https://api.travis-ci.org/haccer/subjack.svg?branch=master)](https://travis-ci.org/haccer/subjack) [![Build status](https://ci.appveyor.com/api/projects/status/dm8f2yyjcbn3j1cm?svg=true&passingText=Windows%20-%20OK&failingText=Windows%20-%20failed&pendingText=Windows%20-%20pending)](https://ci.appveyor.com/project/haccer/subjack) [![Go Report Card](https://goreportcard.com/badge/github.com/haccer/subjack)](https://goreportcard.com/report/github.com/haccer/subjack) [![GitHub license](https://img.shields.io/github/license/haccer/subjack.svg)](https://github.com/haccer/subjack/blob/master/LICENSE)

Subjack is a Hostile Subdomain Takeover tool written in Go designed to scan a list of subdomains concurrently and identify ones that are able to be hijacked. With Go's speed and efficiency, this tool really stands out when it comes to mass-testing. Always double check the results manually to rule out false positives.

**New:**
> Subjack now has a subdomain discovery option that uses [Jeff Foley](https://twitter.com/@jeff_foley)'s [amass](https://github.com/caffix/amass) to discover subdomains and test them immediately.

Subjack uses amass integration to:
- enumerate subdomains of a specified domain or from a list of domains.
- brute force subdomains with a wordlist.
- enumerate subdomains recursively and/or with alterations.
- save subdomains enumerated with amass integration.

**Also New:**
Subjack will check for subdomains attached to domains that don't exist (NXDOMAIN) and are **available to be registered**. No need for dig ever again! This is still cross-compatible too.

## Installing

Requires [Go](https://golang.org/dl/) >= 1.10.

`go get -u github.com/haccer/subjack`

## How To Use:

Examples: 
- `./subjack -w subdomains.txt -t 100 -timeout 30 -o results.txt -ssl`
- `./subjack -d example.com -brute -w subdomain_wordlist.txt`
- `./subjack -dL domains.txt -alts -save subdomains.txt -o results.txt`

Options:
- `-d domain.com` is a domain you want to gather subdomains for with [amass](https://github.com/caffix/amass).
- `-w domains.txt` is your list of subdomains.
- `-t` is the number of threads (Default: 10 threads). 
- `-timeout` is the seconds to wait before timeout connection (Default: 10 seconds).
- `-o results.txt` where to save results to.
- `-ssl` enforces HTTPS requests which may return a different set of results and increase accuracy.
- `-a` skips CNAME check and sends requests to every URL.
- `-save subdomains.txt` is to save subdomains enumerated with amass (Use with -d or -dL).
- `-dL domains.txt` is a list of domains to enumerate subdomains using amass.
- `-brute` enables subdomain brute forcing (Use with -d or -dL).
- `-r` enables recursive subdomain brute forcing (Use with -d or -dL).
- `-alts` enables subdomain alterations (Use with -d or -dL).

Currently checks for (44 Services):
> Acquia Cloud Site Factory, ActiveCampaign, AfterShip, Aha!, Amazon S3 Bucket, Amazon Cloudfront, Big Cartel, Bitbucket, Brightcove, Campaign Monitor, Cargo Collective, Desk, Fastly, FeedPress, GetResponse, Ghost, Github, Helpjuice, Help Scout, Heroku, Intercom, JetBrains, Kajabi, MailerLite, Mashery, Microsoft Azure, Pantheon.io, Proposify, Shopify, simplebooklet, StatusPage, Surge, Táve, Teamwork, Thinkific, Tictail, Tumblr, Unbounce, UserVoice, Vend Ecommerce, Webflow, Wishpond, WordPress, Zendesk

<!--
## Screenshots
<img src="https://i.imgur.com/xfjSuwW.jpg" />
<img src="https://i.imgur.com/2bZF0Ge.png" />
-->

## In Action
![realtime](https://github.com/haccer/haccer.github.io/blob/master/img/subjack1.gif)

## Practical Use

You can use [scanio.sh](https://gist.github.com/haccer/3698ff6927fc00c8fe533fc977f850f8) which is kind of a PoC script to mass-locate vulnerable subdomains using results from Rapid7's Project Sonar. This script parses and greps through the dump for desired CNAME records and makes a large list of subdomains to check with subjack if they're vulnerable to Hostile Subdomain Takeover. Of course this isn't the only method to get a large amount of data to test. **Please use this responsibly ;)**

## Docker
```
docker run --name subjack --rm -v <path to wordlist or save dir>:/data c0dy/subjack
```

## FAQ
**Q:** What should my wordlist look like?

**A:** Your wordlist should include a list of subdomains you're checking and should look something like:
```
assets.cody.su
assets.github.com
b.cody.su
big.example.com
cdn.cody.su
dev.cody.su
dev2.twitter.com
```

**Q:** I ran my scan and nothing happened. What does this mean?

**A:** In most cases, this means that subjack didn't discover any vulnerable subdomains in your wordlist or your wordlist of is formatted weird.

## References
Extra information about Hostile Subdomain Takeovers:

- [https://cody.su/blog/Hostile-Subdomain-Takeovers/](https://cody.su/blog/Hostile-Subdomain-Takeovers/)
- [https://github.com/EdOverflow/can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)
- [https://labs.detectify.com/2014/10/21/hostile-subdomain-takeover-using-herokugithubdesk-more/](https://labs.detectify.com/2014/10/21/hostile-subdomain-takeover-using-herokugithubdesk-more/)

## Contact

Shout me out on Twitter: [@now](https://twitter.com/now)

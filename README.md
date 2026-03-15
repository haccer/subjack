# subjack

[![Go Report Card](https://goreportcard.com/badge/github.com/haccer/subjack)](https://goreportcard.com/report/github.com/haccer/subjack)
[![GoDoc](https://godoc.org/github.com/haccer/subjack/subjack?status.svg)](http://godoc.org/github.com/haccer/subjack/subjack)
[![GitHub license](https://img.shields.io/github/license/haccer/subjack.svg)](https://github.com/haccer/subjack/blob/master/LICENSE)

<p align="center">
  <img src="subjack.png" alt="subjack logo">
  <br>
  <b>Subdomain Takeover Tool</b>
</p>

Subjack is a subdomain takeover tool written in Go designed to scan a list of subdomains concurrently and identify ones that are able to be hijacked. With Go's speed and efficiency, this tool really stands out when it comes to mass-testing. Always double check the results manually to rule out false positives.

Subjack will also check for subdomains attached to domains that don't exist (NXDOMAIN) and are **available to be registered**. No need for dig ever again!

## Installing

Requires [Go](https://golang.org/dl/)

```
go install github.com/haccer/subjack@latest
```

## Usage

```
subjack -w subdomains.txt -t 100 -timeout 30 -o results.txt -ssl
```

| Flag | Description | Default |
|------|-------------|---------|
| `-d` | Single domain to check | |
| `-w` | Path to wordlist of subdomains | |
| `-t` | Number of concurrent threads | `10` |
| `-timeout` | Seconds to wait before connection timeout | `10` |
| `-o` | Output results to file (use `.json` extension for JSON output) | |
| `-ssl` | Force HTTPS connections (may increase accuracy) | `false` |
| `-a` | Send requests to every URL, not just those with identified CNAMEs **(recommended)** | `false` |
| `-m` | Flag dead CNAME records even if the domain is not available for registration | `false` |
| `-r` | Path to a list of DNS resolvers (one IP per line, falls back to `8.8.8.8` on failure) | |
| `-v` | Display more information per request | `false` |

## Practical Use

You can use [scanio.sh](https://gist.github.com/haccer/3698ff6927fc00c8fe533fc977f850f8) which is kind of a PoC script to mass-locate vulnerable subdomains using results from Rapid7's Project Sonar. This script parses and greps through the dump for desired CNAME records and makes a large list of subdomains to check with subjack if they're vulnerable to hostile subdomain takeover. **Please use this responsibly.**

## Wordlist Format

Your wordlist should include a list of subdomains, one per line:

```
assets.xen.world
assets.github.com
b.xen.world
big.example.com
cdn.xen.world
dev.xen.world
dev2.twitter.com
```

## References

Extra information about hostile subdomain takeovers:

- [Can I take over XYZ?](https://github.com/EdOverflow/can-i-take-over-xyz)
- [Hostile Subdomain Takeover using Heroku/GitHub/Desk + More](https://labs.detectify.com/2014/10/21/hostile-subdomain-takeover-using-herokugithubdesk-more/)

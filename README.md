# subjack

[![Go Report Card](https://goreportcard.com/badge/github.com/haccer/subjack)](https://goreportcard.com/report/github.com/haccer/subjack)
[![GoDoc](https://godoc.org/github.com/haccer/subjack/subjack?status.svg)](http://godoc.org/github.com/haccer/subjack/subjack)
[![GitHub license](https://img.shields.io/github/license/haccer/subjack.svg)](https://github.com/haccer/subjack/blob/master/LICENSE)

<p align="center">
  <img src="subjack.png" alt="subjack logo">
  <br>
  <b>DNS Takeover Scanner</b>
</p>

Subjack is a DNS takeover scanner written in Go designed to scan a list of domains concurrently and identify ones that are able to be hijacked. With Go's speed and efficiency, this tool really stands out when it comes to mass-testing. Always double check the results manually to rule out false positives.

Subjack detects:

- **CNAME takeovers** — dangling CNAMEs pointing to unclaimed third-party services
- **NS delegation takeovers** — expired nameserver domains and dangling cloud DNS zones (Route 53, Google Cloud DNS, Azure DNS, DigitalOcean, Vultr, Linode)
- **Stale A records** — A records pointing to dead IPs on cloud providers (AWS, GCP, Azure, DigitalOcean, Linode, Vultr, Oracle)
- **Zone transfers (AXFR)** — misconfigured nameservers leaking entire zone files, with NS hostname bruteforcing
- **SPF include takeovers** — expired domains in SPF `include:` directives enabling email spoofing
- **MX record takeovers** — expired mail server domains enabling email interception
- **CNAME chain takeovers** — multi-level CNAME chains where intermediate targets are claimable
- **SRV record takeovers** — SRV records pointing to expired/registrable domains
- **NXDOMAIN registration** — domains that don't exist and are available to be registered

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
| `-ns` | Check for NS takeovers (expired NS domains + dangling cloud DNS delegations) | `false` |
| `-ar` | Check for stale A records pointing to dead IPs (may require root for ICMP) | `false` |
| `-axfr` | Check for zone transfers (AXFR) including NS bruteforce | `false` |
| `-mail` | Check for SPF include and MX record takeovers | `false` |
| `-v` | Display more information per request | `false` |

## Stdin Support

Subjack can read domains from stdin, making it easy to pipe output from other tools:

```
subfinder -d example.com | subjack -ssl -o results.json
cat domains.txt | subjack -t 20 -o results.txt
```

## Nameserver Takeover

With the `-ns` flag, subjack performs two types of nameserver takeover checks:

**Expired NS domains**: Checks if any of a domain's nameservers have expired and are available for purchase. An attacker who registers an expired nameserver can take full control of all DNS for that domain — they can point any record anywhere, intercept email, issue certificates, and more.

**Dangling NS delegations**: Detects when a domain's NS records point to cloud DNS providers but the hosted zone has been deleted. Subjack queries each nameserver directly for an SOA record — if all return `SERVFAIL` or `REFUSED`, the zone is gone and potentially claimable. Supported providers:

- AWS Route 53 (`ns-*.awsdns-*`)
- Google Cloud DNS (`ns-cloud-*.googledomains.com`)
- Azure DNS (`ns*-*.azure-dns.*`)
- DigitalOcean DNS (`ns*.digitalocean.com`)
- Vultr DNS (`ns*.vultr.com`)
- Linode DNS (`ns*.linode.com`)

```
subjack -w subdomains.txt -ns -o results.json
```

## Stale A Record Detection

With the `-ar` flag, subjack will resolve A records and check if the IP address is actually alive. When a company terminates a cloud server but forgets to remove the DNS A record, the IP gets released back to the provider's pool. An attacker can spin up new instances on that provider until they land on the same IP, gaining control of the subdomain.

Subjack identifies the cloud provider (AWS, GCP, Azure, DigitalOcean, Linode, Vultr, Oracle) when possible, making it easier to target the right platform. Detection uses ICMP ping (requires root) with a TCP fallback on ports 80/443.

```
sudo subjack -w subdomains.txt -ar -o results.json
```

Results are flagged as `STALE A RECORD` and should be verified manually — a non-responding IP doesn't always mean it's reclaimable.

## Zone Transfer Detection

With the `-axfr` flag, subjack will attempt DNS zone transfers (AXFR) which can expose an entire domain's DNS records. Subjack goes beyond just testing the domain's official nameservers — it also bruteforces common nameserver hostnames (`ns1`, `dns-0`, `ns-backup`, etc.) because hidden or forgotten nameservers are often left unsecured even after the primary ones have been locked down.

```
subjack -d example.com -axfr -o results.json
subjack -w domains.txt -axfr -o results.json
```

Results are flagged as `ZONE TRANSFER` with the vulnerable nameserver and number of records exposed.

## Email Takeover Detection

With the `-mail` flag, subjack checks for two email-based takeover vectors:

**SPF include takeover**: Parses SPF TXT records and checks if any `include:` domains are expired and available for registration. An attacker who registers the included domain can send fully authenticated emails as the target, bypassing SPF and DMARC.

**MX record takeover**: Checks if any MX record targets are expired and available for registration. An attacker who controls the mail server can intercept all inbound email — password resets, 2FA codes, and more.

```
subjack -w domains.txt -mail -o results.json
```

## CNAME Chain and SRV Detection

These checks run automatically on every scan:

**CNAME chain takeover**: Follows multi-level CNAME chains (up to 10 deep) and checks if any intermediate target is claimable. Standard CNAME detection only checks the first hop — chains catch deeper takeover opportunities.

**SRV record takeover**: Checks common SRV records (SIP, XMPP, LDAP, Kerberos, IMAP, CalDAV, etc.) for targets that are expired and available for registration.

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

Extra information about DNS takeovers:

- [Can I take over XYZ?](https://github.com/EdOverflow/can-i-take-over-xyz)
- [Hostile Subdomain Takeover using Heroku/GitHub/Desk + More](https://labs.detectify.com/2014/10/21/hostile-subdomain-takeover-using-herokugithubdesk-more/)
- [Can I take over DNS?](https://github.com/indianajson/can-i-take-over-dns)

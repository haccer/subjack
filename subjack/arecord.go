package subjack

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// cloudCIDRs maps cloud providers to their known IP ranges.
var cloudCIDRs = map[string][]string{
	"AWS": {
		"3.0.0.0/8",
		"13.36.0.0/14",
		"13.204.0.0/14",
		"13.208.0.0/14",
		"13.236.0.0/14",
		"13.248.0.0/14",
		"18.192.0.0/15",
		"18.232.0.0/14",
		"52.0.0.0/11",
		"54.144.0.0/14",
		"54.248.0.0/15",
		"107.20.0.0/14",
	},
	"GCP": {
		"34.0.0.0/9",
		"35.184.0.0/13",
		"104.196.0.0/14",
	},
	"Azure": {
		"13.64.0.0/11",
		"20.0.0.0/11",
		"20.32.0.0/11",
		"20.64.0.0/10",
		"20.128.0.0/16",
		"20.184.0.0/13",
		"40.64.0.0/10",
		"40.112.0.0/13",
		"51.0.0.0/11",
		"52.96.0.0/12",
		"104.208.0.0/13",
	},
	"DigitalOcean": {
		"45.55.0.0/16",
		"46.101.0.0/17",
		"68.183.0.0/16",
		"104.131.0.0/18",
		"104.236.0.0/16",
		"107.170.0.0/16",
		"128.199.0.0/18",
		"134.122.0.0/16",
		"134.209.0.0/17",
		"137.184.0.0/16",
		"138.68.0.0/16",
		"138.197.0.0/16",
		"139.59.0.0/17",
		"142.93.0.0/16",
		"143.198.0.0/16",
		"159.65.0.0/16",
		"162.243.0.0/17",
		"167.71.0.0/16",
		"188.166.0.0/17",
	},
	"Linode": {
		"45.33.0.0/17",
		"45.56.64.0/18",
		"45.79.0.0/16",
		"50.116.0.0/18",
		"69.164.192.0/19",
		"96.126.96.0/19",
		"104.237.128.0/19",
		"139.144.0.0/16",
		"139.162.0.0/17",
		"172.104.0.0/15",
		"172.232.0.0/13",
	},
	"Vultr": {
		"45.32.0.0/16",
		"64.176.0.0/18",
		"66.55.128.0/19",
		"66.135.0.0/19",
		"108.61.0.0/19",
		"139.84.128.0/18",
		"139.180.128.0/18",
		"149.28.0.0/16",
		"155.138.0.0/17",
		"207.246.0.0/16",
		"216.238.64.0/18",
	},
	"Oracle": {
		"129.80.0.0/16",
		"129.144.0.0/16",
		"130.35.0.0/16",
		"130.61.0.0/16",
		"132.145.0.0/16",
		"138.1.0.0/16",
		"138.2.0.0/16",
		"140.238.0.0/16",
		"141.147.0.0/16",
		"144.21.0.0/16",
		"150.136.0.0/16",
		"152.67.0.0/16",
		"152.69.0.0/16",
		"158.101.0.0/16",
	},
}

// parsedNets is built once from cloudCIDRs for fast lookups.
var parsedNets []cloudNet

type cloudNet struct {
	provider string
	network  *net.IPNet
}

func init() {
	for provider, cidrs := range cloudCIDRs {
		for _, cidr := range cidrs {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			parsedNets = append(parsedNets, cloudNet{provider: provider, network: network})
		}
	}
}

func identifyProvider(ip net.IP) string {
	for _, cn := range parsedNets {
		if cn.network.Contains(ip) {
			return cn.provider
		}
	}
	return ""
}

func resolveA(domain string, o *Options) []net.IP {
	msg := new(dns.Msg)
	msg.SetQuestion(domain+".", dns.TypeA)
	resp, err := dnsExchange(msg, o.resolvers, time.Duration(o.Timeout)*time.Second)
	if err != nil {
		return nil
	}

	var ips []net.IP
	for _, a := range resp.Answer {
		if t, ok := a.(*dns.A); ok {
			ips = append(ips, t.A)
		}
	}
	return ips
}

func isHostDead(ip string, timeout time.Duration) bool {
	// Try ICMP ping first (requires root)
	conn, err := net.DialTimeout("ip4:icmp", ip, timeout)
	if err == nil {
		conn.Close()
		// Connection succeeded — host might be alive, verify with actual ping
		return !ping(ip, timeout)
	}

	// Fall back to TCP connect on common ports
	for _, port := range []string{"80", "443"} {
		conn, err := net.DialTimeout("tcp", ip+":"+port, timeout)
		if err == nil {
			conn.Close()
			return false
		}
	}
	return true
}

func ping(ip string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("ip4:icmp", ip, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	// ICMP Echo Request
	msg := []byte{
		8, 0, 0, 0, // Type 8 (Echo), Code 0, Checksum placeholder
		0, 1, 0, 1, // Identifier, Sequence
	}
	// Calculate checksum
	cs := icmpChecksum(msg)
	msg[2] = byte(cs >> 8)
	msg[3] = byte(cs)

	if _, err := conn.Write(msg); err != nil {
		return false
	}

	buf := make([]byte, 128)
	_, err = conn.Read(buf)
	return err == nil
}

func icmpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return ^uint16(sum)
}

func checkARecord(domain string, o *Options) {
	ips := resolveA(domain, o)
	if len(ips) == 0 {
		return
	}

	timeout := time.Duration(o.Timeout) * time.Second
	for _, ip := range ips {
		if !isHostDead(ip.String(), timeout) {
			continue
		}

		provider := identifyProvider(ip)
		var service, detail string
		if provider != "" {
			service = "STALE A RECORD"
			detail = fmt.Sprintf("%s (%s) - IP %s appears dead", domain, provider, ip)
		} else {
			service = "STALE A RECORD"
			detail = fmt.Sprintf("%s - IP %s appears dead", domain, ip)
		}

		fmt.Printf("[%s%s%s] %s\n", colorGreen, service, colorReset, detail)
		if o.Output != "" {
			msg := fmt.Sprintf("[%s] %s\n", service, detail)
			writeOutput(service, domain, msg, o.Output)
		}
	}
}

package subjack

func dotDomain(domain string) string {
	return domain + "."
}

func joinHost(server string) string {
	return server + ":53"
}

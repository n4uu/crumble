package extract

import (
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	urlRE    = regexp.MustCompile(`(?i)\b(?:https?|wss?)://[^\s'"<>\x60\\]+`)
	ipPortRE = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b`)
	domainRE = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})\b`)
)

// tlds is deliberately short: the TLDs that show up in Contagious Interview
// infrastructure and in commodity C2 generally. Matching against the full
// IANA list turns every "index.js" or "module.exports" into a domain.
var tlds = map[string]bool{
	"com": true, "net": true, "org": true, "io": true, "dev": true, "app": true, "xyz": true,
	"top": true, "online": true, "site": true, "store": true, "cloud": true, "tech": true,
	"pro": true, "info": true, "biz": true, "me": true, "co": true, "us": true, "ru": true,
	"cn": true, "uk": true, "de": true, "nl": true, "jp": true, "kr": true, "vn": true,
	"in": true, "live": true, "link": true, "click": true, "shop": true, "space": true,
	"website": true, "fun": true, "icu": true, "cc": true, "ws": true, "su": true, "to": true,
	"sh": true, "ai": true, "stream": true, "life": true, "world": true, "today": true,
	"network": true, "services": true, "solutions": true, "digital": true, "global": true,
	"invalid": true, "example": true, "test": true,
}

// benign are well-known hosts that legitimately appear in Node.js code. They
// are reported but flagged, never presented as C2.
var benign = map[string]bool{
	"registry.npmjs.org": true, "npmjs.org": true, "npmjs.com": true, "nodejs.org": true,
	"github.com": true, "raw.githubusercontent.com": true, "api.github.com": true,
	"google.com": true, "www.google.com": true, "microsoft.com": true, "apple.com": true,
	"ipinfo.io": true, "ip-api.com": true, "api.ipify.org": true, "ifconfig.me": true,
	"socket.io": true, "engine.io": true, "w3.org": true, "www.w3.org": true,
}

// Indicator is a network indicator found in the sample's strings.
type Indicator struct {
	Type   string `json:"type"` // url, ip:port, ip, domain
	Value  string `json:"value"`
	Benign bool   `json:"benign,omitempty"`
}

// indicators pulls URLs, IP[:port] pairs and domains out of strings.
// Overlap is removed: a domain or IP that's already part of a URL is not
// listed again on its own.
func indicators(strs []string) []Indicator {
	seen := map[string]bool{}
	var urls, ipps, doms []Indicator
	covered := map[string]bool{} // hosts already represented by a URL or ip:port

	for _, s := range strs {
		for _, m := range urlRE.FindAllString(s, -1) {
			m = strings.TrimRight(m, ".,;)]}")
			u, err := url.Parse(m)
			if err != nil || u.Hostname() == "" {
				continue
			}
			if !seen["url:"+m] {
				seen["url:"+m] = true
				urls = append(urls, Indicator{Type: "url", Value: m, Benign: isBenign(u.Hostname())})
			}
			covered[strings.ToLower(u.Hostname())] = true
			if u.Port() != "" {
				covered[strings.ToLower(u.Hostname())+":"+u.Port()] = true
			}
		}
	}
	for _, s := range strs {
		for _, m := range ipPortRE.FindAllString(s, -1) {
			host, port, hasPort := strings.Cut(m, ":")
			addr, err := netip.ParseAddr(host)
			if err != nil || !addr.Is4() || addr.IsUnspecified() || addr.IsLoopback() {
				continue
			}
			if hasPort {
				if p, err := strconv.Atoi(port); err != nil || p == 0 || p > 65535 {
					continue
				}
				if covered[m] || seen["ipp:"+m] {
					continue
				}
				seen["ipp:"+m] = true
				covered[host] = true
				ipps = append(ipps, Indicator{Type: "ip:port", Value: m})
				continue
			}
			if covered[host] || seen["ip:"+host] || looksLikeVersion(s, host) {
				continue
			}
			seen["ip:"+host] = true
			ipps = append(ipps, Indicator{Type: "ip", Value: host})
		}
	}
	for _, s := range strs {
		for _, idx := range domainRE.FindAllStringSubmatchIndex(s, -1) {
			m := strings.ToLower(s[idx[0]:idx[1]])
			tld := strings.ToLower(s[idx[2]:idx[3]])
			if !tlds[tld] || covered[m] || seen["dom:"+m] {
				continue
			}
			// "socket.io-client", "a.io/path" in a require: skip package
			// names, which are followed by a hyphen or preceded by "@".
			if idx[1] < len(s) && s[idx[1]] == '-' {
				continue
			}
			if idx[0] > 0 && (s[idx[0]-1] == '@' || s[idx[0]-1] == '-') {
				continue
			}
			seen["dom:"+m] = true
			doms = append(doms, Indicator{Type: "domain", Value: m, Benign: isBenign(m)})
		}
	}

	out := append(append(urls, ipps...), doms...)
	sort.SliceStable(out, func(i, j int) bool { return !out[i].Benign && out[j].Benign })
	return out
}

func isBenign(host string) bool {
	host = strings.ToLower(host)
	if benign[host] {
		return true
	}
	for b := range benign {
		if strings.HasSuffix(host, "."+b) {
			return true
		}
	}
	return false
}

// looksLikeVersion skips dotted quads that are really version strings:
// "Chrome/120.0.0.0" in a user agent, "v1.2.3.4" in a banner. An address
// after a slash inside a URL is already covered by the URL match.
func looksLikeVersion(s, ip string) bool {
	i := strings.Index(s, ip)
	if i <= 0 {
		return false
	}
	prev := s[i-1]
	return prev == 'v' || prev == 'V' || prev == '/'
}

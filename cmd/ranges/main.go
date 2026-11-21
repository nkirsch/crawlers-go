// Command ranges writes ranges.txt (cloud and VPS hosts' address ranges,
// "provider<TAB>prefix" per line) and tor.txt (Tor exit relays): Google
// Cloud, AWS, Azure, Oracle from their published lists, DigitalOcean,
// Linode and Vultr from their geofeeds plus what their main networks
// announce, and OVH, Hetzner and smaller hosts (hostingASNs) from the
// prefixes their networks announce (RIPEstat). Run from the module root:
//
//	go run ./cmd/ranges
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
)

type provider struct {
	name   string
	ranges func() []string
}

var providers = []provider{
	{"Google Cloud", googleCloud},
	{"AWS", aws},
	{"Azure", azure},
	// Published lists miss prefixes: add what the host's main network
	// announces. Not Azure's AS8075, which carries Microsoft's corporate
	// traffic too.
	{"Oracle Cloud", both(oracle, announced("AS31898"))},
	{"DigitalOcean", both(geofeed("https://www.digitalocean.com/geo/google.csv"), announced("AS14061"))},
	{"Linode", both(geofeed("https://geoip.linode.com/"), announced("AS63949"))},
	{"Vultr", both(geofeed("https://geofeed.constant.com/?text"), announced("AS20473"))},
	// OVH and Hetzner publish no list: take what their networks announce.
	{"OVH", announced("AS16276")},
	{"Hetzner", announced("AS24940")},
}

// hostingASNs are smaller hosting providers whose machines scan sites,
// flagged by what their networks announce.
var hostingASNs = []struct {
	name string
	asns []string
}{
	{"TC Datacenter", []string{"AS218785"}},
	{"Tencent Cloud", []string{"AS132203", "AS45090"}},
	{"Huawei Cloud", []string{"AS136907", "AS55990"}},
	{"Alibaba Cloud", []string{"AS45102", "AS37963"}},
	{"HostRoyale", []string{"AS207990", "AS203020", "AS204287", "AS133499"}},
	{"LogicWeb", []string{"AS64286"}},
	{"FiberPower", []string{"AS214483"}},
	{"Leaseweb", []string{ // every Leaseweb network RIPEstat names
		"AS7203", "AS15003", "AS16265", "AS19148", "AS25847", "AS27411", "AS28753", "AS30633",
		"AS32613", "AS59253", "AS60626", "AS60781", "AS133752", "AS134351", "AS136988", "AS202134",
		"AS203774", "AS203928", "AS205544", "AS393886", "AS394380", "AS395954", "AS396190", "AS396362",
	}},
	{"M247", []string{"AS9009"}},
	{"netcup", []string{"AS197540"}},
	{"Latitude.sh", []string{"AS396356"}},
	{"Senko Digital", []string{"AS213520"}},
	{"China Telecom IDC", []string{"AS23724"}},
	{"China Mobile IDC", []string{"AS132510"}},
}

// torExits is the Tor Project's list of exit relays' addresses.
const torExits = "https://check.torproject.org/torbulkexitlist"

func init() {
	for _, h := range hostingASNs {
		providers = append(providers, provider{h.name, announced(h.asns...)})
	}
}

func main() {
	day := time.Now().UTC().Format("2006-01-02")
	var b bytes.Buffer
	fmt.Fprintf(&b, "# Cloud and VPS hosts' ranges, from go run ./cmd/ranges on %s.\n# provider<TAB>prefix; nested and sibling prefixes merged per provider.\n", day)
	for _, p := range providers {
		r := collapse(p.ranges())
		if len(r) == 0 {
			fmt.Fprintln(os.Stderr, p.name+": no ranges")
			os.Exit(1)
		}
		for _, s := range r {
			fmt.Fprintf(&b, "%s\t%s\n", p.name, s)
		}
	}
	write("ranges.txt", b.Bytes())
	exits := collapse(lines(get(torExits)))
	if len(exits) == 0 {
		fmt.Fprintln(os.Stderr, "Tor: no exits")
		os.Exit(1)
	}
	write("tor.txt", []byte(fmt.Sprintf("# Tor exit relays, from the Tor Project's bulk exit list on %s.\n%s\n", day, strings.Join(exits, "\n"))))
}

func write(name string, b []byte) {
	if err := os.WriteFile(name, b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func googleCloud() []string {
	var v struct {
		Prefixes []struct {
			V4 string `json:"ipv4Prefix"`
			V6 string `json:"ipv6Prefix"`
		}
	}
	fetch("https://www.gstatic.com/ipranges/cloud.json", &v)
	var out []string
	for _, p := range v.Prefixes {
		out = append(out, p.V4+p.V6)
	}
	return out
}

func aws() []string {
	var v struct {
		Prefixes []struct {
			V4 string `json:"ip_prefix"`
		}
		IPv6Prefixes []struct {
			V6 string `json:"ipv6_prefix"`
		} `json:"ipv6_prefixes"`
	}
	fetch("https://ip-ranges.amazonaws.com/ip-ranges.json", &v)
	var out []string
	for _, p := range v.Prefixes {
		out = append(out, p.V4)
	}
	for _, p := range v.IPv6Prefixes {
		out = append(out, p.V6)
	}
	return out
}

// azure reads the weekly Service Tags file, whose dated URL is on its
// download page, and keeps the AzureCloud tag: every Azure datacenter range.
func azure() []string {
	page := get("https://www.microsoft.com/en-us/download/details.aspx?id=56519")
	u := regexp.MustCompile(`https://download\.microsoft\.com/[^"]*ServiceTags_Public_\d+\.json`).Find(page)
	if u == nil {
		fmt.Fprintln(os.Stderr, "azure: no Service Tags link on the download page")
		os.Exit(1)
	}
	var v struct {
		Values []struct {
			Name       string
			Properties struct {
				AddressPrefixes []string
			}
		}
	}
	fetch(string(u), &v)
	for _, t := range v.Values {
		if t.Name == "AzureCloud" {
			return t.Properties.AddressPrefixes
		}
	}
	return nil
}

func oracle() []string {
	var v struct {
		Regions []struct {
			CIDRs []struct {
				CIDR string
			}
		}
	}
	fetch("https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json", &v)
	var out []string
	for _, r := range v.Regions {
		for _, c := range r.CIDRs {
			out = append(out, c.CIDR)
		}
	}
	return out
}

// both joins two sources of one provider's ranges.
func both(a, b func() []string) func() []string {
	return func() []string { return append(a(), b()...) }
}

// lines are body's non-blank lines that aren't comments.
func lines(body []byte) []string {
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

// geofeed reads an RFC 8805 feed: one prefix per line, first CSV field.
func geofeed(url string) func() []string {
	return func() []string {
		var out []string
		for _, line := range lines(get(url)) {
			out = append(out, strings.Split(line, ",")[0])
		}
		return out
	}
}

// announced lists the prefixes autonomous systems announce, from RIPEstat.
func announced(asns ...string) func() []string {
	return func() []string {
		var out []string
		for _, asn := range asns {
			var v struct {
				Data struct {
					Prefixes []struct {
						Prefix string
					}
				}
			}
			fetch("https://stat.ripe.net/data/announced-prefixes/data.json?resource="+asn, &v)
			for _, p := range v.Data.Prefixes {
				out = append(out, p.Prefix)
			}
		}
		return out
	}
}

func get(url string) []byte {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "crawlers-go ranges")
	resp, err := (&http.Client{Timeout: 2 * time.Minute}).Do(req)
	var b []byte
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("%s", resp.Status)
		} else {
			b, err = io.ReadAll(resp.Body)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, url+":", err)
		os.Exit(1)
	}
	return b
}

func fetch(url string, v any) {
	if err := json.Unmarshal(get(url), v); err != nil {
		fmt.Fprintln(os.Stderr, url+":", err)
		os.Exit(1)
	}
}

// collapse sorts prefixes (or addresses), drops those inside another and merges sibling halves.
func collapse(in []string) []string {
	var ps []netip.Prefix
	for _, s := range in {
		if p, err := netip.ParsePrefix(s); err == nil {
			ps = append(ps, p.Masked())
		} else if a, err := netip.ParseAddr(s); err == nil { // a single address, as Tor lists them
			ps = append(ps, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	for {
		slices.SortFunc(ps, func(x, y netip.Prefix) int {
			if c := x.Addr().Compare(y.Addr()); c != 0 {
				return c
			}
			return x.Bits() - y.Bits()
		})
		var out []netip.Prefix
		merged := false
		for _, p := range ps {
			if n := len(out); n > 0 {
				last := out[n-1]
				if last.Overlaps(p) && last.Bits() <= p.Bits() {
					continue
				}
				if last.Bits() == p.Bits() && last.Bits() > 0 {
					parent, _ := last.Addr().Prefix(last.Bits() - 1)
					if parent.Contains(p.Addr()) && parent.Addr() == last.Addr() {
						out[n-1] = parent
						merged = true
						continue
					}
				}
			}
			out = append(out, p)
		}
		ps = out
		if !merged {
			break
		}
	}
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return s
}

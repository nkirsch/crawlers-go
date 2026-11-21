// Package crawlers tells automated visitors from people in web request logs.
//
// A visitor is one browser on one network: an IP (IPv6 grouped by /64,
// see Network) and user agent, with its requests. Reason says why one looks
// automated, or "" for a person. The rules are behaviour no reader shows:
// a bot user agent, probing for missing pages, never loading an asset,
// browsing from a cloud or VPS host's machines or a Tor exit, an old
// Chrome build, pages on many sites within seconds, or many pages within a
// minute. Fleets finds one outdated user agent spread over many networks.
//
// Nothing here knows any site: site-specific rules go in Rules.Extra.
package crawlers

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Hit is one request.
type Hit struct {
	At     time.Time
	Method string // "" is GET; Reason ignores all but GET and HEAD
	Host   string // lowercase, no port
	Path   string
	Status int
	Ref    string // external referrer host; "" when none or one of the sites' own
}

func (h Hit) read() bool { return h.Method == "" || h.Method == "GET" || h.Method == "HEAD" }

// Visitor is one browser on one network. IP is any of its addresses or
// its Network prefix.
type Visitor struct {
	IP, UA string
	Hits   []Hit
	// First is when this browser was first seen, for the Chrome age check;
	// zero means its first hit. A person's Chrome doesn't turn into a
	// crawler as it ages.
	First time.Time
	// Named means a sign-in or the site's own records name the visitor. It
	// skips the rules that judge the network or browser rather than what
	// the visitor did.
	Named bool
}

// Thresholds.
const (
	NotFound     = 3               // this many 404s (NotProbe aside) mark a crawler
	Burst        = 10              // as do this many pages within a minute
	Sites        = 4               // or pages on this many sites within SiteBurst
	SiteBurst    = 5 * time.Second //
	StaleChrome  = 15              // a Chrome this many majors behind stable
	FleetNets    = 5               // one outdated UA on this many networks
	FleetPages   = 2               // with no row past this many pages
	FleetBehind  = 3               // a fleet's Chrome is this many majors behind stable
	chromeCycle  = 28 * 24 * time.Hour
	chromeMajor0 = 138
)

var chromeDay0 = time.Date(2025, 6, 24, 0, 0, 0, 0, time.UTC) // Chrome 138 shipped

var (
	botUA    = regexp.MustCompile(`(?i)bot\b|bot/|crawl|spider|slurp|fetcher|go-http|python|curl/|libwww|wget|scrapy|okhttp|java/|node-fetch|axios|facebookexternal|flipboardproxy|panscient|headlesschrome|lighthouse|bytespider|gptbot|claudebot|perplexity|amazonbot|applebot|meta-external|feed|rss|monitor|uptime|preview|compatible;|\+https?://|^-?$`)
	chromeRe = regexp.MustCompile(`Chrome/(\d+)\.`)
	assetRe  = regexp.MustCompile(`(?i)\.(css|js|png|jpe?g|gif|svg|webp|avif)$`)
	imageRe  = regexp.MustCompile(`(?i)\.(png|jpe?g|gif|svg|webp|avif|ico)$`)
	// What browsers miss on their own: icons, images, source maps, .txt
	// files and /.well-known/ lookups.
	notProbeRe = regexp.MustCompile(`(?i)\.(ico|png|jpe?g|gif|svg|webp|avif|map|txt)$|^/\.well-known/`)
)

// BotUA reports whether ua names itself a bot, a library or a feed reader.
func BotUA(ua string) bool { return botUA.MatchString(ua) }

// BrowserUA reports whether ua starts the way every browser's does.
func BrowserUA(ua string) bool { return strings.HasPrefix(ua, "Mozilla/5.0 (") }

// ChromeStable is the stable Chrome major on t (a new one every 4 weeks).
func ChromeStable(t time.Time) int {
	return chromeMajor0 + int(t.Sub(chromeDay0)/chromeCycle)
}

// ChromeVersion is ua's Chrome major.
func ChromeVersion(ua string) (int, bool) {
	m := chromeRe.FindStringSubmatch(ua)
	if m == nil {
		return 0, false
	}
	v, err := strconv.Atoi(m[1])
	return v, err == nil
}

// Stale reports whether ua is a Chrome more than StaleChrome majors behind
// stable on t: proxied crawlers keep years-old builds.
func Stale(ua string, t time.Time) bool {
	v, ok := ChromeVersion(ua)
	return ok && v < ChromeStable(t)-StaleChrome
}

// IsAsset reports whether path is a stylesheet, script or image.
func IsAsset(path string) bool { return assetRe.MatchString(stripQuery(path)) }

// IsImage reports whether path is an image.
func IsImage(path string) bool { return imageRe.MatchString(stripQuery(path)) }

// NotProbe reports whether a 404 for path is one a browser makes on its own
// (an icon, image, source map, .txt file or /.well-known/ lookup), so it
// doesn't count toward NotFound.
func NotProbe(path string) bool { return notProbeRe.MatchString(stripQuery(path)) }

// IsPage reports whether path looks like an HTML page: .html, a trailing
// slash, or no extension, outside /auth/, /api/ and /static/.
func IsPage(path string) bool {
	path = stripQuery(path)
	if strings.HasPrefix(path, "/auth/") || strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/static/") {
		return false
	}
	last := path[strings.LastIndex(path, "/")+1:]
	return strings.HasSuffix(path, ".html") || strings.HasSuffix(path, "/") || !strings.Contains(last, ".")
}

func stripQuery(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		return p[:i]
	}
	return p
}

// Network is ip's IPv6 /64, whose suffix rotates per visit, or ip itself.
func Network(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil || a.Unmap().Is4() {
		return ip
	}
	p, _ := a.Prefix(64)
	return p.String()
}

// addr parses an address, or a prefix (as Network returns) as its first address.
func addr(s string) (netip.Addr, bool) {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap(), true
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked().Addr().Unmap(), true
	}
	return netip.Addr{}, false
}

// Pages counts v's page reads as Reason does: successful GETs of pages.
func (r Rules) Pages(v Visitor) int {
	n := 0
	for _, h := range v.Hits {
		if h.read() && (h.Status == 304 || h.Status >= 200 && h.Status < 300) && !IsAsset(h.Path) && r.page(h) {
			n++
		}
	}
	return n
}

// Rules adapts Reason to a site. The zero value applies the generic rules.
type Rules struct {
	// Page reports whether a successful hit counts as a page read; nil uses
	// IsPage on its path. Return false for hits that aren't reading (an app's
	// API calls, a booking widget's polling).
	Page func(Hit) bool
	// Extra runs last, on visitors no generic rule flagged and that aren't
	// Named: a site's own crawl patterns (only list pages, a path the site
	// never links). pages are the successful page reads, sorted by time;
	// v.Hits has every request (404s, redirects, other extensions); referred
	// is whether any hit came from an external link.
	Extra func(v Visitor, pages []Hit, referred bool) string
}

// Reason says why v looks automated, or "" for a person.
func Reason(v Visitor) string { return Rules{}.Reason(v) }

// Reason says why v looks automated, or "" for a person.
func (r Rules) Reason(v Visitor) string {
	if BotUA(v.UA) {
		return "bot UA"
	}
	var missing, assets int
	var referred bool
	var pages []Hit
	for _, h := range v.Hits {
		if !h.read() {
			continue
		}
		referred = referred || h.Ref != ""
		ok := h.Status == 304 || h.Status >= 200 && h.Status < 300
		switch {
		case h.Status == 404 && !NotProbe(h.Path):
			missing++
		case IsAsset(h.Path):
			if ok {
				assets++
			}
		case ok && r.page(h):
			pages = append(pages, h) // redirects (3xx) aren't pages
		}
	}
	if missing >= NotFound {
		return fmt.Sprintf("%d not found", missing)
	}
	if !v.Named {
		if Tor(v.IP) {
			return "Tor exit"
		}
		if p := Provider(v.IP); p != "" {
			return p + " IP"
		}
		if !BrowserUA(v.UA) {
			return "non-browser UA"
		}
		first := v.First
		if first.IsZero() {
			for _, h := range v.Hits {
				if first.IsZero() || h.At.Before(first) {
					first = h.At
				}
			}
		}
		if !first.IsZero() && Stale(v.UA, first) {
			return "stale Chrome"
		}
	}
	slices.SortStableFunc(pages, func(a, b Hit) int { return a.At.Compare(b.At) })
	if n := sitesWithin(pages, SiteBurst); n >= Sites && !v.Named {
		return fmt.Sprintf("%d sites in %ds", n, int(SiteBurst.Seconds()))
	}
	if n := mostWithin(pages, time.Minute); n >= Burst && !(assets > 0 && referred) {
		return fmt.Sprintf("%d pages in a minute", n) // a referred reader opening tabs is fine
	}
	if v.Named {
		return ""
	}
	if assets == 0 {
		return "no assets"
	}
	if r.Extra != nil {
		return r.Extra(v, pages, referred)
	}
	return ""
}

func (r Rules) page(h Hit) bool {
	if r.Page != nil {
		return r.Page(h)
	}
	return IsPage(h.Path)
}

// mostWithin is the most pages (sorted by time) inside any window shorter than d.
func mostWithin(pages []Hit, d time.Duration) int {
	most := 0
	for i, j := 0, 0; j < len(pages); j++ {
		for pages[j].At.Sub(pages[i].At) >= d {
			i++
		}
		most = max(most, j-i+1)
	}
	return most
}

// sitesWithin is the most distinct sites (host without www.) among pages
// (sorted by time) inside any window of length d.
func sitesWithin(pages []Hit, d time.Duration) int {
	most := 0
	in := map[string]int{}
	site := func(h Hit) string { return strings.TrimPrefix(h.Host, "www.") }
	for i, j := 0, 0; j < len(pages); j++ {
		in[site(pages[j])]++
		for pages[j].At.Sub(pages[i].At) > d {
			s := site(pages[i])
			if in[s]--; in[s] == 0 {
				delete(in, s)
			}
			i++
		}
		most = max(most, len(in))
	}
	return most
}

// FleetRow is one visitor as Fleets sees it.
type FleetRow struct {
	IP, UA  string
	Pages   int
	Last    time.Time // its last hit
	Flagged bool      // another rule already marked it
	Named   bool
}

// Fleets finds crawlers spread over residential IPs: one exact user agent
// on FleetNets or more networks (IPv4 /16, IPv6 /32) of unnamed rows, no
// unflagged row past FleetPages pages, and a Chrome FleetBehind or more
// majors behind stable. It returns, by index into rows, the reason for each
// unflagged, unnamed row it marks.
func Fleets(rows []FleetRow) map[int]string {
	type fleet struct {
		rows []int
		nets map[netip.Prefix]bool
		last time.Time
		big  bool
	}
	byUA := map[string]*fleet{}
	for i, x := range rows {
		f := byUA[x.UA]
		if f == nil {
			f = &fleet{nets: map[netip.Prefix]bool{}}
			byUA[x.UA] = f
		}
		f.rows = append(f.rows, i)
		// A row another rule flagged (a heavy prober) doesn't veto the fleet.
		f.big = f.big || !x.Flagged && x.Pages > FleetPages
		if x.Last.After(f.last) {
			f.last = x.Last
		}
		if p, ok := WideNet(x.IP); ok && !x.Named {
			f.nets[p] = true
		}
	}
	out := map[int]string{}
	for ua, f := range byUA {
		v, ok := ChromeVersion(ua)
		if f.big || len(f.nets) < FleetNets || !ok || v > ChromeStable(f.last)-FleetBehind {
			continue
		}
		for _, i := range f.rows {
			if !rows[i].Flagged && !rows[i].Named {
				out[i] = fmt.Sprintf("UA fleet (%d networks)", len(f.nets))
			}
		}
	}
	return out
}

// WideNet is ip's IPv4 /16 or IPv6 /32: one operator's block. ip may be an
// address or a prefix.
func WideNet(ip string) (netip.Prefix, bool) {
	a, ok := addr(ip)
	if !ok {
		return netip.Prefix{}, false
	}
	bits := 32
	if a.Is4() {
		bits = 16
	}
	p, err := a.Prefix(bits)
	return p, err == nil
}

package crawlers

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

const chrome = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"

// reader is a person: a page, its stylesheet and a second page.
func reader(ip string) Visitor {
	return Visitor{IP: ip, UA: chrome, Hits: []Hit{
		{At: t0, Host: "example.com", Path: "/", Status: 200},
		{At: t0.Add(time.Second), Host: "example.com", Path: "/style.css", Status: 200},
		{At: t0.Add(time.Minute), Host: "example.com", Path: "/about.html", Status: 200},
	}}
}

func TestReason(t *testing.T) {
	home := "203.0.113.7" // TEST-NET-3: no provider
	pages := func(v Visitor, n int, gap time.Duration, host func(int) string) Visitor {
		for i := range n {
			v.Hits = append(v.Hits, Hit{At: t0.Add(2*time.Minute + time.Duration(i)*gap), Host: host(i), Path: fmt.Sprintf("/p%d", i), Status: 200})
		}
		return v
	}
	same := func(int) string { return "example.com" }
	for _, c := range []struct {
		name string
		v    Visitor
		want string
	}{
		{"person", reader(home), ""},
		{"bot UA", func() Visitor { v := reader(home); v.UA = "Googlebot/2.1"; return v }(), "bot UA"},
		{"non-browser UA", func() Visitor { v := reader(home); v.UA = "Opera/9.80"; return v }(), "non-browser UA"},
		{"stale Chrome", func() Visitor { v := reader(home); v.UA = strings.Replace(chrome, "155", "120", 1); return v }(), "stale Chrome"},
		{"old Chrome first seen when current", func() Visitor {
			v := reader(home)
			v.UA = strings.Replace(chrome, "155", "140", 1)
			v.First = time.Date(2025, 9, 1, 0, 0, 0, 0, time.UTC)
			return v
		}(), ""},
		{"no assets", Visitor{IP: home, UA: chrome, Hits: []Hit{{At: t0, Host: "example.com", Path: "/", Status: 200}}}, "no assets"},
		{"404s", func() Visitor {
			v := reader(home)
			for _, p := range []string{"/wp-login.php", "/.env", "/admin"} {
				v.Hits = append(v.Hits, Hit{At: t0, Host: "example.com", Path: p, Status: 404})
			}
			return v
		}(), "3 not found"},
		{"missing images aren't probes", func() Visitor {
			v := reader(home)
			for _, p := range []string{"/a.png", "/b.jpg", "/c.gif"} {
				v.Hits = append(v.Hits, Hit{At: t0, Host: "example.com", Path: p, Status: 404})
			}
			return v
		}(), ""},
		{"burst", pages(reader(home), 10, 5*time.Second, same), "10 pages in a minute"},
		{"referred burst is a reader opening tabs", func() Visitor {
			v := pages(reader(home), 10, 5*time.Second, same)
			v.Hits[0].Ref = "news.example.net"
			return v
		}(), ""},
		{"redirects aren't pages", func() Visitor {
			v := reader(home)
			for i := range 12 {
				v.Hits = append(v.Hits, Hit{At: t0.Add(time.Duration(i) * time.Second), Host: "example.com", Path: "/old", Status: 301})
			}
			return v
		}(), ""},
		{"sites", pages(reader(home), 4, time.Second, func(i int) string { return fmt.Sprintf("s%d.example.com", i) }), "4 sites in 5s"},
		{"www. is the same site", pages(reader(home), 4, time.Second, func(i int) string { return []string{"example.com", "www.example.com"}[i%2] }), ""},
		{"AWS", reader("3.5.140.2"), "AWS IP"},
		{"named skips the network", func() Visitor { v := reader("3.5.140.2"); v.Named = true; return v }(), ""},
		{"named still can't probe", func() Visitor {
			v := reader(home)
			v.Named = true
			for _, p := range []string{"/a", "/b", "/c"} {
				v.Hits = append(v.Hits, Hit{At: t0, Host: "example.com", Path: p, Status: 404})
			}
			return v
		}(), "3 not found"},
	} {
		if got := Reason(c.v); got != c.want {
			t.Errorf("%s: Reason = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestRules(t *testing.T) {
	r := Rules{
		Page: func(h Hit) bool { return h.Path != "/poll" },
		Extra: func(v Visitor, pages []Hit, referred bool) string {
			if !referred && len(pages) == 1 && pages[0].Path == "/tags/" {
				return "list page only"
			}
			return ""
		},
	}
	v := Visitor{IP: "203.0.113.7", UA: chrome, Hits: []Hit{
		{At: t0, Host: "example.com", Path: "/tags/", Status: 200},
		{At: t0, Host: "example.com", Path: "/style.css", Status: 200},
	}}
	if got := r.Reason(v); got != "list page only" {
		t.Errorf("Extra: %q", got)
	}
	for i := range 20 {
		v.Hits = append(v.Hits, Hit{At: t0.Add(time.Duration(i) * time.Second), Host: "example.com", Path: "/poll", Status: 200})
	}
	v.Hits[0].Ref = "search.example.net"
	if got := r.Reason(v); got != "" {
		t.Errorf("polling counted as pages: %q", got)
	}
}

func TestFleets(t *testing.T) {
	old := strings.Replace(chrome, "155", "150", 1)
	var rows []FleetRow
	for i := range 5 {
		rows = append(rows, FleetRow{IP: fmt.Sprintf("10.%d.0.1", i), UA: old, Pages: 1, Last: t0})
	}
	got := Fleets(rows)
	if len(got) != 5 || got[0] != "UA fleet (5 networks)" {
		t.Fatalf("fleet: %v", got)
	}
	rows[2].Pages = 3 // someone reads with it: not a fleet
	if got := Fleets(rows); len(got) != 0 {
		t.Fatalf("read past FleetPages: %v", got)
	}
	rows[2].Flagged = true // a prober another rule caught doesn't veto
	if got := Fleets(rows); len(got) != 4 {
		t.Fatalf("flagged row vetoed: %v", got)
	}
}

func TestNetwork(t *testing.T) {
	if got := Network("2001:db8:1:2:aaaa::1"); got != "2001:db8:1:2::/64" {
		t.Errorf("v6: %s", got)
	}
	if got := Network("203.0.113.7"); got != "203.0.113.7" {
		t.Errorf("v4: %s", got)
	}
}

func TestRanges(t *testing.T) {
	if Provider("203.0.113.7") != "" || Tor("203.0.113.7") {
		t.Error("TEST-NET-3 matched")
	}
	if Provider("::ffff:3.5.140.2") != "AWS" {
		t.Error("mapped AWS address")
	}
	if len(tor()) < 100 || len(hosting()) < 1000 {
		t.Errorf("tables: %d tor, %d hosting", len(tor()), len(hosting()))
	}
}

func TestChromeStable(t *testing.T) {
	if got := ChromeStable(chromeDay0); got != 138 {
		t.Errorf("day 0: %d", got)
	}
	if got := ChromeStable(chromeDay0.Add(56 * 24 * time.Hour)); got != 140 {
		t.Errorf("8 weeks on: %d", got)
	}
}

func TestV2(t *testing.T) {
	v := reader("203.0.113.7")
	for _, p := range []string{"/favicon.ico", "/app.js.map", "/ads.txt", "/.well-known/appspecific/com.chrome.devtools.json"} {
		v.Hits = append(v.Hits, Hit{At: t0, Host: "example.com", Path: p, Status: 404})
	}
	if got := Reason(v); got != "" {
		t.Errorf("browser misses counted as probes: %q", got)
	}
	v = reader("203.0.113.7")
	for i := range 20 {
		v.Hits = append(v.Hits, Hit{At: t0.Add(time.Duration(i) * time.Second), Method: "POST", Host: "example.com", Path: "/form", Status: 200})
	}
	if got := Reason(v); got != "" {
		t.Errorf("POSTs counted as pages: %q", got)
	}
	if got := (Rules{}).Pages(v); got != 2 {
		t.Errorf("Pages = %d, want 2", got)
	}
	if Provider("3.5.140.0/24") != "AWS" {
		t.Error("prefix lookup")
	}
	if p, ok := WideNet(Network("2001:db8:1:2::5")); !ok || p.String() != "2001:db8::/32" {
		t.Errorf("WideNet of a /64: %v", p)
	}
}

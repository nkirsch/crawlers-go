package crawlers

import (
	_ "embed"
	"net/netip"
	"slices"
	"strings"
	"sync"
)

// ranges.txt and tor.txt are written by go run ./cmd/ranges.
var (
	//go:embed ranges.txt
	rangesTxt string
	//go:embed tor.txt
	torTxt string
)

type span struct {
	p    netip.Prefix
	name string
}

// table is a sorted, disjoint prefix list: outermost prefixes win.
type table []span

func load(txt string, named bool) table {
	var t table
	for line := range strings.Lines(txt) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, pfx := "", line
		if named {
			var ok bool
			if name, pfx, ok = strings.Cut(line, "\t"); !ok {
				continue
			}
		}
		p, err := netip.ParsePrefix(pfx)
		if err != nil {
			a, err := netip.ParseAddr(pfx)
			if err != nil {
				continue
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		t = append(t, span{p.Masked(), name})
	}
	slices.SortFunc(t, func(a, b span) int {
		if c := a.p.Addr().Compare(b.p.Addr()); c != 0 {
			return c
		}
		return a.p.Bits() - b.p.Bits()
	})
	var out table
	for _, s := range t {
		if n := len(out); n == 0 || !out[n-1].p.Contains(s.p.Addr()) {
			out = append(out, s)
		}
	}
	return out
}

func (t table) find(ip string) (span, bool) {
	a, ok := addr(ip)
	if !ok {
		return span{}, false
	}
	// Only the last prefix starting at or before a can contain it.
	i, _ := slices.BinarySearchFunc(t, a, func(s span, a netip.Addr) int {
		if s.p.Addr().Compare(a) <= 0 {
			return -1
		}
		return 1
	})
	if i > 0 && t[i-1].p.Contains(a) {
		return t[i-1], true
	}
	return span{}, false
}

var (
	hosting = sync.OnceValue(func() table { return load(rangesTxt, true) })
	tor     = sync.OnceValue(func() table { return load(torTxt, false) })
)

// Provider names the cloud or VPS host whose range holds ip (an address or a Network prefix) ("AWS",
// "Hetzner"), or "" for any other network. Readers don't browse from
// there; headless scanners do, with browser user agents that load assets.
func Provider(ip string) string {
	s, _ := hosting().find(ip)
	return s.name
}

// Tor reports whether ip is a Tor exit relay.
func Tor(ip string) bool {
	_, ok := tor().find(ip)
	return ok
}

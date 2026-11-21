# crawlers-go

Tells automated visitors from people in web request logs. Stdlib only.

```go
import "github.com/nkirsch/crawlers-go"

v := crawlers.Visitor{IP: ip, UA: ua, Hits: hits} // one browser on one network
if why := crawlers.Reason(v); why != "" {
	// "bot UA", "3 not found", "AWS IP", "Tor exit", "stale Chrome",
	// "4 sites in 5s", "10 pages in a minute", "no assets", …
}
```

- Group requests by `crawlers.Network(ip)` (IPv6 /64) and user agent.
- `Rules{Page, Extra}` adapts it to a site: which hits count as pages, and
  the site's own crawl patterns.
- `Fleets` finds one outdated user agent spread over many networks.
- `Provider(ip)` and `Tor(ip)` look up the embedded cloud/VPS and Tor exit
  ranges, refreshed with `go run ./cmd/ranges`.

package traefik_warden

import (
	"context"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	reGooglebot = regexp.MustCompile(`(?i)(googlebot|google-inspectiontool|google-other|adsbot-google)`)
	reBingbot   = regexp.MustCompile(`(?i)(bingbot|bingpreview)`)
	reApplebot  = regexp.MustCompile(`(?i)applebot`)
)

// BotSearchEngine represents the claimed search engine identity.
type BotSearchEngine string

const (
	EngineGoogle BotSearchEngine = "google"
	EngineBing   BotSearchEngine = "bing"
	EngineApple  BotSearchEngine = "apple"
)

// DetectSearchEngineBot checks if a User-Agent string claims to be a recognized search engine crawler.
func DetectSearchEngineBot(ua string) (bool, BotSearchEngine) {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return false, ""
	}
	if reGooglebot.MatchString(ua) {
		return true, EngineGoogle
	}
	if reBingbot.MatchString(ua) {
		return true, EngineBing
	}
	if reApplebot.MatchString(ua) {
		return true, EngineApple
	}
	return false, ""
}

type fcrdnsCacheEntry struct {
	valid   bool
	expires time.Time
}

// FCrDNSVerifier performs Forward-Confirmed Reverse DNS verification with an in-memory TTL cache.
type FCrDNSVerifier struct {
	mu         sync.RWMutex
	cache      map[string]fcrdnsCacheEntry
	maxEntries int
	ttl        time.Duration
	timeout    time.Duration

	lookupAddr func(ctx context.Context, addr string) ([]string, error)
	lookupIP   func(ctx context.Context, host string) ([]net.IP, error)
}

// NewFCrDNSVerifier initializes an FCrDNS verifier.
func NewFCrDNSVerifier(ttl time.Duration, timeout time.Duration) *FCrDNSVerifier {
	if ttl <= 0 {
		ttl = 6 * time.Hour
	}
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	return &FCrDNSVerifier{
		cache:      make(map[string]fcrdnsCacheEntry),
		maxEntries: 10000,
		ttl:        ttl,
		timeout:    timeout,
		lookupAddr: func(ctx context.Context, addr string) ([]string, error) {
			return net.DefaultResolver.LookupAddr(ctx, addr)
		},
		lookupIP: func(ctx context.Context, host string) ([]net.IP, error) {
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			res := make([]net.IP, len(ips))
			for i, ipa := range ips {
				res[i] = ipa.IP
			}
			return res, nil
		},
	}
}

func isValidHostForEngine(host string, engine BotSearchEngine) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	switch engine {
	case EngineGoogle:
		return strings.HasSuffix(h, ".googlebot.com") || strings.HasSuffix(h, ".google.com") || h == "googlebot.com" || h == "google.com"
	case EngineBing:
		return strings.HasSuffix(h, ".search.msn.com") || h == "search.msn.com"
	case EngineApple:
		return strings.HasSuffix(h, ".applebot.apple.com") || h == "applebot.apple.com"
	default:
		return false
	}
}

// Verify evaluates whether the client IP genuinely belongs to the claimed search engine spider.
func (v *FCrDNSVerifier) Verify(ctx context.Context, rawIP string, engine BotSearchEngine) bool {
	if v == nil {
		return true
	}

	clientIPStr := normalizeIPKey(rawIP)
	parsedIP := net.ParseIP(clientIPStr)
	if parsedIP == nil {
		return false
	}

	cacheKey := string(engine) + ":" + clientIPStr
	now := time.Now()

	// 1. Check cache
	v.mu.RLock()
	entry, exists := v.cache[cacheKey]
	v.mu.RUnlock()

	if exists && now.Before(entry.expires) {
		return entry.valid
	}

	// 2. Perform FCrDNS verification
	lookupCtx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	valid := false
	names, err := v.lookupAddr(lookupCtx, clientIPStr)
	if err == nil {
		for _, name := range names {
			if isValidHostForEngine(name, engine) {
				cleanName := strings.TrimSuffix(strings.TrimSpace(name), ".")
				forwardIPs, fwdErr := v.lookupIP(lookupCtx, cleanName)
				if fwdErr == nil {
					for _, fwdIP := range forwardIPs {
						if fwdIP.Equal(parsedIP) {
							valid = true
							break
						}
					}
				}
			}
			if valid {
				break
			}
		}
	}

	// 3. Store result in cache
	v.mu.Lock()
	if len(v.cache) >= v.maxEntries {
		for k, exp := range v.cache {
			if now.After(exp.expires) {
				delete(v.cache, k)
			}
		}
		if len(v.cache) >= v.maxEntries {
			for k := range v.cache {
				delete(v.cache, k)
				break
			}
		}
	}
	v.cache[cacheKey] = fcrdnsCacheEntry{
		valid:   valid,
		expires: now.Add(v.ttl),
	}
	v.mu.Unlock()

	return valid
}


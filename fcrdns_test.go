package traefik_warden

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestDetectSearchEngineBot(t *testing.T) {
	tests := []struct {
		ua       string
		expected bool
		engine   BotSearchEngine
	}{
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", true, EngineGoogle},
		{"Mozilla/5.0 (compatible; Google-InspectionTool/1.0;)", true, EngineGoogle},
		{"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", true, EngineBing},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)", true, EngineApple},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0", false, ""},
		{"GPTBot/1.0 (+https://openai.com/gptbot)", false, ""},
		{"", false, ""},
	}

	for _, tc := range tests {
		matched, engine := DetectSearchEngineBot(tc.ua)
		if matched != tc.expected {
			t.Errorf("UA %q: expected matched=%v, got %v", tc.ua, tc.expected, matched)
		}
		if engine != tc.engine {
			t.Errorf("UA %q: expected engine=%q, got %q", tc.ua, tc.engine, engine)
		}
	}
}

func TestFCrDNSVerifier(t *testing.T) {
	v := NewFCrDNSVerifier(1*time.Hour, 200*time.Millisecond)

	// Mock DNS lookup data
	ptrRecords := map[string][]string{
		"66.249.66.1":  {"crawl-66-249-66-1.googlebot.com."},
		"157.55.39.1":  {"msnbot-157-55-39-1.search.msn.com."},
		"17.58.101.1":  {"applebot-17-58-101-1.applebot.apple.com."},
		"198.51.100.1": {"spoofed.attacker.com."},
		"198.51.100.2": {"fake.googlebot.com."}, // PTR claims googlebot.com, but forward lookup doesn't resolve to 198.51.100.2
	}

	forwardRecords := map[string][]net.IP{
		"crawl-66-249-66-1.googlebot.com":      {net.ParseIP("66.249.66.1")},
		"msnbot-157-55-39-1.search.msn.com":    {net.ParseIP("157.55.39.1")},
		"applebot-17-58-101-1.applebot.apple.com": {net.ParseIP("17.58.101.1")},
		"spoofed.attacker.com":                 {net.ParseIP("198.51.100.1")},
		"fake.googlebot.com":                   {net.ParseIP("66.249.66.99")}, // does NOT include 198.51.100.2
	}

	v.lookupAddr = func(ctx context.Context, addr string) ([]string, error) {
		if recs, ok := ptrRecords[addr]; ok {
			return recs, nil
		}
		return nil, errors.New("host not found")
	}

	v.lookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
		if ips, ok := forwardRecords[host]; ok {
			return ips, nil
		}
		return nil, errors.New("host not found")
	}

	ctx := context.Background()

	// 1. Valid Googlebot
	if !v.Verify(ctx, "66.249.66.1", EngineGoogle) {
		t.Errorf("expected valid Googlebot IP to verify true")
	}
	// Verify it hit cache (second call)
	if !v.Verify(ctx, "66.249.66.1", EngineGoogle) {
		t.Errorf("expected cached valid Googlebot IP to verify true")
	}

	// 2. Valid Bingbot
	if !v.Verify(ctx, "157.55.39.1", EngineBing) {
		t.Errorf("expected valid Bingbot IP to verify true")
	}

	// 3. Valid Applebot
	if !v.Verify(ctx, "17.58.101.1", EngineApple) {
		t.Errorf("expected valid Applebot IP to verify true")
	}

	// 4. Attacker with attacker.com PTR claiming to be Googlebot
	if v.Verify(ctx, "198.51.100.1", EngineGoogle) {
		t.Errorf("expected spoofed attacker to fail verification")
	}

	// 5. Attacker with spoofed PTR fake.googlebot.com that fails forward lookup confirmation
	if v.Verify(ctx, "198.51.100.2", EngineGoogle) {
		t.Errorf("expected forward confirmation failure to return false")
	}

	// 6. Non-existent IP
	if v.Verify(ctx, "203.0.113.99", EngineGoogle) {
		t.Errorf("expected unresolvable IP to fail verification")
	}
}


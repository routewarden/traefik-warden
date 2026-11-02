package traefik_warden

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRobotsHoneypot_TokenGeneration(t *testing.T) {
	fixedTime := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)

	token1 := GetRobotsHoneypotToken("secret123", fixedTime)
	token2 := GetRobotsHoneypotToken("secret123", fixedTime)
	if token1 != token2 {
		t.Fatalf("expected deterministic token, got %q vs %q", token1, token2)
	}

	if len(token1) != 12 {
		t.Fatalf("expected 12-char token, got %q (len %d)", token1, len(token1))
	}

	tokenDiff := GetRobotsHoneypotToken("other-secret", fixedTime)
	if token1 == tokenDiff {
		t.Fatalf("expected different token for different secret, got %q", tokenDiff)
	}

	tokenDefault := GetRobotsHoneypotToken("", fixedTime)
	if tokenDefault == "" {
		t.Fatal("expected non-empty token for default secret")
	}

	nextDay := fixedTime.Add(24 * time.Hour)
	tokenNextDay := GetRobotsHoneypotToken("secret123", nextDay)
	if token1 == tokenNextDay {
		t.Fatalf("expected different token for next day, got %q", tokenNextDay)
	}
}

func TestRobotsHoneypot_ActiveTraps(t *testing.T) {
	fixedTime := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	activeTrap, validPrefixes := GetActiveRobotsHoneypotTraps("mysecret", fixedTime)

	if !strings.HasPrefix(activeTrap, "/_rw_trap_") || !strings.HasSuffix(activeTrap, "/") {
		t.Fatalf("unexpected activeTrap format: %q", activeTrap)
	}

	if len(validPrefixes) != 2 {
		t.Fatalf("expected 2 active prefixes, got %d", len(validPrefixes))
	}

	todayToken := GetRobotsHoneypotToken("mysecret", fixedTime)
	yesterdayToken := GetRobotsHoneypotToken("mysecret", fixedTime.Add(-24*time.Hour))

	expectedTodayPrefix := "/_rw_trap_" + todayToken
	expectedYesterdayPrefix := "/_rw_trap_" + yesterdayToken

	if validPrefixes[0] != expectedTodayPrefix || validPrefixes[1] != expectedYesterdayPrefix {
		t.Fatalf("unexpected validPrefixes: %v", validPrefixes)
	}
}

func TestRobotsHoneypot_IsRobotsTxtPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/robots.txt", true},
		{"/robots.txt/", true},
		{"/ROBOTS.TXT", true},
		{" /robots.txt ", true},
		{"/robots.txt.bak", false},
		{"/api/robots.txt", false},
		{"/", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := IsRobotsTxtPath(tt.path); got != tt.want {
			t.Errorf("IsRobotsTxtPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestRobotsHoneypot_InjectRobotsTxtTrap(t *testing.T) {
	activeTrap := "/_rw_trap_f8a3e9c1/"

	// Case 1: Empty upstream body
	injectedEmpty := string(InjectRobotsTxtTrap(nil, activeTrap))
	if !strings.Contains(injectedEmpty, "User-agent: *\nDisallow: /_rw_trap_f8a3e9c1/\n") {
		t.Fatalf("unexpected empty injection: %q", injectedEmpty)
	}

	// Case 2: Existing upstream body without trailing newline
	origBody := "User-agent: Googlebot\nDisallow: /admin"
	injected := string(InjectRobotsTxtTrap([]byte(origBody), activeTrap))
	if !strings.HasPrefix(injected, origBody) {
		t.Fatalf("original body was not preserved: %q", injected)
	}
	if !strings.Contains(injected, "\nDisallow: /_rw_trap_f8a3e9c1/\n") {
		t.Fatalf("missing injected disallow: %q", injected)
	}
}

func TestRobotsHoneypot_MiddlewareInterceptionAndBanning(t *testing.T) {
	// Upstream handler that serves an existing robots.txt and handles /normal.html
	upstream := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/robots.txt" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("User-agent: *\nDisallow: /private\n"))
			return
		}
		if req.URL.Path == "/normal.html" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
			return
		}
		http.NotFound(w, req)
	})

	cfg := CreateConfig()
	cfg.EnableRobotsTxtHoneypot = true
	cfg.RobotsTxtHoneypotSecret = "traefik-test-secret"
	cfg.TrapBanDuration = "1h"

	handler, err := New(context.Background(), upstream, cfg, "robots-test")
	if err != nil {
		t.Fatalf("failed to create RouteWarden middleware: %v", err)
	}

	now := time.Now()
	activeTrap, validPrefixes := GetActiveRobotsHoneypotTraps(cfg.RobotsTxtHoneypotSecret, now)

	// 1. GET /robots.txt -> Upstream content preserved AND dynamic trap injected
	reqRobots := httptest.NewRequest(http.MethodGet, "http://example.com/robots.txt", nil)
	reqRobots.RemoteAddr = "198.51.100.10:1234"
	recRobots := httptest.NewRecorder()
	handler.ServeHTTP(recRobots, reqRobots)

	if recRobots.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /robots.txt, got %d", recRobots.Code)
	}
	body := recRobots.Body.String()
	if !strings.Contains(body, "Disallow: /private") {
		t.Fatalf("expected upstream content to be preserved, got %q", body)
	}
	if !strings.Contains(body, "Disallow: "+activeTrap) {
		t.Fatalf("expected injected active trap %q in body, got %q", activeTrap, body)
	}

	// 2. Crawler requests today's trap URI -> Blocked with 403 and client IP banned
	crawlerIP := "198.51.100.88"
	reqTrap := httptest.NewRequest(http.MethodGet, "http://example.com"+validPrefixes[0]+"/sub/target.html", nil)
	reqTrap.RemoteAddr = crawlerIP + ":5678"
	recTrap := httptest.NewRecorder()
	handler.ServeHTTP(recTrap, reqTrap)

	if recTrap.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for honeypot trap, got %d", recTrap.Code)
	}

	// 3. Crawler subsequent request to legitimate /normal.html -> Blocked due to active ban
	reqSubsequent := httptest.NewRequest(http.MethodGet, "http://example.com/normal.html", nil)
	reqSubsequent.RemoteAddr = crawlerIP + ":5678"
	recSubsequent := httptest.NewRecorder()
	handler.ServeHTTP(recSubsequent, reqSubsequent)

	if recSubsequent.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for banned client on normal route, got %d", recSubsequent.Code)
	}

	// 4. Request from another IP to yesterday's rollover trap prefix -> Also blocked and banned
	otherCrawlerIP := "198.51.100.99"
	reqYesterday := httptest.NewRequest(http.MethodGet, "http://example.com"+validPrefixes[1]+"/", nil)
	reqYesterday.RemoteAddr = otherCrawlerIP + ":9999"
	recYesterday := httptest.NewRecorder()
	handler.ServeHTTP(recYesterday, reqYesterday)

	if recYesterday.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for yesterday's trap prefix, got %d", recYesterday.Code)
	}

	// 5. Clean client request to /normal.html -> 200 OK
	reqClean := httptest.NewRequest(http.MethodGet, "http://example.com/normal.html", nil)
	reqClean.RemoteAddr = "203.0.113.50:4321"
	recClean := httptest.NewRecorder()
	handler.ServeHTTP(recClean, reqClean)

	if recClean.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for clean client, got %d", recClean.Code)
	}
}

func TestRobotsHoneypot_Upstream404Fallback(t *testing.T) {
	// Upstream that returns 404 for all requests (e.g. no robots.txt exists)
	upstream := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.NotFound(w, req)
	})

	cfg := CreateConfig()
	cfg.EnableRobotsTxtHoneypot = true
	cfg.RobotsTxtHoneypotSecret = "fallback-secret"

	handler, err := New(context.Background(), upstream, cfg, "robots-fallback")
	if err != nil {
		t.Fatalf("failed to create middleware: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/robots.txt", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Should synthesize a 200 OK robots.txt
	if rec.Code != http.StatusOK {
		t.Fatalf("expected synthesized 200 OK when upstream 404s, got %d", rec.Code)
	}
	body := rec.Body.String()
	activeTrap, _ := GetActiveRobotsHoneypotTraps(cfg.RobotsTxtHoneypotSecret, time.Now())
	if !strings.Contains(body, "Disallow: "+activeTrap) {
		t.Fatalf("expected synthesized robots.txt to contain trap %q, got %q", activeTrap, body)
	}
}

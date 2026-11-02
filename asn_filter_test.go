package traefik_warden

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func asnTestDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "asn.json")
	if err := os.WriteFile(path, []byte(`{"AS64500":["8.0.0.0/8","2001:db8::/32"],"64501":["8.8.8.0/24","2001:db8:1::/48"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestASNLongestPrefix(t *testing.T) {
	f, err := NewASNFilter([]string{"as64500"}, asnTestDB(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"8.1.2.3", true}, {"8.1.2.3:443", true}, {"::ffff:8.1.2.3", true},
		{"8.8.8.8", false}, {"2001:db8:2::1", true}, {"2001:db8:1::1", false},
		{"9.1.2.3", false}, {"127.0.0.1", false}, {"bad", false}, {"", false},
	} {
		if got := f.IsAllowed(tc.ip); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.ip, got, tc.want)
		}
	}
}
func TestASNValidation(t *testing.T) {
	path := asnTestDB(t)
	for _, allowed := range [][]string{{"0"}, {"4294967296"}, {"AS"}, {"-1"}, {"+64500"}, {"1.2"}, {"64502"}} {
		if _, err := NewASNFilter(allowed, path); err == nil {
			t.Errorf("accepted %v", allowed)
		}
	}
	if _, err := NewASNFilter([]string{"64500"}, ""); err == nil {
		t.Error("accepted missing DB path")
	}
	if _, err := NewASNFilter([]string{"64500"}, path+"missing"); err == nil {
		t.Error("accepted unreadable DB")
	}
	for _, content := range []string{`bad`, `null`, `{}`, `{"64500":["invalid"]}`, `{"64500":["8.0.0.0/8"],"64501":["8.1.0.0/8"]}`} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewASNFilter([]string{"64500"}, path); err == nil {
			t.Errorf("accepted bad database %s", content)
		}
	}
	f, err := NewASNFilter(nil, "nonexistent")
	if err != nil || f.IsAllowed("8.1.2.3") {
		t.Error("disabled feature changed behavior")
	}
}

func TestASNProxyTrust(t *testing.T) {
	asn, err := NewASNFilter([]string{"64500"}, asnTestDB(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, proxies := range [][]string{nil, {"10.0.0.0/8"}} {
		f, err := NewIPFilter(nil, proxies)
		if err != nil {
			t.Fatal(err)
		}
		f.asn = asn
		req := httptest.NewRequest("GET", "http://example.com/.env", nil)
		req.RemoteAddr = "9.1.2.3:1234"
		req.Header.Set("X-Forwarded-For", "8.1.2.3")
		if f.IsAllowed(req) {
			t.Error("untrusted forwarded IP granted ASN bypass")
		}
		req.RemoteAddr = "10.1.2.3:1234"
		if got := f.IsAllowed(req); got != (len(proxies) > 0) {
			t.Errorf("trusted proxy got %v with %v", got, proxies)
		}
		req.RemoteAddr = "8.1.2.3:1234"
		req.Header.Del("X-Forwarded-For")
		if !f.IsAllowed(req) {
			t.Error("socket ASN did not grant bypass")
		}
	}
}

func TestASNMiddleware(t *testing.T) {
	cfg := CreateConfig()
	cfg.AllowedASNs = []string{"64500"}
	cfg.ASNDB = asnTestDB(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	for _, fileConfig := range []bool{false, true} {
		use := cfg
		if fileConfig {
			path := filepath.Join(t.TempDir(), "policy.json")
			data, err := json.Marshal(map[string]interface{}{"allowed_asns": cfg.AllowedASNs, "asn_db": cfg.ASNDB})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			use = CreateConfig()
			use.ConfigFile = path
		}
		handler, err := New(context.Background(), next, use, "asn-test")
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			ip   string
			code int
		}{{"8.1.2.3:1234", 204}, {"8.8.8.8:1234", 403}, {"[2001:db8:2::1]:1234", 204}} {
			req := httptest.NewRequest("GET", "http://example.com/.env", nil)
			req.RemoteAddr = tc.ip
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.code {
				t.Errorf("file=%v ip=%s got %d want %d", fileConfig, tc.ip, rec.Code, tc.code)
			}
		}
	}
}

func TestASNBlockedMatching(t *testing.T) {
	path := asnTestDB(t)
	// AS64501 is blocked (8.8.8.0/24), AS64500 is allowed (8.0.0.0/8)
	f, err := NewASNFilterEx([]string{"as64500"}, []string{"64501"}, path)
	if err != nil {
		t.Fatal(err)
	}

	// 8.8.8.8 belongs to AS64501 (blocked)
	blocked, asn := f.IsBlocked("8.8.8.8")
	if !blocked || asn != 64501 {
		t.Errorf("expected 8.8.8.8 to be blocked with ASN 64501, got %v (%d)", blocked, asn)
	}

	// 8.1.2.3 belongs to AS64500 (allowed, not blocked)
	blocked, _ = f.IsBlocked("8.1.2.3")
	if blocked {
		t.Errorf("expected 8.1.2.3 to not be blocked")
	}

	cfg := CreateConfig()
	cfg.BlockedASNs = []string{"AS64501"}
	cfg.ASNDB = path
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })

	handler, err := New(context.Background(), next, cfg, "blocked-asn-test")
	if err != nil {
		t.Fatal(err)
	}

	// Benign path (/public/index.html) from blocked ASN must be 403
	req := httptest.NewRequest("GET", "http://example.com/public/index.html", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Errorf("expected 403 for blocked ASN on benign path, got %d", rec.Code)
	}

	// Non-blocked ASN passes through (200)
	reqOK := httptest.NewRequest("GET", "http://example.com/public/index.html", nil)
	reqOK.RemoteAddr = "8.1.2.3:1234"
	recOK := httptest.NewRecorder()
	handler.ServeHTTP(recOK, reqOK)
	if recOK.Code != 200 {
		t.Errorf("expected 200 for allowed origin on benign path, got %d", recOK.Code)
	}
}

func TestCloudHostClassifier(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "asn.json")
	dbContent := `{
		"16509": ["54.240.196.0/24"],
		"15169": ["66.249.66.0/24"],
		"24940": ["136.243.0.0/16"],
		"13335": ["1.1.1.0/24"]
	}`
	if err := os.WriteFile(dbPath, []byte(dbContent), 0600); err != nil {
		t.Fatal(err)
	}

	filter, err := NewASNFilterEx(nil, nil, dbPath, true)
	if err != nil {
		t.Fatalf("unexpected error creating ASNFilter: %v", err)
	}

	// 54.240.196.1 -> AWS (AS16509)
	isCloud, asn, provider := filter.IsCloudHost("54.240.196.1")
	if !isCloud || asn != 16509 || provider != "AWS" {
		t.Errorf("expected AWS, got isCloud=%v, asn=%d, provider=%s", isCloud, asn, provider)
	}

	// 1.1.1.1 -> Cloudflare (AS13335, not in default cloud ASNs)
	isCloud, asn, _ = filter.IsCloudHost("1.1.1.1")
	if isCloud {
		t.Errorf("expected Cloudflare AS13335 not to be flagged as cloud host, got asn=%d", asn)
	}

	// Test RouteWarden middleware integration
	cfg := CreateConfig()
	cfg.BlockCloudHosts = true
	cfg.ASNDB = dbPath
	cfg.VerifySearchEngineBots = true
	cfg.AllowPatterns = []string{"^/api/webhook$"}
	cfg.AllowedIPs = []string{"54.240.196.99"}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	handler, err := New(context.Background(), next, cfg, "cloud-host-test")
	if err != nil {
		t.Fatal(err)
	}

	rw := handler.(*RouteWarden)
	rw.SetFCrDNSLookupFuncs(
		func(ctx context.Context, addr string) ([]string, error) {
			if addr == "66.249.66.1" {
				return []string{"crawl-66-249-66-1.googlebot.com."}, nil
			}
			return nil, nil
		},
		func(ctx context.Context, host string) ([]net.IP, error) {
			cleanHost := strings.TrimSuffix(host, ".")
			if cleanHost == "crawl-66-249-66-1.googlebot.com" {
				return []net.IP{net.ParseIP("66.249.66.1")}, nil
			}
			return nil, nil
		},
	)

	// 1. Claimed browser from AWS -> blocked (403)
	req1 := httptest.NewRequest("GET", "http://example.com/dashboard", nil)
	req1.RemoteAddr = "54.240.196.10:1234"
	req1.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != 403 {
		t.Errorf("expected 403 for browser from AWS, got %d", rec1.Code)
	}

	// 2. Non-browser scraper from Hetzner -> blocked (403)
	req2 := httptest.NewRequest("GET", "http://example.com/items", nil)
	req2.RemoteAddr = "136.243.1.2:1234"
	req2.Header.Set("User-Agent", "CustomCollector/2.0")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != 403 {
		t.Errorf("expected 403 for scraper from Hetzner, got %d", rec2.Code)
	}

	// 3. AllowPattern exemption (/api/webhook) from AWS -> allowed (200)
	req3 := httptest.NewRequest("GET", "http://example.com/api/webhook", nil)
	req3.RemoteAddr = "54.240.196.10:1234"
	req3.Header.Set("User-Agent", "GitHub-Hookshot/1.0")
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)
	if rec3.Code != 200 {
		t.Errorf("expected 200 for allowed pattern from AWS, got %d", rec3.Code)
	}

	// 4. Verified Googlebot on GCP (AS15169) -> allowed (200)
	req4 := httptest.NewRequest("GET", "http://example.com/articles", nil)
	req4.RemoteAddr = "66.249.66.1:1234"
	req4.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	rec4 := httptest.NewRecorder()
	handler.ServeHTTP(rec4, req4)
	if rec4.Code != 200 {
		t.Errorf("expected 200 for verified Googlebot from GCP, got %d", rec4.Code)
	}

	// 5. Allowed IP whitelist exemption from AWS -> allowed (200)
	req5 := httptest.NewRequest("GET", "http://example.com/private", nil)
	req5.RemoteAddr = "54.240.196.99:1234"
	rec5 := httptest.NewRecorder()
	handler.ServeHTTP(rec5, req5)
	if rec5.Code != 200 {
		t.Errorf("expected 200 for whitelisted IP from AWS, got %d", rec5.Code)
	}

	// 6. Non-cloud IP -> allowed (200)
	req6 := httptest.NewRequest("GET", "http://example.com/items", nil)
	req6.RemoteAddr = "1.1.1.1:1234"
	req6.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req6.Header.Set("Accept-Language", "en-US")
	req6.Header.Set("Accept-Encoding", "gzip")
	rec6 := httptest.NewRecorder()
	handler.ServeHTTP(rec6, req6)
	if rec6.Code != 200 {
		t.Errorf("expected 200 for non-cloud IP, got %d", rec6.Code)
	}
}

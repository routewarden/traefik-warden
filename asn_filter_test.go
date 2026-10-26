package traefik_warden

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

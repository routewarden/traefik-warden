package traefik_warden

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPoW_ChallengeAndVerification(t *testing.T) {
	clientIP := "198.51.100.22"
	secret := "traefik-warden-pow-secret"
	difficulty := 10
	now := time.Now()

	challenge, err := GeneratePoWChallenge(clientIP, secret, difficulty, now)
	if err != nil {
		t.Fatalf("GeneratePoWChallenge failed: %v", err)
	}

	nonce := SolvePoW(challenge, difficulty)
	solution := fmt.Sprintf("%s.%d", challenge, nonce)

	valid, reason := VerifyPoWSolution(clientIP, secret, solution, 300, now.Add(5*time.Second))
	if !valid {
		t.Fatalf("expected solution to verify, failed: %s", reason)
	}

	// Mismatched IP
	valid, _ = VerifyPoWSolution("203.0.113.1", secret, solution, 300, now.Add(5*time.Second))
	if valid {
		t.Errorf("expected IP mismatch to fail verification")
	}

	// Expired
	valid, _ = VerifyPoWSolution(clientIP, secret, solution, 300, now.Add(305*time.Second))
	if valid {
		t.Errorf("expected expired challenge to fail verification")
	}
}

func TestPoW_ResponseHandlerOutput(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Response: &ResponseConfig{
			Mode:              "powChallenge",
			PoWDifficulty:     12,
			PoWSecret:         "resp-handler-secret",
			PoWTimeoutSeconds: 120,
		},
	}

	handler, err := NewResponseHandler(cfg.Response, 0, "", false)
	if err != nil {
		t.Fatalf("failed to create response handler: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.RemoteAddr = "192.0.2.1:54321"

	handler.ServeBlockedRequest(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected status 429, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Errorf("expected HTML doctype in response body")
	}
	if !strings.Contains(body, "__rw_pow") {
		t.Errorf("expected __rw_pow cookie injection in response body")
	}
	if !strings.Contains(body, "crypto.subtle") {
		t.Errorf("expected crypto.subtle solver in response body")
	}
}

func TestPoW_MiddlewareBypassIntegration(t *testing.T) {
	clientIP := "192.0.2.50"
	secret := "integration-test-secret"
	difficulty := 10

	cfg := &Config{
		Enabled:           true,
		BlockUserAgents:   []string{"^CrawlerBot.*"},
		BlockPatterns:     []string{"^/admin.*"},
		HoneypotTrapPaths: []string{"/honeypot"},
		Response: &ResponseConfig{
			Mode:              "powChallenge",
			PoWDifficulty:     difficulty,
			PoWSecret:         secret,
			PoWTimeoutSeconds: 300,
		},
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ACCESS_GRANTED"))
	})

	mw, err := New(context.Background(), next, cfg, "routewarden")
	if err != nil {
		t.Fatalf("failed to create middleware: %v", err)
	}

	// 1. Request with CrawlerBot -> blocked with 429 PoW challenge
	req1 := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	req1.RemoteAddr = clientIP + ":12345"
	req1.Header.Set("User-Agent", "CrawlerBot/2.0")
	rec1 := httptest.NewRecorder()

	mw.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests, got %d", rec1.Code)
	}
	if !strings.Contains(rec1.Body.String(), "__rw_pow") {
		t.Fatalf("expected response body to contain PoW challenge HTML")
	}

	// 2. Solve challenge for clientIP
	challenge, err := GeneratePoWChallenge(clientIP, secret, difficulty, time.Now())
	if err != nil {
		t.Fatalf("failed to generate challenge: %v", err)
	}
	nonce := SolvePoW(challenge, difficulty)
	solution := fmt.Sprintf("%s.%d", challenge, nonce)

	// 3. Request with CrawlerBot + valid __rw_pow cookie -> 200 OK (ACCESS_GRANTED)
	req2 := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	req2.RemoteAddr = clientIP + ":12345"
	req2.Header.Set("User-Agent", "CrawlerBot/2.0")
	req2.AddCookie(&http.Cookie{Name: "__rw_pow", Value: solution})
	rec2 := httptest.NewRecorder()

	mw.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK || rec2.Body.String() != "ACCESS_GRANTED" {
		t.Fatalf("expected 200 ACCESS_GRANTED with valid PoW cookie, got %d (%s)", rec2.Code, rec2.Body.String())
	}

	// 4. Request to /admin with valid X-RW-PoW header -> 200 OK (ACCESS_GRANTED)
	req3 := httptest.NewRequest(http.MethodGet, "/admin/dashboard", nil)
	req3.RemoteAddr = clientIP + ":12345"
	req3.Header.Set("X-RW-PoW", solution)
	rec3 := httptest.NewRecorder()

	mw.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK || rec3.Body.String() != "ACCESS_GRANTED" {
		t.Fatalf("expected 200 ACCESS_GRANTED for /admin with valid PoW header, got %d", rec3.Code)
	}

	// 5. Honeypot trap cannot be bypassed by PoW
	reqTrap := httptest.NewRequest(http.MethodGet, "/honeypot/spider", nil)
	reqTrap.RemoteAddr = clientIP + ":12345"
	reqTrap.AddCookie(&http.Cookie{Name: "__rw_pow", Value: solution})
	recTrap := httptest.NewRecorder()

	mw.ServeHTTP(recTrap, reqTrap)
	if recTrap.Code == http.StatusOK {
		t.Fatalf("expected honeypot trap to trigger and block despite valid PoW")
	}
}

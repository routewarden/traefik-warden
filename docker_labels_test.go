package traefik_warden_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	traefik_warden "github.com/routewarden/traefik-warden"
)

// TestTraefikDockerLabelsSimulation verifies that configuration structures produced by
// Traefik's dynamic label unmarshaler (including lowercase labels, debug flag, and response sub-struct)
// unmarshal cleanly and instantiate the plugin correctly without runtime panics.
func TestTraefikDockerLabelsSimulation(t *testing.T) {
	// Traefik decodes labels by unmarshaling them into the struct returned by CreateConfig()
	labelJSON := `{
		"enabled": true,
		"debug": true,
		"enableDefaultPatterns": true,
		"enableDefaultAllowPatterns": false,
		"mode": "silentDrop",
		"response": {
			"mode": "silentDrop"
		}
	}`

	cfg := traefik_warden.CreateConfig()
	if err := json.Unmarshal([]byte(labelJSON), cfg); err != nil {
		t.Fatalf("failed to unmarshal labels into Config: %v", err)
	}

	if !cfg.Debug {
		t.Errorf("expected Debug to be true after unmarshaling labels")
	}
	if cfg.Mode != "silentDrop" {
		t.Errorf("expected Mode to be silentDrop after unmarshaling labels")
	}
	if cfg.Response == nil || cfg.Response.Mode != "silentDrop" {
		t.Errorf("expected Response.Mode to be silentDrop")
	}

	// Capture stdout to verify debug logs (logDebug writes to os.Stdout)
	oldStdout := os.Stdout
	pr, pw, _ := os.Pipe()
	os.Stdout = pw

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler, err := traefik_warden.New(context.Background(), dummyHandler, cfg, "routewarden-docker-test")
	if err != nil {
		pw.Close()
		os.Stdout = oldStdout
		t.Fatalf("failed to create RouteWarden from decoded labels: %v", err)
	}

	// Send request to sensitive endpoint
	req := httptest.NewRequest(http.MethodGet, "/.env", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	pw.Close()
	os.Stdout = oldStdout

	var logBuf bytes.Buffer
	io.Copy(&logBuf, pr)

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "[DEBUG] routewarden [routewarden-docker-test]") {
		t.Errorf("expected debug log entry, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "blocked by pattern") {
		t.Errorf("expected block debug log entry, got: %s", logOutput)
	}
}

// TestTraefikDockerLabels_DebugFlagToggling verifies that when debug is false, no debug logs are emitted.
func TestTraefikDockerLabels_DebugFlagToggling(t *testing.T) {
	labelJSON := `{
		"enabled": true,
		"debug": false,
		"enableDefaultPatterns": true
	}`

	cfg := traefik_warden.CreateConfig()
	if err := json.Unmarshal([]byte(labelJSON), cfg); err != nil {
		t.Fatalf("failed to unmarshal labels into Config: %v", err)
	}

	var logBuf bytes.Buffer
	oldStdout := os.Stdout
	pr, pw, _ := os.Pipe()
	os.Stdout = pw

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler, err := traefik_warden.New(context.Background(), dummyHandler, cfg, "debug-off-test")
	if err != nil {
		pw.Close()
		os.Stdout = oldStdout
		t.Fatalf("failed to create plugin: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.env", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	pw.Close()
	os.Stdout = oldStdout
	io.Copy(&logBuf, pr)

	if logBuf.Len() > 0 && strings.Contains(logBuf.String(), "[DEBUG]") {
		t.Errorf("expected no debug logs when debug is false, got: %s", logBuf.String())
	}
}

// TestTraefikDockerLabels_FakeSuccess verifies that fakeSuccess mode can be configured
// via response.mode, top-level mode, or top-level action, and returns synthetic 200 OK decoy payload.
func TestTraefikDockerLabels_FakeSuccess(t *testing.T) {
	testCases := []struct {
		name      string
		labelJSON string
	}{
		{
			name: "nested response.mode",
			labelJSON: `{
				"enabled": true,
				"response": {
					"mode": "fakeSuccess"
				}
			}`,
		},
		{
			name: "top-level mode alias",
			labelJSON: `{
				"enabled": true,
				"mode": "fakeSuccess"
			}`,
		},
		{
			name: "top-level action alias",
			labelJSON: `{
				"enabled": true,
				"action": "fakeSuccess"
			}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := traefik_warden.CreateConfig()
			if err := json.Unmarshal([]byte(tc.labelJSON), cfg); err != nil {
				t.Fatalf("failed to unmarshal labels into Config: %v", err)
			}

			dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			})

			handler, err := traefik_warden.New(context.Background(), dummyHandler, cfg, "fakesuccess-test")
			if err != nil {
				t.Fatalf("failed to create plugin: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/.env", nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("expected status 200 OK for fakeSuccess decoy, got %d", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), "APP_NAME=Laravel") {
				t.Errorf("expected synthetic .env body, got: %s", rec.Body.String())
			}
		})
	}
}

// TestTraefikDockerLabels_AllResponseModes verifies that every supported response mode
// works as expected when configured through Traefik Docker labels.
func TestTraefikDockerLabels_AllResponseModes(t *testing.T) {
	modes := []struct {
		name           string
		labelJSON      string
		expectedStatus int
		expectedHeader string
		expectedSubstr string
	}{
		{
			name: "json mode",
			labelJSON: `{
				"enabled": true,
				"response": { "mode": "json", "statusCode": 403 }
			}`,
			expectedStatus: http.StatusForbidden,
			expectedHeader: "application/json",
			expectedSubstr: `"error":"Forbidden"`,
		},
		{
			name: "html mode",
			labelJSON: `{
				"enabled": true,
				"mode": "html"
			}`,
			expectedStatus: http.StatusForbidden,
			expectedHeader: "text/html",
			expectedSubstr: "<!DOCTYPE html>",
		},
		{
			name: "redirect mode",
			labelJSON: `{
				"enabled": true,
				"response": { "mode": "redirect", "redirectUrl": "https://example.com/blocked" }
			}`,
			expectedStatus: http.StatusFound,
			expectedHeader: "",
			expectedSubstr: "https://example.com/blocked",
		},
		{
			name: "rateLimit mode",
			labelJSON: `{
				"enabled": true,
				"action": "rateLimit",
				"response": { "retryAfterSeconds": 120 }
			}`,
			expectedStatus: http.StatusTooManyRequests,
			expectedHeader: "application/json",
			expectedSubstr: "Rate limit exceeded",
		},
		{
			name: "xml mode",
			labelJSON: `{
				"enabled": true,
				"mode": "xml"
			}`,
			expectedStatus: http.StatusForbidden,
			expectedHeader: "application/xml",
			expectedSubstr: "<Error>",
		},
		{
			name: "captcha mode",
			labelJSON: `{
				"enabled": true,
				"response": { "mode": "captcha" }
			}`,
			expectedStatus: http.StatusForbidden,
			expectedHeader: "text/html",
			expectedSubstr: "Security Check Required",
		},
		{
			name: "gzipBomb mode",
			labelJSON: `{
				"enabled": true,
				"mode": "gzipBomb"
			}`,
			expectedStatus: http.StatusForbidden,
			expectedHeader: "gzip",
			expectedSubstr: "",
		},
		{
			name: "garbageStream mode",
			labelJSON: `{
				"enabled": true,
				"response": { "mode": "garbageStream", "streamSizeMB": 1 }
			}`,
			expectedStatus: http.StatusForbidden,
			expectedHeader: "application/octet-stream",
			expectedSubstr: "",
		},
		{
			name: "default text mode",
			labelJSON: `{
				"enabled": true,
				"mode": "text"
			}`,
			expectedStatus: http.StatusForbidden,
			expectedHeader: "text/plain",
			expectedSubstr: "Access to sensitive endpoint is blocked",
		},
	}

	for _, tc := range modes {
		t.Run(tc.name, func(t *testing.T) {
			cfg := traefik_warden.CreateConfig()
			if err := json.Unmarshal([]byte(tc.labelJSON), cfg); err != nil {
				t.Fatalf("failed to unmarshal labels into Config: %v", err)
			}

			dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			handler, err := traefik_warden.New(context.Background(), dummyHandler, cfg, "modes-test")
			if err != nil {
				t.Fatalf("failed to create plugin: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/.env", nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, rec.Code)
			}

			if tc.expectedHeader != "" {
				ct := rec.Header().Get("Content-Type")
				ce := rec.Header().Get("Content-Encoding")
				if !strings.Contains(ct, tc.expectedHeader) && !strings.Contains(ce, tc.expectedHeader) {
					t.Errorf("expected header %q in Content-Type (%q) or Content-Encoding (%q)", tc.expectedHeader, ct, ce)
				}
			}

			if tc.expectedSubstr != "" && !strings.Contains(rec.Body.String(), tc.expectedSubstr) {
				t.Errorf("expected body to contain %q, got: %s", tc.expectedSubstr, rec.Body.String())
			}
		})
	}
}

// TestTraefikDockerLabels_SecurityLog verifies that structured JSON security audit events
// compatible with CrowdSec are emitted when a request is blocked.
func TestTraefikDockerLabels_SecurityLog(t *testing.T) {
	labelJSON := `{
		"enabled": true,
		"securityLog": true,
		"mode": "json"
	}`

	cfg := traefik_warden.CreateConfig()
	if err := json.Unmarshal([]byte(labelJSON), cfg); err != nil {
		t.Fatalf("failed to unmarshal labels: %v", err)
	}

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler, err := traefik_warden.New(context.Background(), dummyHandler, cfg, "crowdsec-log-test")
	if err != nil {
		t.Fatalf("failed to create plugin: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.env", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.195")
	req.Header.Set("User-Agent", "Nuclei/v3.1.0")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}


package traefik_warden_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/routewarden/traefik-warden"
)

// TestRouteWarden_E2E_Pipeline simulates a full Traefik pipeline with chained middleware,
// custom backend services, request context, headers, and responses.
func TestRouteWarden_E2E_Pipeline(t *testing.T) {
	// Simulated upstream backend service
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend-Handled", "true")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","message":"Welcome to protected API"}`))
	})

	// Pre-middleware (e.g. Traefik forwardAuth / tracing simulator)
	tracingMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Trace-ID", "trace-xyz-123")
			next.ServeHTTP(w, r)
		})
	}

	cfg := traefik_warden.CreateConfig()
	cfg.BlockPatterns = []string{
		`(?i)^/admin(/.*)?$`,
		`(?i).*\.secret$`,
	}
	cfg.AllowedIPs = []string{
		"10.50.0.0/16",
		"192.168.1.100",
	}
	cfg.Response = &traefik_warden.ResponseConfig{
		Mode:       "json",
		StatusCode: http.StatusForbidden,
		Body:       `{"error":"access_denied","code":403}`,
		Headers: map[string]string{
			"X-RouteWarden-Protection": "active",
		},
	}

	warden, err := traefik_warden.New(context.Background(), backendHandler, cfg, "e2e-warden")
	if err != nil {
		t.Fatalf("failed to initialize plugin: %v", err)
	}

	// Compose the full Traefik middleware chain: Client -> Tracing -> RouteWarden -> Backend
	pipeline := tracingMiddleware(warden)

	t.Run("Pipeline blocks sensitive dotfile (.env)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.env", nil)
		req.RemoteAddr = "203.0.113.199:5432"
		rr := httptest.NewRecorder()

		pipeline.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", rr.Code)
		}
		if rr.Header().Get("X-RouteWarden-Protection") != "active" {
			t.Errorf("expected protection header")
		}
		if rr.Header().Get("X-Trace-ID") != "trace-xyz-123" {
			t.Errorf("expected trace header from outer pipeline middleware")
		}
		if rr.Header().Get("X-Backend-Handled") != "" {
			t.Errorf("backend should NOT have been invoked")
		}
		if !strings.Contains(rr.Body.String(), `"error":"access_denied"`) {
			t.Errorf("unexpected body: %s", rr.Body.String())
		}
	})

	t.Run("Pipeline allows legitimate endpoint through to backend", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/orders", nil)
		req.RemoteAddr = "203.0.113.199:5432"
		rr := httptest.NewRecorder()

		pipeline.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
		if rr.Header().Get("X-Backend-Handled") != "true" {
			t.Errorf("expected backend to handle request")
		}
		if !strings.Contains(rr.Body.String(), "Welcome to protected API") {
			t.Errorf("unexpected body: %s", rr.Body.String())
		}
	})

	t.Run("Pipeline exempts whitelisted IP accessing sensitive route", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/secrets.json", nil)
		req.RemoteAddr = "10.50.12.34:9876" // Matches 10.50.0.0/16
		rr := httptest.NewRecorder()

		pipeline.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 for whitelisted IP, got %d", rr.Code)
		}
		if rr.Header().Get("X-Backend-Handled") != "true" {
			t.Errorf("expected backend to handle request for whitelisted IP")
		}
	})

	t.Run("Pipeline allows whitelisted endpoints even with dotfile-like extensions", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
		req.RemoteAddr = "203.0.113.199:5432"
		rr := httptest.NewRecorder()

		pipeline.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 for robots.txt, got %d", rr.Code)
		}
		if rr.Header().Get("X-Backend-Handled") != "true" {
			t.Errorf("expected backend to handle allowed robots.txt")
		}
	})

	t.Run("Pipeline blocks encoded bypass attempt (%252eenv)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/%252eenv", nil)
		req.RemoteAddr = "203.0.113.199:5432"
		rr := httptest.NewRecorder()

		pipeline.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", rr.Code)
		}
	})
}

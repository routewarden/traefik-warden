package traefik_warden_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/routewarden/traefik-warden"
)

func TestRouteWarden_Defaults(t *testing.T) {
	cfg := traefik_warden.CreateConfig()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	handler, err := traefik_warden.New(context.Background(), next, cfg, "routewarden-test")
	if err != nil {
		t.Fatalf("unexpected error initializing plugin: %v", err)
	}

	tests := []struct {
		name         string
		url          string
		expectedCode int
	}{
		// Blocked sensitive files
		{"Block .env", "/.env", http.StatusForbidden},
		{"Block .env.production", "/.env.production", http.StatusForbidden},
		{"Block subpath .env", "/config/.env", http.StatusForbidden},
		{"Block app.log", "/app.log", http.StatusForbidden},
		{"Block database.sql", "/backup/database.sql", http.StatusForbidden},
		{"Block dump.bak", "/dump.bak", http.StatusForbidden},
		{"Block config.ini", "/settings/config.ini", http.StatusForbidden},
		{"Block config.yaml", "/config.yaml", http.StatusForbidden},
		{"Block config.yml", "/config.yml", http.StatusForbidden},
		{"Block secret.conf", "/secret.conf", http.StatusForbidden},
		{"Block notes.txt", "/notes.txt", http.StatusForbidden},
		{"Block .git folder", "/.git/config", http.StatusForbidden},
		{"Block .git root", "/.git", http.StatusForbidden},
		{"Block .aws folder", "/.aws/credentials", http.StatusForbidden},
		{"Block zip archive", "/backup.zip", http.StatusForbidden},
		{"Block tar archive", "/site.tar.gz", http.StatusForbidden},
		{"Block composer.lock", "/composer.lock", http.StatusForbidden},
		{"Block package-lock.json", "/package-lock.json", http.StatusForbidden},
		{"Block phpinfo", "/phpinfo.php", http.StatusForbidden},
		{"Block actuator", "/actuator/health", http.StatusForbidden},
		{"Block private key (.key)", "/server.key", http.StatusForbidden},
		{"Block certificate (.pem)", "/cert.pem", http.StatusForbidden},
		{"Block Dockerfile", "/Dockerfile", http.StatusForbidden},
		{"Block docker-compose", "/docker-compose.yml", http.StatusForbidden},
		{"Block .DS_Store", "/.DS_Store", http.StatusForbidden},
		{"Block wp-config.php", "/wp-config.php", http.StatusForbidden},

		// URL-encoded evasion attempts
		{"Block encoded .env (%2eenv)", "/%2eenv", http.StatusForbidden},
		{"Block double encoded path traversal", "/static/%2e%2e/.env", http.StatusForbidden},

		// Allowed / legitimate files matching broad patterns
		{"Allow robots.txt", "/robots.txt", http.StatusOK},
		{"Allow ads.txt", "/ads.txt", http.StatusOK},
		{"Allow security.txt", "/security.txt", http.StatusOK},
		{"Allow .well-known", "/.well-known/acme-challenge/test", http.StatusOK},

		// Normal clean endpoints
		{"Allow normal root", "/", http.StatusOK},
		{"Allow normal API", "/api/v1/users", http.StatusOK},
		{"Allow normal page", "/dashboard", http.StatusOK},
		{"Allow normal image", "/assets/logo.png", http.StatusOK},
		{"Allow normal js", "/bundle.js", http.StatusOK},
		{"Allow normal css", "/styles.css", http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != tc.expectedCode {
				t.Errorf("Path %q: expected status %d, got %d", tc.url, tc.expectedCode, rr.Code)
			}
		})
	}
}

func TestRouteWarden_CustomBlockPatterns(t *testing.T) {
	cfg := traefik_warden.CreateConfig()
	cfg.EnableDefaultPatterns = false
	// Add user's exact requested pattern
	cfg.BlockPatterns = []string{
		`(?i)(^|/)(\.env.*|.*\.(txt|log|bak|backup|sql|conf|config|ini|yaml|yml))`,
	}
	cfg.StatusCode = http.StatusNotFound // Custom 404
	cfg.CustomResponseText = "Not Found"

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	handler, err := traefik_warden.New(context.Background(), next, cfg, "custom-test")
	if err != nil {
		t.Fatalf("unexpected error initializing plugin: %v", err)
	}

	tests := []struct {
		url          string
		expectedCode int
	}{
		{"/.env", http.StatusNotFound},
		{"/.env.local", http.StatusNotFound},
		{"/app.log", http.StatusNotFound},
		{"/db.backup", http.StatusNotFound},
		{"/my.sql", http.StatusNotFound},
		{"/app.conf", http.StatusNotFound},
		{"/test.ini", http.StatusNotFound},
		{"/server.yaml", http.StatusNotFound},
		{"/server.yml", http.StatusNotFound},
		{"/secret.txt", http.StatusNotFound},
		// Unblocked paths since default patterns were disabled
		{"/.git/config", http.StatusOK},
		{"/normal/page", http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.url, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != tc.expectedCode {
				t.Errorf("Path %q: expected status %d, got %d", tc.url, tc.expectedCode, rr.Code)
			}
		})
	}
}

func TestRouteWarden_JSONResponse(t *testing.T) {
	cfg := traefik_warden.CreateConfig()
	cfg.PathPatterns = []string{`^/api/admin/.*`}
	cfg.Response = &traefik_warden.ResponseConfig{
		Mode:       "json",
		StatusCode: http.StatusTeapot, // 418 or 403 / 429
		Body:       `{"error":"unauthorized_resource","status":418,"success":false}`,
		Headers: map[string]string{
			"X-RouteWarden-Blocked": "true",
		},
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler, err := traefik_warden.New(context.Background(), next, cfg, "json-test")
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/secrets", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTeapot {
		t.Errorf("expected status %d, got %d", http.StatusTeapot, rr.Code)
	}

	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("expected Content-Type application/json, got %q", contentType)
	}

	if rr.Header().Get("X-RouteWarden-Blocked") != "true" {
		t.Errorf("expected custom header X-RouteWarden-Blocked to be 'true'")
	}

	body := rr.Body.String()
	if !strings.Contains(body, `"error":"unauthorized_resource"`) {
		t.Errorf("unexpected body content: %s", body)
	}
}

func TestRouteWarden_HTMLResponse(t *testing.T) {
	cfg := traefik_warden.CreateConfig()
	cfg.PathPatterns = []string{`(?i)^/admin/login`}
	cfg.Response = &traefik_warden.ResponseConfig{
		Mode:       "html",
		StatusCode: http.StatusForbidden,
		Body:       `<!DOCTYPE html><html><body><h1>Access Denied</h1><p>Restricted area.</p></body></html>`,
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler, err := traefik_warden.New(context.Background(), next, cfg, "html-test")
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rr.Code)
	}

	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("expected Content-Type text/html, got %q", contentType)
	}

	body := rr.Body.String()
	if !strings.Contains(body, `<h1>Access Denied</h1>`) {
		t.Errorf("unexpected body: %s", body)
	}
}

func TestRouteWarden_CaptchaResponse(t *testing.T) {
	providers := []struct {
		provider string
		element  string
	}{
		{"turnstile", "cf-turnstile"},
		{"hcaptcha", "h-captcha"},
		{"recaptcha", "g-recaptcha"},
	}

	for _, p := range providers {
		t.Run(p.provider, func(t *testing.T) {
			cfg := traefik_warden.CreateConfig()
			cfg.PathPatterns = []string{`^/login`}
			cfg.Response = &traefik_warden.ResponseConfig{
				Mode:       "captcha",
				StatusCode: http.StatusForbidden,
				Captcha: &traefik_warden.CaptchaConfig{
					Provider: p.provider,
					SiteKey:  "0x4AAAAAAtestkey123",
					Title:    "Custom Security Check",
				},
			}

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
			handler, err := traefik_warden.New(context.Background(), next, cfg, "captcha-test")
			if err != nil {
				t.Fatalf("failed to create handler: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/login", nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusForbidden {
				t.Errorf("expected status 403, got %d", rr.Code)
			}

			body := rr.Body.String()
			if !strings.Contains(body, p.element) {
				t.Errorf("expected captcha container with %q, got body:\n%s", p.element, body)
			}
			if !strings.Contains(body, "0x4AAAAAAtestkey123") {
				t.Errorf("expected sitekey to be in HTML output")
			}
			if !strings.Contains(body, "Custom Security Check") {
				t.Errorf("expected title to be in HTML output")
			}
		})
	}
}

func TestRouteWarden_RedirectResponse(t *testing.T) {
	cfg := traefik_warden.CreateConfig()
	cfg.PathPatterns = []string{`^/trap`}
	cfg.Response = &traefik_warden.ResponseConfig{
		Mode:        "redirect",
		StatusCode:  http.StatusTemporaryRedirect, // 307
		RedirectURL: "https://example.com/blocked",
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	handler, err := traefik_warden.New(context.Background(), next, cfg, "redirect-test")
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/trap", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected status 307, got %d", rr.Code)
	}

	loc := rr.Header().Get("Location")
	if loc != "https://example.com/blocked" {
		t.Errorf("expected redirect location https://example.com/blocked, got %q", loc)
	}
}

func TestRouteWarden_AllowPatternsOverride(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("Allowlist supersedes both default and custom block patterns", func(t *testing.T) {
		cfg := traefik_warden.CreateConfig()
		cfg.EnableDefaultPatterns = true
		cfg.EnableDefaultAllowPatterns = true
		cfg.PathPatterns = []string{`(?i)^/api/.*$`}
		cfg.AllowPatterns = []string{
			`(?i)^/api/public/.*\.env$`,
			`(?i)^/public/.*\.txt$`,
		}

		handler, err := traefik_warden.New(context.Background(), next, cfg, "allow-override-test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// 1. Default allow pattern: /robots.txt
		// (/robots.txt matches default block pattern for .txt, but is exempted by default allow pattern)
		reqRobots := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
		rrRobots := httptest.NewRecorder()
		handler.ServeHTTP(rrRobots, reqRobots)
		if rrRobots.Code != http.StatusOK {
			t.Errorf("expected /robots.txt to pass through via default allowlist override, got %d", rrRobots.Code)
		}

		// 2. Default allow pattern: /.well-known/acme-challenge/test
		// (/.well-known matches hidden directory block pattern, but acme-challenge is allowed)
		reqAcme := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/test", nil)
		rrAcme := httptest.NewRecorder()
		handler.ServeHTTP(rrAcme, reqAcme)
		if rrAcme.Code != http.StatusOK {
			t.Errorf("expected /.well-known/acme-challenge to pass through via default allowlist override, got %d", rrAcme.Code)
		}

		// 3. Custom allow overriding default block (.env)
		// /api/public/demo.env matches default .env block pattern, but matches custom allow pattern
		reqEnv := httptest.NewRequest(http.MethodGet, "/api/public/demo.env", nil)
		rrEnv := httptest.NewRecorder()
		handler.ServeHTTP(rrEnv, reqEnv)
		if rrEnv.Code != http.StatusOK {
			t.Errorf("expected /api/public/demo.env to supersede blocklist and pass through, got %d", rrEnv.Code)
		}

		// 4. Custom allow overriding custom block pattern (/api/.*)
		// /public/info.txt matches block pattern for .txt, but matches custom allow pattern
		reqTxt := httptest.NewRequest(http.MethodGet, "/public/info.txt", nil)
		rrTxt := httptest.NewRecorder()
		handler.ServeHTTP(rrTxt, reqTxt)
		if rrTxt.Code != http.StatusOK {
			t.Errorf("expected /public/info.txt to supersede blocklist and pass through, got %d", rrTxt.Code)
		}

		// 5. Normal blocked request (not in allowlist) should be rejected
		reqBlocked := httptest.NewRequest(http.MethodGet, "/api/private/secret.env", nil)
		rrBlocked := httptest.NewRecorder()
		handler.ServeHTTP(rrBlocked, reqBlocked)
		if rrBlocked.Code != http.StatusForbidden {
			t.Errorf("expected /api/private/secret.env to be blocked with 403, got %d", rrBlocked.Code)
		}
	})

	t.Run("Disabling default allow patterns removes exemption", func(t *testing.T) {
		cfg := traefik_warden.CreateConfig()
		cfg.EnableDefaultPatterns = true
		cfg.EnableDefaultAllowPatterns = false

		handler, err := traefik_warden.New(context.Background(), next, cfg, "disable-default-allow")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// When default allow patterns are disabled, /robots.txt matches the default .txt block rule
		reqRobots := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
		rrRobots := httptest.NewRecorder()
		handler.ServeHTTP(rrRobots, reqRobots)
		if rrRobots.Code != http.StatusForbidden {
			t.Errorf("expected /robots.txt to be blocked when EnableDefaultAllowPatterns is false, got %d", rrRobots.Code)
		}
	})
}

func TestRouteWarden_DisableDefaultAllowPatterns(t *testing.T) {
	// When EnableDefaultAllowPatterns is false, standard paths like /robots.txt or /security.txt
	// that match a block rule will NOT be exempted.
	cfg := traefik_warden.CreateConfig()
	cfg.EnableDefaultAllowPatterns = false
	// Block all .txt files
	cfg.PathPatterns = []string{`(?i).*\.txt$`}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler, err := traefik_warden.New(context.Background(), next, cfg, "disable-default-allow-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// /robots.txt matches .*\.txt$ and should be blocked because default allow patterns are disabled
	req1 := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusForbidden {
		t.Errorf("expected /robots.txt to be blocked when EnableDefaultAllowPatterns=false, got %d", rr1.Code)
	}

	// /security.txt should also be blocked
	req2 := httptest.NewRequest(http.MethodGet, "/security.txt", nil)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusForbidden {
		t.Errorf("expected /security.txt to be blocked when EnableDefaultAllowPatterns=false, got %d", rr2.Code)
	}
}

func TestRouteWarden_CheckQuery(t *testing.T) {
	cfg := traefik_warden.CreateConfig()
	cfg.CheckQuery = true

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler, err := traefik_warden.New(context.Background(), next, cfg, "query-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/search?file=.env", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 when query matches sensitive block pattern, got %d", rr.Code)
	}
}

func TestRouteWarden_Disabled(t *testing.T) {
	cfg := traefik_warden.CreateConfig()
	cfg.Enabled = false

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler, err := traefik_warden.New(context.Background(), next, cfg, "disabled-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.env", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 when plugin is disabled, got %d", rr.Code)
	}
}

func TestRouteWarden_InvalidRegex(t *testing.T) {
	cfg := traefik_warden.CreateConfig()
	cfg.BlockPatterns = []string{"(unclosed parenthesis"}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	_, err := traefik_warden.New(context.Background(), next, cfg, "error-test")
	if err == nil {
		t.Errorf("expected error for invalid regex pattern, got nil")
	}
}

func TestRouteWarden_InvalidAllowRegex(t *testing.T) {
	cfg := traefik_warden.CreateConfig()
	cfg.AllowPatterns = []string{"[unclosed bracket"}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	_, err := traefik_warden.New(context.Background(), next, cfg, "allow-error-test")
	if err == nil {
		t.Errorf("expected error for invalid allow regex pattern, got nil")
	}
}

func TestRouteWarden_NilConfig(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler, err := traefik_warden.New(context.Background(), next, nil, "nil-config-test")
	if err != nil {
		t.Fatalf("unexpected error initializing with nil config: %v", err)
	}

	// Should block sensitive files using default config
	req := httptest.NewRequest(http.MethodGet, "/.env", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 with nil config, got %d", rr.Code)
	}
}

func TestRouteWarden_InvalidResponseConfig(t *testing.T) {
	cfg := traefik_warden.CreateConfig()
	cfg.Response = &traefik_warden.ResponseConfig{
		Mode:     "proxy",
		ProxyURL: "://invalid-url",
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	_, err := traefik_warden.New(context.Background(), next, cfg, "resp-error-test")
	if err == nil {
		t.Errorf("expected error initializing with invalid proxy url")
	}
}

func TestRouteWarden_SecurityEvasionVectors(t *testing.T) {
	cfg := traefik_warden.CreateConfig()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("SHOULD NOT BE REACHED"))
	})

	handler, err := traefik_warden.New(context.Background(), next, cfg, "security-evasion-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	evasionTests := []struct {
		name string
		path string
	}{
		// Double URL encoding
		{"Double encoded dot (%252eenv)", "/%252eenv"},
		{"Double encoded traversal (%252e%252e/.env)", "/static/%252e%252e/.env"},

		// Matrix parameter evasion (Spring / Java / reverse-proxy semicolon bypass)
		{"Semicolon matrix parameter prefix", "/;.env"},
		{"Semicolon path segment suffix", "/static;param=123/.env"},
		{"Semicolon within path", "/api;.env/config.json"},

		// Backslash path separation (Windows / IIS / reverse-proxy normalizer evasion)
		{"Backslash traversal", "/static\\..\\.env"},
		{"Direct backslash path", "/\\.env"},

		// Encoded null byte injection attempt
		{"Null byte in path (%00)", "/.env%00.png"},

		// Direct and subpath variations
		{"Dot slash path variation", "/./.env"},
		{"Trailing slash directory .git", "/.git/"},
		{"Case insensitivity (.ENV)", "/.ENV"},
		{"Case insensitivity (.YML)", "/config.YML"},
		{"Case insensitivity (.SQL)", "/DUMP.SQL"},
	}

	for _, tc := range evasionTests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusForbidden {
				t.Errorf("Security evasion test %q failed: path %q got status %d, expected %d",
					tc.name, tc.path, rr.Code, http.StatusForbidden)
			}
		})
	}
}

func TestRouteWarden_SilentDrop(t *testing.T) {
	cfg := traefik_warden.CreateConfig()
	cfg.Mode = "silentDrop"
	cfg.StatusCode = http.StatusForbidden

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler, err := traefik_warden.New(context.Background(), next, cfg, "silent-drop-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.env", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Since httptest.ResponseRecorder doesn't implement http.Hijacker, it falls back to writing status code with empty body
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, rr.Code)
	}
	if rr.Body.Len() > 0 {
		t.Errorf("expected empty body for silent drop fallback, got %q", rr.Body.String())
	}
}

func TestRouteWarden_IPWhitelist(t *testing.T) {
	cfg := traefik_warden.CreateConfig()
	cfg.AllowedIPs = []string{
		"192.168.1.50",       // Exact IP
		"10.0.0.0/24",        // CIDR subnet
		"2001:db8::/32",      // IPv6 subnet
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ALLOWED"))
	})

	handler, err := traefik_warden.New(context.Background(), next, cfg, "ip-whitelist-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		name         string
		remoteAddr   string
		xff          string
		xrip         string
		path         string
		expectedCode int
	}{
		{
			name:         "Whitelisted exact IP in RemoteAddr",
			remoteAddr:   "192.168.1.50:54321",
			path:         "/.env",
			expectedCode: http.StatusOK,
		},
		{
			name:         "Whitelisted CIDR IP in RemoteAddr",
			remoteAddr:   "10.0.0.42:12345",
			path:         "/.env",
			expectedCode: http.StatusOK,
		},
		{
			name:         "Whitelisted IP via X-Forwarded-For",
			remoteAddr:   "203.0.113.195:8080",
			xff:          "192.168.1.50, 10.0.0.1",
			path:         "/.env.production",
			expectedCode: http.StatusOK,
		},
		{
			name:         "Whitelisted IP via X-Real-IP",
			remoteAddr:   "203.0.113.195:8080",
			xrip:         "10.0.0.99",
			path:         "/backup/database.sql",
			expectedCode: http.StatusOK,
		},
		{
			name:         "Non-whitelisted IP accessing sensitive file is blocked",
			remoteAddr:   "203.0.113.5:12345",
			path:         "/.env",
			expectedCode: http.StatusForbidden,
		},
		{
			name:         "Non-whitelisted IP accessing normal page is allowed",
			remoteAddr:   "203.0.113.5:12345",
			path:         "/api/users",
			expectedCode: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.xrip != "" {
				req.Header.Set("X-Real-IP", tc.xrip)
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tc.expectedCode {
				t.Errorf("expected code %d, got %d", tc.expectedCode, rr.Code)
			}
		})
	}
}

func TestRouteWarden_InvalidAllowedIPs(t *testing.T) {
	cfg := traefik_warden.CreateConfig()
	cfg.AllowedIPs = []string{"not-an-ip-or-cidr"}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	_, err := traefik_warden.New(context.Background(), next, cfg, "invalid-ip-test")
	if err == nil {
		t.Errorf("expected error on invalid IP format, got nil")
	}

	cfg2 := traefik_warden.CreateConfig()
	cfg2.AllowedIPs = []string{"10.0.0.0/99"} // invalid CIDR mask
	_, err2 := traefik_warden.New(context.Background(), next, cfg2, "invalid-cidr-test")
	if err2 == nil {
		t.Errorf("expected error on invalid CIDR mask, got nil")
	}
}

func TestRouteWarden_WildcardAndPrefixPatterns(t *testing.T) {
	cfg := traefik_warden.CreateConfig()
	cfg.EnableDefaultPatterns = false
	// Real-world API wildcard and prefix patterns (like Immich, admin dashboards, etc.)
	cfg.PathPatterns = []string{
		`(?i)^/api/auth/login.*$`,
		`(?i)^/api/auth/admin-sign-up.*$`,
		`(?i)^/api/users.*$`,
		`(?i)^/api/admin.*$`,
		`(?i)^/api/server-info/stats.*$`,
		`(?i)^/internal/.*`,
	}
	cfg.Response = &traefik_warden.ResponseConfig{
		Mode:       "json",
		StatusCode: http.StatusNotFound,
		Body:       `{"error":"Not Found"}`,
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true}`))
	})

	handler, err := traefik_warden.New(context.Background(), next, cfg, "wildcard-test")
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	tests := []struct {
		name         string
		path         string
		expectedCode int
	}{
		// Blocked by ^/api/auth/login.*$
		{"Exact login endpoint", "/api/auth/login", http.StatusNotFound},
		{"Login endpoint with trailing slash", "/api/auth/login/", http.StatusNotFound},
		{"Login endpoint with subpath", "/api/auth/login/oauth", http.StatusNotFound},
		{"Login endpoint with query", "/api/auth/login?redirect=/home", http.StatusNotFound},
		{"Uppercase login", "/API/AUTH/LOGIN", http.StatusNotFound},

		// Blocked by ^/api/auth/admin-sign-up.*$
		{"Admin sign up exact", "/api/auth/admin-sign-up", http.StatusNotFound},
		{"Admin sign up subpath", "/api/auth/admin-sign-up/submit", http.StatusNotFound},

		// Blocked by ^/api/users.*$
		{"Users root", "/api/users", http.StatusNotFound},
		{"Users specific ID", "/api/users/123", http.StatusNotFound},
		{"Users profile", "/api/users/me/profile", http.StatusNotFound},

		// Blocked by ^/api/admin.*$
		{"Admin root", "/api/admin", http.StatusNotFound},
		{"Admin settings", "/api/admin/settings/security", http.StatusNotFound},

		// Blocked by ^/api/server-info/stats.*$
		{"Server stats", "/api/server-info/stats", http.StatusNotFound},
		{"Server stats detail", "/api/server-info/stats/cpu", http.StatusNotFound},

		// Blocked by ^/internal/.*
		{"Internal endpoint", "/internal/metrics", http.StatusNotFound},

		// Allowed public endpoints (should pass through to next with 200 OK)
		{"Public share link", "/share/Hj89aLm1", http.StatusOK},
		{"Public asset thumbnail", "/api/asset/thumbnail/456", http.StatusOK},
		{"Public photo view", "/api/asset/file/789", http.StatusOK},
		{"Other non-matching auth", "/api/auth/logout", http.StatusOK},
		{"Server info other than stats", "/api/server-info/version", http.StatusOK},
		{"Static assets", "/favicon.ico", http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != tc.expectedCode {
				t.Errorf("Path %q: expected status %d, got %d", tc.path, tc.expectedCode, rr.Code)
			}
		})
	}
}

func TestRouteWarden_Methods(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("PASSED"))
	})

	t.Run("Default inspects only GET", func(t *testing.T) {
		cfg := traefik_warden.CreateConfig()
		handler, err := traefik_warden.New(context.Background(), next, cfg, "methods-default")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// GET /.env should be blocked
		reqGet := httptest.NewRequest(http.MethodGet, "/.env", nil)
		rrGet := httptest.NewRecorder()
		handler.ServeHTTP(rrGet, reqGet)
		if rrGet.Code != http.StatusForbidden {
			t.Errorf("expected GET /.env to be 403, got %d", rrGet.Code)
		}

		// POST /.env should bypass inspection and pass through
		reqPost := httptest.NewRequest(http.MethodPost, "/.env", nil)
		rrPost := httptest.NewRecorder()
		handler.ServeHTTP(rrPost, reqPost)
		if rrPost.Code != http.StatusOK {
			t.Errorf("expected POST /.env to bypass inspection and return 200, got %d", rrPost.Code)
		}

		// PUT, DELETE, PATCH should also bypass
		for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodHead} {
			req := httptest.NewRequest(method, "/.env", nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("expected %s /.env to bypass inspection and return 200, got %d", method, rr.Code)
			}
		}
	})

	t.Run("Custom methods GET and POST", func(t *testing.T) {
		cfg := traefik_warden.CreateConfig()
		cfg.Methods = []string{"GET", "POST"}
		handler, err := traefik_warden.New(context.Background(), next, cfg, "methods-get-post")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Both GET and POST to sensitive path should be blocked
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			req := httptest.NewRequest(method, "/.env", nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusForbidden {
				t.Errorf("expected %s /.env to be 403, got %d", method, rr.Code)
			}
		}

		// DELETE should bypass
		reqDel := httptest.NewRequest(http.MethodDelete, "/.env", nil)
		rrDel := httptest.NewRecorder()
		handler.ServeHTTP(rrDel, reqDel)
		if rrDel.Code != http.StatusOK {
			t.Errorf("expected DELETE /.env to return 200, got %d", rrDel.Code)
		}
	})

	t.Run("Case-insensitive and empty fallback", func(t *testing.T) {
		cfg := traefik_warden.CreateConfig()
		cfg.Methods = []string{"post", "delete"}
		handler, err := traefik_warden.New(context.Background(), next, cfg, "methods-case")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// POST should be blocked
		reqPost := httptest.NewRequest(http.MethodPost, "/.env", nil)
		rrPost := httptest.NewRecorder()
		handler.ServeHTTP(rrPost, reqPost)
		if rrPost.Code != http.StatusForbidden {
			t.Errorf("expected POST /.env to be 403, got %d", rrPost.Code)
		}

		// GET should bypass
		reqGet := httptest.NewRequest(http.MethodGet, "/.env", nil)
		rrGet := httptest.NewRecorder()
		handler.ServeHTTP(rrGet, reqGet)
		if rrGet.Code != http.StatusOK {
			t.Errorf("expected GET /.env to return 200, got %d", rrGet.Code)
		}

		// Empty slice defaults to GET
		cfgEmpty := traefik_warden.CreateConfig()
		cfgEmpty.Methods = []string{}
		handlerEmpty, err := traefik_warden.New(context.Background(), next, cfgEmpty, "methods-empty")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		reqGet2 := httptest.NewRequest(http.MethodGet, "/.env", nil)
		rrGet2 := httptest.NewRecorder()
		handlerEmpty.ServeHTTP(rrGet2, reqGet2)
		if rrGet2.Code != http.StatusForbidden {
			t.Errorf("expected GET /.env with empty Methods to default to 403, got %d", rrGet2.Code)
		}
	})
}

func TestRouteWarden_CheckQuery_EdgeCases(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cfg := traefik_warden.CreateConfig()
	cfg.CheckQuery = true

	handler, err := traefik_warden.New(context.Background(), next, cfg, "query-edge")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Run("Multi-value query parameter with sensitive value", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/search?file=report&file=backup.sql", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403 for query containing backup.sql, got %d", rr.Code)
		}
	})

	t.Run("Malformed percent-encoding in query", func(t *testing.T) {
		// %ZZ is not valid percent-encoding; QueryUnescape will error,
		// code falls back to raw query which still contains .env
		req := httptest.NewRequest(http.MethodGet, "/search?file=%ZZ/.env", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403 for malformed encoding containing .env, got %d", rr.Code)
		}
	})

	t.Run("Benign query string does not trigger block", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/search?page=1&limit=20&sort=name", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 for benign query, got %d", rr.Code)
		}
	})

	t.Run("Empty query string with checkQuery enabled", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 for no query string, got %d", rr.Code)
		}
	})

	t.Run("Query parameter key matches sensitive pattern", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/search?foo=bar&.env=1", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403 when query key is .env, got %d", rr.Code)
		}
	})

	t.Run("Query parameter value with path traversal", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/search?file=/images/../.env", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403 when query value normalizes to .env, got %d", rr.Code)
		}
	})
}

func TestRouteWarden_Methods_WithCheckQuery(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cfg := traefik_warden.CreateConfig()
	cfg.CheckQuery = true
	cfg.Methods = []string{"GET", "POST"}

	handler, err := traefik_warden.New(context.Background(), next, cfg, "methods-query")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Run("POST with sensitive query is blocked when POST in methods", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/submit?file=.env", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403 for POST with sensitive query, got %d", rr.Code)
		}
	})

	t.Run("DELETE with sensitive query bypasses when DELETE not in methods", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/submit?file=.env", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 for DELETE bypassing inspection, got %d", rr.Code)
		}
	})
}

func TestRouteWarden_Methods_WhitespacePadded(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cfg := traefik_warden.CreateConfig()
	cfg.Methods = []string{"  get  ", "  post  "}

	handler, err := traefik_warden.New(context.Background(), next, cfg, "methods-whitespace")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// GET should be inspected and blocked
	reqGet := httptest.NewRequest(http.MethodGet, "/.env", nil)
	rrGet := httptest.NewRecorder()
	handler.ServeHTTP(rrGet, reqGet)
	if rrGet.Code != http.StatusForbidden {
		t.Errorf("expected trimmed ' get ' to match GET and block /.env, got %d", rrGet.Code)
	}

	// POST should be inspected and blocked
	reqPost := httptest.NewRequest(http.MethodPost, "/.env", nil)
	rrPost := httptest.NewRecorder()
	handler.ServeHTTP(rrPost, reqPost)
	if rrPost.Code != http.StatusForbidden {
		t.Errorf("expected trimmed ' post ' to match POST and block /.env, got %d", rrPost.Code)
	}

	// PUT should bypass
	reqPut := httptest.NewRequest(http.MethodPut, "/.env", nil)
	rrPut := httptest.NewRecorder()
	handler.ServeHTTP(rrPut, reqPut)
	if rrPut.Code != http.StatusOK {
		t.Errorf("expected PUT to bypass, got %d", rrPut.Code)
	}
}

func TestRouteWarden_Methods_WhitespaceOnly_FallsBackToGET(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cfg := traefik_warden.CreateConfig()
	cfg.Methods = []string{"", "   ", "  "}

	handler, err := traefik_warden.New(context.Background(), next, cfg, "methods-ws-only")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should fall back to GET as all entries are whitespace-only
	reqGet := httptest.NewRequest(http.MethodGet, "/.env", nil)
	rrGet := httptest.NewRecorder()
	handler.ServeHTTP(rrGet, reqGet)
	if rrGet.Code != http.StatusForbidden {
		t.Errorf("expected whitespace-only methods to default to GET and block /.env, got %d", rrGet.Code)
	}

	reqPost := httptest.NewRequest(http.MethodPost, "/.env", nil)
	rrPost := httptest.NewRecorder()
	handler.ServeHTTP(rrPost, reqPost)
	if rrPost.Code != http.StatusOK {
		t.Errorf("expected POST to bypass when defaulted to GET-only, got %d", rrPost.Code)
	}
}

func TestRouteWarden_EmptyPatternStrings(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cfg := traefik_warden.CreateConfig()
	cfg.EnableDefaultPatterns = false
	cfg.PathPatterns = []string{"", "   ", `(?i)^/secret$`, ""}
	cfg.AllowPatterns = []string{"", "  ", `(?i)^/secret/allowed$`, ""}

	handler, err := traefik_warden.New(context.Background(), next, cfg, "empty-pattern-test")
	if err != nil {
		t.Fatalf("unexpected error creating handler with empty pattern strings: %v", err)
	}

	// /secret should be blocked
	req1 := httptest.NewRequest(http.MethodGet, "/secret", nil)
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusForbidden {
		t.Errorf("expected /secret to be blocked, got %d", rr1.Code)
	}

	// /secret/allowed should pass
	reqAllowed := httptest.NewRequest(http.MethodGet, "/secret/allowed", nil)
	rrAllowed := httptest.NewRecorder()
	handler.ServeHTTP(rrAllowed, reqAllowed)
	if rrAllowed.Code != http.StatusOK {
		t.Errorf("expected /secret/allowed to pass, got %d", rrAllowed.Code)
	}

	// /normal should pass
	req2 := httptest.NewRequest(http.MethodGet, "/normal", nil)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Errorf("expected /normal to pass, got %d", rr2.Code)
	}
}

func TestRouteWarden_DebugLogging(t *testing.T) {
	cfg := traefik_warden.CreateConfig()
	cfg.Debug = true
	cfg.CheckQuery = true
	cfg.AllowedIPs = []string{"192.168.1.100"}
	cfg.Methods = []string{"GET"}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	handler, err := traefik_warden.New(context.Background(), next, cfg, "debug-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 1. Blocked path
	reqBlock := httptest.NewRequest(http.MethodGet, "/.env", nil)
	rrBlock := httptest.NewRecorder()
	handler.ServeHTTP(rrBlock, reqBlock)
	if rrBlock.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rrBlock.Code)
	}

	// 2. Allowed path
	reqAllow := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	rrAllow := httptest.NewRecorder()
	handler.ServeHTTP(rrAllow, reqAllow)
	if rrAllow.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rrAllow.Code)
	}

	// 3. Whitelisted IP
	reqIP := httptest.NewRequest(http.MethodGet, "/.env", nil)
	reqIP.RemoteAddr = "192.168.1.100:5432"
	rrIP := httptest.NewRecorder()
	handler.ServeHTTP(rrIP, reqIP)
	if rrIP.Code != http.StatusOK {
		t.Errorf("expected 200 for whitelisted IP, got %d", rrIP.Code)
	}

	// 4. Non-inspected method
	reqPOST := httptest.NewRequest(http.MethodPost, "/.env", nil)
	rrPOST := httptest.NewRecorder()
	handler.ServeHTTP(rrPOST, reqPOST)
	if rrPOST.Code != http.StatusOK {
		t.Errorf("expected 200 for bypassed method, got %d", rrPOST.Code)
	}

	// 5. Blocked query
	reqQuery := httptest.NewRequest(http.MethodGet, "/test?file=.env", nil)
	rrQuery := httptest.NewRecorder()
	handler.ServeHTTP(rrQuery, reqQuery)
	if rrQuery.Code != http.StatusForbidden {
		t.Errorf("expected 403 for blocked query, got %d", rrQuery.Code)
	}

	// 6. Normal benign request
	reqNormal := httptest.NewRequest(http.MethodGet, "/about", nil)
	rrNormal := httptest.NewRecorder()
	handler.ServeHTTP(rrNormal, reqNormal)
	if rrNormal.Code != http.StatusOK {
		t.Errorf("expected 200 for normal request, got %d", rrNormal.Code)
	}
}

func TestRouteWarden_SecurityLog_Toggling(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// 1. SecurityLog = false
	cfgNoLog := traefik_warden.CreateConfig()
	cfgNoLog.SecurityLog = false

	handlerNoLog, err := traefik_warden.New(context.Background(), next, cfgNoLog, "no-sec-log")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.env", nil)
	rr := httptest.NewRecorder()
	handlerNoLog.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}

	// 2. SecurityLog = true with Mode = silentDrop
	cfgSilent := traefik_warden.CreateConfig()
	cfgSilent.SecurityLog = true
	cfgSilent.Mode = "silentDrop"
	cfgSilent.Response = nil

	handlerSilent, err := traefik_warden.New(context.Background(), next, cfgSilent, "silent-sec-log")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	reqSilent := httptest.NewRequest(http.MethodGet, "/.env", nil)
	rrSilent := httptest.NewRecorder()
	handlerSilent.ServeHTTP(rrSilent, reqSilent)
	if rrSilent.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rrSilent.Code)
	}
}

func TestRouteWarden_CheckQuery_MalformedUnescape(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cfg := traefik_warden.CreateConfig()
	cfg.CheckQuery = true
	cfg.BlockPatterns = []string{`(?i)malicious`}

	handler, err := traefik_warden.New(context.Background(), next, cfg, "malformed-query-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Send request with malformed percent-encoding (%ZZ) combined with blocked word
	req := httptest.NewRequest(http.MethodGet, "/search?q=%ZZmalicious", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 when malformed query contains blocked pattern, got %d", rr.Code)
	}
}

func TestRouteWarden_CheckQuery_RawQueryOnly(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Pattern matches the literal %20 or percent-encoded token in raw query, but not in unescaped space
	cfg := traefik_warden.CreateConfig()
	cfg.CheckQuery = true
	cfg.BlockPatterns = []string{`%20bad`}

	handler, err := traefik_warden.New(context.Background(), next, cfg, "raw-query-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/search?q=%20bad", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 when raw query matches pattern, got %d", rr.Code)
	}
}

func TestRouteWarden_CheckHeaders(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	cfg := traefik_warden.CreateConfig()
	cfg.CheckHeaders = []string{"X-Forwarded-Uri", "X-Rewrite-URL", "X-Original-URL"}

	handler, err := traefik_warden.New(context.Background(), next, cfg, "check-headers-test")
	if err != nil {
		t.Fatalf("failed to create plugin: %v", err)
	}

	// 1. Clean request with benign headers should pass
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)
	req.Header.Set("X-Forwarded-Uri", "/api/dashboard")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for clean forwarded header, got %d", rr.Code)
	}

	// 2. Request with smuggled sensitive path in X-Forwarded-Uri
	req = httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)
	req.Header.Set("X-Forwarded-Uri", "/.env")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for smuggled .env in X-Forwarded-Uri, got %d", rr.Code)
	}

	// 3. Request with URL-encoded path in X-Rewrite-URL
	req = httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)
	req.Header.Set("X-Rewrite-URL", "/%2e%2e/.git/config")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for smuggled .git/config in X-Rewrite-URL, got %d", rr.Code)
	}
}



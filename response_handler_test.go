package traefik_warden_test

import (
	"bufio"
	"compress/gzip"
	"context"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/routewarden/traefik-warden"
)

func TestResponseHandler_JSON(t *testing.T) {
	cfg := &traefik_warden.ResponseConfig{
		Mode:       "json",
		StatusCode: http.StatusTeapot,
		Body:       `{"error":"blocked","code":418}`,
		Headers: map[string]string{
			"X-Custom-Header": "WardenSec",
		},
	}

	handler, err := traefik_warden.NewResponseHandler(cfg, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeBlockedRequest(rr, req)

	if rr.Code != http.StatusTeapot {
		t.Errorf("expected %d, got %d", http.StatusTeapot, rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "application/json") {
		t.Errorf("expected application/json content-type")
	}
	if rr.Header().Get("X-Custom-Header") != "WardenSec" {
		t.Errorf("expected custom header")
	}
	if !strings.Contains(rr.Body.String(), `"error":"blocked"`) {
		t.Errorf("unexpected body: %s", rr.Body.String())
	}
}

func TestResponseHandler_HTML(t *testing.T) {
	cfg := &traefik_warden.ResponseConfig{
		Mode:       "html",
		StatusCode: http.StatusForbidden,
		Body:       "<html><body>Access Restricted</body></html>",
	}

	handler, err := traefik_warden.NewResponseHandler(cfg, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeBlockedRequest(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected %d, got %d", http.StatusForbidden, rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "text/html") {
		t.Errorf("expected text/html content-type")
	}
	if !strings.Contains(rr.Body.String(), "Access Restricted") {
		t.Errorf("unexpected body: %s", rr.Body.String())
	}
}

func TestResponseHandler_Captcha(t *testing.T) {
	cfg := &traefik_warden.ResponseConfig{
		Mode:       "captcha",
		StatusCode: http.StatusForbidden,
		Captcha: &traefik_warden.CaptchaConfig{
			Provider: "turnstile",
			SiteKey:  "0x4AAAAAAtestkey",
			Title:    "Bot Check",
		},
	}

	handler, err := traefik_warden.NewResponseHandler(cfg, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeBlockedRequest(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected %d, got %d", http.StatusForbidden, rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "cf-turnstile") {
		t.Errorf("expected turnstile widget in body")
	}
	if !strings.Contains(body, "0x4AAAAAAtestkey") {
		t.Errorf("expected sitekey in body")
	}
}

func TestResponseHandler_Redirect(t *testing.T) {
	cfg := &traefik_warden.ResponseConfig{
		Mode:        "redirect",
		StatusCode:  http.StatusFound,
		RedirectURL: "https://example.com/blocked",
	}

	handler, err := traefik_warden.NewResponseHandler(cfg, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeBlockedRequest(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("expected %d, got %d", http.StatusFound, rr.Code)
	}
	if rr.Header().Get("Location") != "https://example.com/blocked" {
		t.Errorf("expected Location header")
	}
}

func TestResponseHandler_SilentDrop_ModeConfig(t *testing.T) {
	cfg := &traefik_warden.ResponseConfig{
		Mode: "silentDrop",
	}
	handler, err := traefik_warden.NewResponseHandler(cfg, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeBlockedRequest(rr, req)

	if rr.Body.Len() > 0 {
		t.Errorf("expected empty body for silent drop")
	}
}

func TestResponseHandler_SilentDrop(t *testing.T) {
	handler, err := traefik_warden.NewResponseHandler(nil, http.StatusForbidden, "", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeBlockedRequest(rr, req)

	// Bug 2 fix: when TCP hijacking is unavailable (httptest.ResponseRecorder does not
	// implement http.Hijacker), silentDrop falls back to 200 OK with an empty body
	// instead of leaking the real block status code to the client.
	if rr.Code != http.StatusOK {
		t.Errorf("expected %d, got %d", http.StatusOK, rr.Code)
	}
	if rr.Body.Len() > 0 {
		t.Errorf("expected empty body for silent drop")
	}
}

func TestResponseHandler_InvalidCaptchaTemplate(t *testing.T) {
	cfg := &traefik_warden.ResponseConfig{
		Mode: "captcha",
		Captcha: &traefik_warden.CaptchaConfig{
			Template: "{{.UnclosedBracket",
		},
	}

	_, err := traefik_warden.NewResponseHandler(cfg, 0, "", false)
	if err == nil {
		t.Errorf("expected error for invalid captcha template")
	}
}

func TestResponseHandler_DefaultTextAndEmptyFallbacks(t *testing.T) {
	// 1. Default text mode with top-level message
	handlerText, err := traefik_warden.NewResponseHandler(nil, http.StatusForbidden, "Access Denied by Text", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr1 := httptest.NewRecorder()
	handlerText.ServeBlockedRequest(rr1, req1)

	if !strings.Contains(rr1.Body.String(), "Access Denied by Text") {
		t.Errorf("expected default text response, got %s", rr1.Body.String())
	}
	if !strings.Contains(rr1.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("expected text/plain content-type, got %s", rr1.Header().Get("Content-Type"))
	}

	// 2. JSON mode with empty body fallback
	handlerJSON, err := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode:       "json",
		StatusCode: http.StatusForbidden,
	}, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr2 := httptest.NewRecorder()
	handlerJSON.ServeBlockedRequest(rr2, req2)

	if !strings.Contains(rr2.Body.String(), `"error":"Forbidden"`) {
		t.Errorf("expected default json payload, got %s", rr2.Body.String())
	}

	// 3. HTML mode with empty body fallback
	handlerHTML, err := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode:       "html",
		StatusCode: http.StatusNotFound,
	}, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req3 := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr3 := httptest.NewRecorder()
	handlerHTML.ServeBlockedRequest(rr3, req3)

	if !strings.Contains(rr3.Body.String(), "404 Forbidden") && !strings.Contains(rr3.Body.String(), "Access to this resource is denied") {
		t.Errorf("expected default html payload, got %s", rr3.Body.String())
	}

	// 4. Custom Captcha Template
	handlerCustomCaptcha, err := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode:       "captcha",
		StatusCode: http.StatusForbidden,
		Captcha: &traefik_warden.CaptchaConfig{
			Template: "<div>{{.Title}} - SiteKey: {{.SiteKey}}</div>",
			Title:    "Custom Challenge",
			SiteKey:  "my-custom-key-999",
		},
	}, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req4 := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr4 := httptest.NewRecorder()
	handlerCustomCaptcha.ServeBlockedRequest(rr4, req4)

	if !strings.Contains(rr4.Body.String(), "Custom Challenge - SiteKey: my-custom-key-999") {
		t.Errorf("expected custom captcha template output, got %s", rr4.Body.String())
	}
}

func TestResponseHandler_GzipBomb(t *testing.T) {
	// 1. Test gzipBomb mode with default size (10MB)
	cfg := &traefik_warden.ResponseConfig{
		Mode:       "gzipBomb",
		StatusCode: http.StatusOK,
	}

	handler, err := traefik_warden.NewResponseHandler(cfg, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.env", nil)
	rr := httptest.NewRecorder()
	handler.ServeBlockedRequest(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected %d, got %d", http.StatusOK, rr.Code)
	}
	if rr.Header().Get("Content-Encoding") != "gzip" {
		t.Errorf("expected Content-Encoding: gzip, got %s", rr.Header().Get("Content-Encoding"))
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "text/html") {
		t.Errorf("expected text/html Content-Type, got %s", rr.Header().Get("Content-Type"))
	}

	// Verify the payload is valid gzip and expands
	gzReader, err := gzip.NewReader(rr.Body)
	if err != nil {
		t.Fatalf("failed to create gzip reader from response: %v", err)
	}
	defer gzReader.Close()

	// Read first 1MB of decompressed stream to verify it's zero bytes without exhausting test RAM
	buf := make([]byte, 1024*1024)
	n, err := io.ReadFull(gzReader, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		t.Fatalf("failed reading uncompressed stream: %v", err)
	}
	if n != len(buf) {
		t.Errorf("expected to read at least 1MB of decompressed zeroes, read %d bytes", n)
	}
	for i := 0; i < 1024; i++ {
		if buf[i] != 0 {
			t.Errorf("expected byte 0 at pos %d, got %d", i, buf[i])
			break
		}
	}

	// 2. Test alias mode "bomb" with custom size and custom status code
	cfgCustom := &traefik_warden.ResponseConfig{
		Mode:        "bomb",
		StatusCode:  http.StatusForbidden,
		GzipBombMB:  2,
		ContentType: "text/plain",
	}

	handlerCustom, err := traefik_warden.NewResponseHandler(cfgCustom, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rrCustom := httptest.NewRecorder()
	handlerCustom.ServeBlockedRequest(rrCustom, req)

	if rrCustom.Code != http.StatusForbidden {
		t.Errorf("expected %d, got %d", http.StatusForbidden, rrCustom.Code)
	}
	if rrCustom.Header().Get("Content-Encoding") != "gzip" {
		t.Errorf("expected Content-Encoding: gzip")
	}
	if rrCustom.Header().Get("Content-Type") != "text/plain" {
		t.Errorf("expected text/plain Content-Type, got %s", rrCustom.Header().Get("Content-Type"))
	}
}

func TestResponseHandler_XML(t *testing.T) {
	// Default XML
	handler, err := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode:       "xml",
		StatusCode: http.StatusForbidden,
	}, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/endpoint", nil)
	rr := httptest.NewRecorder()
	handler.ServeBlockedRequest(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected %d, got %d", http.StatusForbidden, rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "application/xml") {
		t.Errorf("expected application/xml content-type")
	}
	if !strings.Contains(rr.Body.String(), "<Error>") || !strings.Contains(rr.Body.String(), "<Status>403</Status>") {
		t.Errorf("unexpected xml body: %s", rr.Body.String())
	}

	// Custom XML body
	handlerCustom, _ := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode:       "xml",
		StatusCode: http.StatusUnauthorized,
		Body:       "<soap:Fault><faultcode>Client</faultcode></soap:Fault>",
	}, 0, "", false)
	rrCustom := httptest.NewRecorder()
	handlerCustom.ServeBlockedRequest(rrCustom, req)
	if !strings.Contains(rrCustom.Body.String(), "<soap:Fault>") {
		t.Errorf("expected custom XML fault body")
	}
}

func TestResponseHandler_RateLimitChallenge(t *testing.T) {
	handler, err := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode:              "rateLimitChallenge",
		RetryAfterSeconds: 600,
	}, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()
	handler.ServeBlockedRequest(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", rr.Code)
	}
	if rr.Header().Get("Retry-After") != "600" {
		t.Errorf("expected Retry-After: 600, got %s", rr.Header().Get("Retry-After"))
	}
	if !strings.Contains(rr.Body.String(), `"retryAfter":600`) {
		t.Errorf("unexpected body: %s", rr.Body.String())
	}
}

func TestResponseHandler_FakeSuccessDecoy(t *testing.T) {
	handler, err := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode: "fakeSuccess",
	}, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test .env synthetic response
	reqEnv := httptest.NewRequest(http.MethodGet, "/.env", nil)
	rrEnv := httptest.NewRecorder()
	handler.ServeBlockedRequest(rrEnv, reqEnv)
	if rrEnv.Code != http.StatusOK {
		t.Errorf("expected 200 OK for decoy")
	}
	if !strings.Contains(rrEnv.Body.String(), "APP_NAME=Laravel") || !strings.Contains(rrEnv.Body.String(), "DB_PASSWORD=") {
		t.Errorf("expected synthetic .env body, got: %s", rrEnv.Body.String())
	}

	// Test actuator health decoy
	reqActuator := httptest.NewRequest(http.MethodGet, "/actuator/health", nil)
	rrActuator := httptest.NewRecorder()
	handler.ServeBlockedRequest(rrActuator, reqActuator)
	if !strings.Contains(rrActuator.Body.String(), `"status":"UP"`) {
		t.Errorf("expected actuator decoy, got: %s", rrActuator.Body.String())
	}

	// Test git/HEAD decoy
	reqGit := httptest.NewRequest(http.MethodGet, "/.git/HEAD", nil)
	rrGit := httptest.NewRecorder()
	handler.ServeBlockedRequest(rrGit, reqGit)
	if !strings.Contains(rrGit.Body.String(), "ref: refs/heads/master") {
		t.Errorf("expected git decoy, got: %s", rrGit.Body.String())
	}

	// Test phpinfo decoy
	reqPHP := httptest.NewRequest(http.MethodGet, "/phpinfo.php", nil)
	rrPHP := httptest.NewRecorder()
	handler.ServeBlockedRequest(rrPHP, reqPHP)
	if !strings.Contains(rrPHP.Body.String(), "phpinfo()") {
		t.Errorf("expected phpinfo decoy, got: %s", rrPHP.Body.String())
	}

	// Test wp-login decoy
	reqWP := httptest.NewRequest(http.MethodGet, "/wp-login.php", nil)
	rrWP := httptest.NewRecorder()
	handler.ServeBlockedRequest(rrWP, reqWP)
	if !strings.Contains(rrWP.Body.String(), "WordPress") {
		t.Errorf("expected wp-login decoy, got: %s", rrWP.Body.String())
	}

	// Test generic route decoy
	reqGeneric := httptest.NewRequest(http.MethodGet, "/api/something", nil)
	rrGeneric := httptest.NewRecorder()
	handler.ServeBlockedRequest(rrGeneric, reqGeneric)
	if !strings.Contains(rrGeneric.Body.String(), `"status":"success"`) {
		t.Errorf("expected generic success decoy")
	}
}

func TestResponseHandler_Proxy(t *testing.T) {
	// 1. Test Proxy handler with custom RoundTripper so it doesn't need to bind network ports in sandbox
	targetURL, _ := url.Parse("http://honeypot.local")
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	type testTransport struct{}
	proxy.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		rec.Header().Set("X-Honeypot-Captured", "true")
		rec.WriteHeader(http.StatusTeapot)
		_, _ = rec.WriteString("honeypot-captured")
		resp := rec.Result()
		resp.Request = req
		return resp, nil
	})

	handler, err := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode:     "proxy",
		ProxyURL: "http://honeypot.local",
	}, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Inject test proxy
	handler.SetProxyHandlerForTest(proxy)

	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	rr := httptest.NewRecorder()
	handler.ServeBlockedRequest(rr, req)

	if rr.Code != http.StatusTeapot {
		t.Errorf("expected %d from honeypot backend, got %d", http.StatusTeapot, rr.Code)
	}
	if rr.Header().Get("X-Honeypot-Captured") != "true" {
		t.Errorf("expected proxy header")
	}
	if !strings.Contains(rr.Body.String(), "honeypot-captured") {
		t.Errorf("expected honeypot body")
	}

	// 2. Test invalid proxy URL error
	_, errInvalid := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode:     "proxy",
		ProxyURL: "://invalid-url",
	}, 0, "", false)
	if errInvalid == nil {
		t.Errorf("expected error for invalid proxy URL")
	}

	// 3. Test empty proxy fallback
	handlerEmpty, _ := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode: "proxy",
	}, 0, "", false)
	rrEmpty := httptest.NewRecorder()
	handlerEmpty.ServeBlockedRequest(rrEmpty, req)
	if rrEmpty.Code != http.StatusBadGateway {
		t.Errorf("expected 502 for unconfigured proxy, got %d", rrEmpty.Code)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestResponseHandler_InfiniteStream(t *testing.T) {
	handler, err := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode:         "infiniteStream",
		StatusCode:   http.StatusOK,
		StreamSizeMB: 1, // 1MB in test
	}, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	rr := httptest.NewRecorder()
	handler.ServeBlockedRequest(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if rr.Body.Len() < 1024*1024 {
		t.Errorf("expected at least 1MB garbage stream, got %d bytes", rr.Body.Len())
	}
}

func TestResponseHandler_Tarpit(t *testing.T) {
	handler, err := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode:                     "tarpit",
		StatusCode:               http.StatusOK,
		TarpitDelayMs:           5,  // Fast delay for testing
		TarpitMaxDurationSeconds: 1,  // 1 second max
	}, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test context cancellation exits cleanly
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	req := httptest.NewRequest(http.MethodGet, "/probe", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	handler.ServeBlockedRequest(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	// Test tarpit natural timeout branch
	handlerTimeout, _ := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode:                     "tarpit",
		TarpitDelayMs:           5,
		TarpitMaxDurationSeconds: 1, // 1 second timeout
	}, 0, "", false)
	reqTimeout := httptest.NewRequest(http.MethodGet, "/probe", nil)
	rrTimeout := httptest.NewRecorder()
	handlerTimeout.ServeBlockedRequest(rrTimeout, reqTimeout)
	if rrTimeout.Code != http.StatusForbidden {
		t.Errorf("expected default 403 for tarpit without explicit code")
	}
}

func TestResponseHandler_EdgeCases(t *testing.T) {
	// 1. Custom Body & Status for FakeSuccess
	handlerCustomDecoy, err := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode:        "fakeSuccess",
		StatusCode:  http.StatusAccepted,
		ContentType: "application/json",
		Body:        `{"custom":"decoy_payload"}`,
	}, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	reqDecoy := httptest.NewRequest(http.MethodGet, "/.env", nil)
	rrDecoy := httptest.NewRecorder()
	handlerCustomDecoy.ServeBlockedRequest(rrDecoy, reqDecoy)
	if rrDecoy.Code != http.StatusAccepted {
		t.Errorf("expected status 202, got %d", rrDecoy.Code)
	}
	if !strings.Contains(rrDecoy.Body.String(), `"custom":"decoy_payload"`) {
		t.Errorf("expected custom decoy payload")
	}

	// 2. Redirect without code (should default to 302 Found)
	handlerRedir, err := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode:        "redirect",
		RedirectURL: "https://example.com/honeypot",
		StatusCode:  200, // Invalid redirect code should fallback to 302
	}, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rrRedir := httptest.NewRecorder()
	handlerRedir.ServeBlockedRequest(rrRedir, reqDecoy)
	if rrRedir.Code != http.StatusFound {
		t.Errorf("expected fallback to 302 Found, got %d", rrRedir.Code)
	}

	// 3. Redirect without redirectURL (should default to "/")
	handlerRedirDefault, _ := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode: "redirect",
	}, 0, "", false)
	rrRedirDefault := httptest.NewRecorder()
	handlerRedirDefault.ServeBlockedRequest(rrRedirDefault, reqDecoy)
	if rrRedirDefault.Header().Get("Location") != "/" {
		t.Errorf("expected Location: /, got %s", rrRedirDefault.Header().Get("Location"))
	}

	// 4. RateLimitChallenge with custom body and status code
	handlerRL, _ := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode:              "rateLimit",
		StatusCode:        http.StatusTooManyRequests,
		RetryAfterSeconds: 120,
		ContentType:       "text/plain",
		Body:              "Calm down bot",
	}, 0, "", false)
	rrRL := httptest.NewRecorder()
	handlerRL.ServeBlockedRequest(rrRL, reqDecoy)
	if rrRL.Header().Get("Retry-After") != "120" {
		t.Errorf("expected Retry-After: 120, got %s", rrRL.Header().Get("Retry-After"))
	}
	if !strings.Contains(rrRL.Body.String(), "Calm down bot") {
		t.Errorf("expected custom rate limit body")
	}

	// 5. XML with custom content type and status code
	handlerXML, _ := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode:        "xml",
		StatusCode:  http.StatusPaymentRequired,
		ContentType: "application/soap+xml",
	}, 0, "", false)
	rrXML := httptest.NewRecorder()
	handlerXML.ServeBlockedRequest(rrXML, reqDecoy)
	if rrXML.Code != http.StatusPaymentRequired {
		t.Errorf("expected 402, got %d", rrXML.Code)
	}
	if rrXML.Header().Get("Content-Type") != "application/soap+xml" {
		t.Errorf("expected custom xml content type")
	}

	// 6. InfiniteStream default fallback size (<=0 MB defaults to 50MB in production, tested with 0)
	handlerStreamZero, _ := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode:         "infiniteStream",
		StreamSizeMB: -1,
	}, 0, "", false)
	if handlerStreamZero == nil {
		t.Errorf("failed creating infiniteStream handler")
	}

	// 7. GzipBomb with 0 MB defaults
	handlerBombZero, _ := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode:       "gzipBomb",
		GzipBombMB: 0,
	}, 0, "", false)
	rrBombZero := httptest.NewRecorder()
	handlerBombZero.ServeBlockedRequest(rrBombZero, reqDecoy)
	if rrBombZero.Header().Get("Content-Encoding") != "gzip" {
		t.Errorf("expected gzip encoding")
	}
}

func TestResponseHandler_NilConfig_Defaults(t *testing.T) {
	// nil respCfg + zero topStatusCode should default to 403 and mode "text"
	handler, err := traefik_warden.NewResponseHandler(nil, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeBlockedRequest(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected nil config to default to 403, got %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("expected nil config to default to text/plain content-type, got %q", rr.Header().Get("Content-Type"))
	}
}

func TestResponseHandler_NilConfig_WithTopStatusCode(t *testing.T) {
	// nil respCfg + topStatusCode=404 should use 404
	handler, err := traefik_warden.NewResponseHandler(nil, http.StatusNotFound, "Custom Not Found", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeBlockedRequest(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 from topStatusCode, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Custom Not Found") {
		t.Errorf("expected custom response text body, got %q", rr.Body.String())
	}
}

func TestResponseHandler_TopStatusCodeFallback_WithRespConfig(t *testing.T) {
	handler, err := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		StatusCode: 0,
		Mode:       "text",
	}, http.StatusTeapot, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeBlockedRequest(rr, req)

	if rr.Code != http.StatusTeapot {
		t.Errorf("expected inherited status code 418, got %d", rr.Code)
	}
}

func TestResponseHandler_ZeroStatusCode_EmptyMode(t *testing.T) {
	// respCfg with StatusCode=0 and Mode="" should default to 403 and "text"
	handler, err := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		StatusCode: 0,
		Mode:       "",
	}, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeBlockedRequest(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected default 403, got %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("expected default text/plain, got %q", rr.Header().Get("Content-Type"))
	}
}

// mockHijackConn is a minimal net.Conn for testing silent drop hijack.
type mockHijackConn struct {
	closed bool
}

func (c *mockHijackConn) Read(_ []byte) (int, error)         { return 0, io.EOF }
func (c *mockHijackConn) Write(_ []byte) (int, error)        { return 0, io.EOF }
func (c *mockHijackConn) Close() error                       { c.closed = true; return nil }
func (c *mockHijackConn) LocalAddr() net.Addr                { return nil }
func (c *mockHijackConn) RemoteAddr() net.Addr               { return nil }
func (c *mockHijackConn) SetDeadline(_ time.Time) error      { return nil }
func (c *mockHijackConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *mockHijackConn) SetWriteDeadline(_ time.Time) error { return nil }

// hijackableRecorder wraps httptest.ResponseRecorder and implements http.Hijacker.
type hijackableRecorder struct {
	*httptest.ResponseRecorder
	conn     *mockHijackConn
	hijacked bool
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	h.conn = &mockHijackConn{}
	return h.conn, bufio.NewReadWriter(bufio.NewReader(strings.NewReader("")), bufio.NewWriter(io.Discard)), nil
}

func TestResponseHandler_SilentDrop_WithHijacker(t *testing.T) {
	handler, err := traefik_warden.NewResponseHandler(nil, 0, "", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.env", nil)
	rec := &hijackableRecorder{ResponseRecorder: httptest.NewRecorder()}
	handler.ServeBlockedRequest(rec, req)

	if !rec.hijacked {
		t.Errorf("expected Hijack() to be called for silent drop")
	}
	// With successful hijack, no status code should be written (the connection was closed)
	// The recorder's Code stays at the default 200 since WriteHeader was never called
	if rec.Code != http.StatusOK {
		t.Errorf("expected no explicit status code write after successful hijack, got %d", rec.Code)
	}
}

func TestResponseHandler_TarpitZeroDefaults(t *testing.T) {
	// Tarpit with zero delay and zero max duration should use defaults
	handler, err := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode:                     "tarpit",
		StatusCode:               http.StatusForbidden,
		TarpitDelayMs:            0,
		TarpitMaxDurationSeconds: 0,
	}, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.env", nil)
	// Use a context with a very short timeout so we don't hang
	ctx, cancel := context.WithTimeout(req.Context(), 100*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeBlockedRequest(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestResponseHandler_RateLimitZeroDefaults(t *testing.T) {
	// RateLimit with zero RetryAfterSeconds should fall back to 300
	handler, err := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode:              "ratelimit",
		RetryAfterSeconds: 0,
	}, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.env", nil)
	rr := httptest.NewRecorder()
	handler.ServeBlockedRequest(rr, req)

	if rr.Header().Get("Retry-After") != "300" {
		t.Errorf("expected default Retry-After: 300, got %q", rr.Header().Get("Retry-After"))
	}
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", rr.Code)
	}
}

func TestResponseHandler_InfiniteStreamZeroDefaults(t *testing.T) {
	// InfiniteStream with zero StreamSizeMB should fall back to default 50MB
	handler, err := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode:         "infiniteStream",
		StatusCode:   http.StatusOK,
		StreamSizeMB: 0,
	}, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.env", nil)
	rr := httptest.NewRecorder()
	handler.ServeBlockedRequest(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "application/octet-stream") {
		t.Errorf("expected application/octet-stream content-type, got %q", rr.Header().Get("Content-Type"))
	}
	// With 50MB default, body should be substantial
	if rr.Body.Len() < 1024 {
		t.Errorf("expected substantial body from infiniteStream, got %d bytes", rr.Body.Len())
	}
}

func TestResponseHandler_Captcha_TemplateExecutionError(t *testing.T) {
	handler, err := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode:       "captcha",
		StatusCode: http.StatusForbidden,
	}, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Inject a template that parses successfully but fails at execution time
	faultyTmpl, err := template.New("faulty").Parse("{{.NoSuchField.CannotIndex}}")
	if err != nil {
		t.Fatalf("unexpected template parse error: %v", err)
	}
	handler.SetCaptchaTemplateForTest(faultyTmpl)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()
	handler.ServeBlockedRequest(rr, req)

	if !strings.Contains(rr.Body.String(), "Security Challenge Required") {
		t.Errorf("expected fallback text on captcha template execution failure, got: %q", rr.Body.String())
	}
}

type errResponseWriter struct {
	header http.Header
}

func newErrResponseWriter() *errResponseWriter {
	return &errResponseWriter{header: make(http.Header)}
}

func (e *errResponseWriter) Header() http.Header {
	return e.header
}

func (e *errResponseWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func (e *errResponseWriter) WriteHeader(statusCode int) {}

func TestResponseHandler_ClientDisconnect_Streams(t *testing.T) {
	// 1. GzipBomb handles client disconnect/write error gracefully
	handlerBomb, err := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode:       "gzipBomb",
		StatusCode: http.StatusOK,
		GzipBombMB: 1,
	}, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.env", nil)
	errWriterBomb := newErrResponseWriter()
	// Must not panic or hang
	handlerBomb.ServeBlockedRequest(errWriterBomb, req)

	// 2. InfiniteStream handles client disconnect/write error gracefully
	handlerStream, err := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode:         "infiniteStream",
		StatusCode:   http.StatusOK,
		StreamSizeMB: 1,
	}, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	errWriterStream := newErrResponseWriter()
	handlerStream.ServeBlockedRequest(errWriterStream, req)

	// 3. Tarpit handles client disconnect on ticker write gracefully
	handlerTarpit, err := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode:                     "tarpit",
		StatusCode:               http.StatusOK,
		TarpitDelayMs:           1,
		TarpitMaxDurationSeconds: 1,
	}, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	errWriterTarpit := newErrResponseWriter()
	handlerTarpit.ServeBlockedRequest(errWriterTarpit, req)
}

func TestResponseHandler_Proxy_UnsafeSchemes(t *testing.T) {
	unsafeURLs := []string{
		"javascript:alert(1)",
		"data:text/plain,hello",
		"ftp://attacker.com/sink",
		"file:///etc/passwd",
	}

	for _, u := range unsafeURLs {
		_, err := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
			Mode:     "proxy",
			ProxyURL: u,
		}, 0, "", false)
		if err == nil {
			t.Errorf("expected error for unsafe proxyUrl %q, got nil", u)
		}
	}
}

func TestResponseHandler_CRLF_Headers(t *testing.T) {
	h, err := traefik_warden.NewResponseHandler(&traefik_warden.ResponseConfig{
		Mode: "text",
		Headers: map[string]string{
			"X-Injected\r\nHeader": "val\r\nSet-Cookie: evil=1",
		},
	}, 0, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	h.ServeBlockedRequest(rr, req)

	if rr.Header().Get("X-InjectedHeader") != "valSet-Cookie: evil=1" {
		t.Errorf("expected sanitized header, got: %q", rr.Header().Get("X-InjectedHeader"))
	}
	if rr.Header().Get("X-Injected\r\nHeader") != "" {
		t.Errorf("expected raw CRLF header to be omitted")
	}
}




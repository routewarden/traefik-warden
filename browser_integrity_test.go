package traefik_warden

import (
	"net/http"
	"testing"
)

func TestDetectBrowserImpersonation(t *testing.T) {
	chromeUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"

	// 1. Legitimate browser with full companion headers
	validHeaders := http.Header{}
	validHeaders.Set("Accept-Language", "en-US,en;q=0.9")
	validHeaders.Set("Accept-Encoding", "gzip, deflate, br")
	validHeaders.Set("Sec-CH-UA-Platform", `"Windows"`)
	validHeaders.Set("Sec-Fetch-Site", "none")
	validHeaders.Set("Sec-Fetch-Mode", "navigate")
	validHeaders.Set("Sec-Fetch-Dest", "document")

	isSpoofed, reason := DetectBrowserImpersonation(chromeUA, validHeaders)
	if isSpoofed {
		t.Fatalf("expected valid Chrome to not be flagged as spoofed, got reason=%s", reason)
	}

	// 2. Missing Accept-Language
	missingLangHeaders := validHeaders.Clone()
	missingLangHeaders.Del("Accept-Language")
	isSpoofed, reason = DetectBrowserImpersonation(chromeUA, missingLangHeaders)
	if !isSpoofed || reason != "missing_accept_language" {
		t.Errorf("expected missing_accept_language, got isSpoofed=%v, reason=%s", isSpoofed, reason)
	}

	// 3. Missing Accept-Encoding
	missingEncHeaders := validHeaders.Clone()
	missingEncHeaders.Del("Accept-Encoding")
	isSpoofed, reason = DetectBrowserImpersonation(chromeUA, missingEncHeaders)
	if !isSpoofed || reason != "missing_accept_encoding" {
		t.Errorf("expected missing_accept_encoding, got isSpoofed=%v, reason=%s", isSpoofed, reason)
	}

	// 4. Platform mismatch: Windows in UA, but Linux in Sec-CH-UA-Platform
	mismatchHeaders := validHeaders.Clone()
	mismatchHeaders.Set("Sec-CH-UA-Platform", `"Linux"`)
	isSpoofed, reason = DetectBrowserImpersonation(chromeUA, mismatchHeaders)
	if !isSpoofed || reason != "sec_ch_ua_platform_mismatch" {
		t.Errorf("expected sec_ch_ua_platform_mismatch, got isSpoofed=%v, reason=%s", isSpoofed, reason)
	}

	// 5. Chrome 128 missing Sec-Fetch-* headers
	noFetchHeaders := validHeaders.Clone()
	noFetchHeaders.Del("Sec-Fetch-Site")
	noFetchHeaders.Del("Sec-Fetch-Mode")
	noFetchHeaders.Del("Sec-Fetch-Dest")
	isSpoofed, reason = DetectBrowserImpersonation(chromeUA, noFetchHeaders)
	if !isSpoofed || reason != "missing_sec_fetch" {
		t.Errorf("expected missing_sec_fetch, got isSpoofed=%v, reason=%s", isSpoofed, reason)
	}

	// 6. Search engine bot (Googlebot) claiming Mozilla/5.0 should not be rejected here
	googleUA := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	isSpoofed, _ = DetectBrowserImpersonation(googleUA, http.Header{})
	if isSpoofed {
		t.Errorf("expected Googlebot to be exempt from browser impersonation check")
	}

	// 7. Non-browser User-Agent (e.g. mobile API client)
	apiUA := "MyCustomApp/1.0"
	isSpoofed, _ = DetectBrowserImpersonation(apiUA, http.Header{})
	if isSpoofed {
		t.Errorf("expected custom API app to not be treated as browser-like")
	}
}

func TestDetectScriptClient(t *testing.T) {
	tests := []struct {
		name       string
		ua         string
		headers    http.Header
		wantDetect bool
	}{
		{
			name:       "python-requests",
			ua:         "python-requests/2.31.0",
			headers:    http.Header{},
			wantDetect: true,
		},
		{
			name:       "aiohttp",
			ua:         "Python/3.10 aiohttp/3.8.5",
			headers:    http.Header{},
			wantDetect: true,
		},
		{
			name:       "axios",
			ua:         "axios/1.6.0",
			headers:    http.Header{},
			wantDetect: true,
		},
		{
			name:       "go-http-client",
			ua:         "Go-http-client/2.0",
			headers:    http.Header{},
			wantDetect: true,
		},
		{
			name:       "curl",
			ua:         "curl/8.1.2",
			headers:    http.Header{},
			wantDetect: true,
		},
		{
			name: "playwright header",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
			headers: http.Header{
				"X-Playwright": []string{"true"},
			},
			wantDetect: true,
		},
		{
			name: "sec-webdriver header",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
			headers: http.Header{
				"Sec-Webdriver": []string{"?1"},
			},
			wantDetect: true,
		},
		{
			name:       "legitimate browser",
			ua:         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
			headers:    http.Header{},
			wantDetect: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			detected, _ := DetectScriptClient(tc.ua, tc.headers)
			if detected != tc.wantDetect {
				t.Errorf("tc %s: got detected=%v, want %v", tc.name, detected, tc.wantDetect)
			}
		})
	}
}

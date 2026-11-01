package traefik_warden_test

import (
	"testing"

	"github.com/routewarden/traefik-warden"
)

func TestPathNormalizer_ExtractCandidatePaths(t *testing.T) {
	tests := []struct {
		name             string
		rawPath          string
		path             string
		requestURI       string
		expectedContains []string
	}{
		{
			name:             "Standard path",
			path:             "/api/v1/users",
			expectedContains: []string{"/api/v1/users"},
		},
		{
			name:             "Single URL encoded dot (%2eenv)",
			path:             "/%2eenv",
			expectedContains: []string{"/.env"},
		},
		{
			name:             "Double URL encoded dot (%252eenv)",
			path:             "/%252eenv",
			expectedContains: []string{"/.env"},
		},
		{
			name:             "Double URL encoded path traversal (%252e%252e)",
			path:             "/static/%252e%252e/.env",
			expectedContains: []string{"/.env"},
		},
		{
			name:             "RawPath difference provided",
			rawPath:          "/raw/%2eenv",
			path:             "/raw/.env",
			expectedContains: []string{"/raw/.env"},
		},
		{
			name:             "Semicolon matrix parameter prefix (/;.env)",
			path:             "/;.env",
			expectedContains: []string{"/.env"},
		},
		{
			name:             "Semicolon matrix parameter in segment (/app;jsessionid=123/.env)",
			path:             "/app;jsessionid=123/.env",
			expectedContains: []string{"/app/.env"},
		},
		{
			name:             "Semicolon embedded within segment (/api;.env/config.json)",
			path:             "/api;.env/config.json",
			expectedContains: []string{"/api/.env/config.json"},
		},
		{
			name:             "Windows backslash separator (\\..\\.env)",
			path:             "/static\\..\\.env",
			expectedContains: []string{"/.env"},
		},
		{
			name:             "Direct backslash path (/\\.env)",
			path:             "/\\.env",
			expectedContains: []string{"/.env"},
		},
		{
			name:             "Null byte in path",
			path:             "/.env\x00.png",
			expectedContains: []string{"/.env", "/.env.png"},
		},
		{
			name:             "Null byte extension truncation",
			path:             "/config.ini\x00.png",
			expectedContains: []string{"/config.ini", "/config.ini.png"},
		},
		{
			name:             "URL-encoded null byte truncation",
			path:             "/database.backup.sql%00.jpg",
			expectedContains: []string{"/database.backup.sql"},
		},
		{
			name:             "RequestURI query string stripped for candidate path",
			path:             "/search",
			requestURI:       "/search?file=.env",
			expectedContains: []string{"/search"},
		},
		{
			name:             "Dot slash canonical path (/./.env)",
			path:             "/./.env",
			expectedContains: []string{"/.env"},
		},
		{
			name:             "NTFS Alternate Data Stream (::$DATA)",
			path:             "/wp-config.php::$DATA",
			expectedContains: []string{"/wp-config.php"},
		},
		{
			name:             "NTFS Alternate Data Stream case-insensitive (::$data)",
			path:             "/settings.py::$data",
			expectedContains: []string{"/settings.py"},
		},
		{
			name:             "Trailing dot on sensitive file extension",
			path:             "/settings.py.",
			expectedContains: []string{"/settings.py"},
		},
		{
			name:             "Trailing spaces on sensitive file",
			path:             "/server.key   ",
			expectedContains: []string{"/server.key"},
		},
		{
			name:             "Trailing dot on path segment",
			path:             "/sub./.env",
			expectedContains: []string{"/sub/.env"},
		},
		{
			name:             "Absolute URI in requestURI",
			path:             "/wp-config.php",
			requestURI:       "http://example.com/wp-config.php",
			expectedContains: []string{"/wp-config.php"},
		},
		{
			name:             "Absolute URI with Windows backslash",
			path:             `http://example.com\.env`,
			requestURI:       `http://example.com\.env`,
			expectedContains: []string{"/.env"},
		},
		{
			name:             "Multi-layer encoded rawPath",
			path:             "/public/test",
			rawPath:          "/%252e%252e/.env",
			requestURI:       "/public/test",
			expectedContains: []string{"/.env"},
		},
		{
			name:             "NTFS Alternate Data Stream combined with trailing dot",
			path:             "/database.sqlite::$DATA.",
			expectedContains: []string{"/database.sqlite"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidates := traefik_warden.ExtractCandidatePaths(tc.rawPath, tc.path, tc.requestURI)

			for _, expected := range tc.expectedContains {
				found := false
				for _, c := range candidates {
					if c == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected candidate %q to be in candidates %v", expected, candidates)
				}
			}
		})
	}
}

// TestPathNormalizer_EdgeCases covers edge cases P-1 through P-5 which are
// not exercised by the main table-driven test above.
func TestPathNormalizer_EdgeCases(t *testing.T) {
	// P-1: Repeated percent signs (%%%%2eenv) – should not panic; .env may or may not be extracted
	t.Run("P-1 repeated percent signs", func(t *testing.T) {
		candidates := traefik_warden.ExtractCandidatePaths("", "/%%%%2eenv", "")
		// Must not panic; result must be a non-empty slice of /‑prefixed strings.
		if len(candidates) == 0 {
			t.Fatal("expected at least one candidate for %%%%2eenv path")
		}
		for _, c := range candidates {
			if len(c) > 0 && c[0] != '/' {
				t.Errorf("candidate %q does not start with '/'", c)
			}
		}
	})

	// P-2: Exact "/" path
	t.Run("P-2 exact root path", func(t *testing.T) {
		candidates := traefik_warden.ExtractCandidatePaths("", "/", "")
		if len(candidates) == 0 {
			t.Fatal("expected at least one candidate for '/'")
		}
		found := false
		for _, c := range candidates {
			if c == "/" {
				found = true
			}
		}
		if !found {
			t.Errorf("expected '/' to be in candidates, got: %v", candidates)
		}
	})

	// P-3: Very long path (>16 KB) must not panic or OOM
	t.Run("P-3 very long path", func(t *testing.T) {
		longPath := "/" + string(make([]byte, 16*1024+1)) // 16 KB + 1
		for i := range longPath[1:] {
			longPath = longPath[:i+1] + "a" + longPath[i+2:]
		}
		candidates := traefik_warden.ExtractCandidatePaths("", longPath, "")
		if len(candidates) == 0 {
			t.Fatal("expected at least one candidate for very long path")
		}
	})

	// P-4: Unicode NFD path – normalizer must not panic; result must be well-formed
	t.Run("P-4 unicode NFC/NFD path", func(t *testing.T) {
		// "é" in NFD is e + combining acute accent (U+0301)
		nfdPath := "/caf\u00e9/menu"
		candidates := traefik_warden.ExtractCandidatePaths("", nfdPath, "")
		for _, c := range candidates {
			if len(c) > 0 && c[0] != '/' {
				t.Errorf("unicode candidate %q does not start with '/'", c)
			}
		}
	})

	// P-5: Path with embedded fragment (#anchor) – fragment must not pollute path candidates
	t.Run("P-5 embedded fragment", func(t *testing.T) {
		candidates := traefik_warden.ExtractCandidatePaths("", "/api/v1#admin", "/api/v1#admin")
		foundBase := false
		for _, c := range candidates {
			if len(c) > 0 && c[0] != '/' {
				t.Errorf("fragment candidate %q does not start with '/'", c)
			}
			if c == "/api/v1" {
				foundBase = true
			}
		}
		if !foundBase {
			t.Errorf("expected candidates to contain stripped base path '/api/v1', got %v", candidates)
		}
	})

	// P-6: Malformed percent-encoding (%zz or trailing %) with multi-layer traversal
	t.Run("P-6 lenient multi-layer percent decoding", func(t *testing.T) {
		candidates := traefik_warden.ExtractCandidatePaths("", "/%252e%252e/.env%zz", "/%252e%252e/.env%zz")
		foundEnv := false
		for _, c := range candidates {
			if c == "/.env%zz" {
				foundEnv = true
				break
			}
		}
		if !foundEnv {
			t.Errorf("expected candidates to contain '/.env%%zz', got %v", candidates)
		}
	})

	// P-7: Quadruple percent-encoded traversal (/%2525252e%2525252e/.env)
	t.Run("P-7 quadruple percent-encoded traversal", func(t *testing.T) {
		candidates := traefik_warden.ExtractCandidatePaths("", "/%2525252e%2525252e/.env", "/%2525252e%2525252e/.env")
		foundEnv := false
		for _, c := range candidates {
			if c == "/.env" {
				foundEnv = true
				break
			}
		}
		if !foundEnv {
			t.Errorf("expected candidates to contain '/.env' after 4 unescaping passes, got %v", candidates)
		}
	})

	// P-8: Absolute URI with multi-layer percent-encoded traversal and backslashes
	t.Run("P-8 absolute URI with multi-layer traversal", func(t *testing.T) {
		candidates := traefik_warden.ExtractCandidatePaths("", "http://example.com/%252e%252e/.env", "http://example.com/%252e%252e/.env")
		foundEnv := false
		for _, c := range candidates {
			if c == "/.env" {
				foundEnv = true
				break
			}
		}
		if !foundEnv {
			t.Errorf("expected candidates to contain '/.env' from absolute URI, got %v", candidates)
		}

		candidatesBackslash := traefik_warden.ExtractCandidatePaths("", "http://example.com\\admin\\.env", "http://example.com\\admin\\.env")
		foundAdminEnv := false
		for _, c := range candidatesBackslash {
			if c == "/admin/.env" {
				foundAdminEnv = true
				break
			}
		}
		if !foundAdminEnv {
			t.Errorf("expected candidates to contain '/admin/.env' from backslash absolute URI, got %v", candidatesBackslash)
		}
	})
}

// FuzzExtractCandidatePaths runs continuous fuzzing with randomized inputs to ensure
// path normalizer never panics or triggers index out of range on malformed or extreme inputs.
func FuzzExtractCandidatePaths(f *testing.F) {
	seeds := []string{
		"/",
		"/.env",
		"/%2e%2e/.env",
		"/static/%252e%252e/.env",
		"/;.env",
		"/app;jsessionid=123/.env",
		"/static\\..\\.env",
		"/.env\x00.png",
		"/search?file=.env",
		"/api/v1/users",
		"/phpinfo.php",
		"//server-status",
		"/..;/..;/.env",
		"/%20/.env",
		"/test/../../../etc/passwd",
	}

	for _, s := range seeds {
		f.Add(s, s, s)
	}

	f.Fuzz(func(t *testing.T, rawPath, pathStr, reqURI string) {
		// Execution must complete safely without panicking
		candidates := traefik_warden.ExtractCandidatePaths(rawPath, pathStr, reqURI)
		for _, c := range candidates {
			if len(c) > 0 && c[0] != '/' {
				t.Fatalf("expected candidate path to begin with '/', got %q", c)
			}
		}
	})
}


package traefik_warden

import (
	"net/url"
	"path"
	"strings"
)

func isHex(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

func lenientPathUnescape(s string) string {
	if u, err := url.PathUnescape(s); err == nil {
		return u
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			val := unhex(s[i+1])<<4 | unhex(s[i+2])
			b.WriteByte(val)
			i += 2
		} else {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func lenientQueryUnescape(s string) string {
	if u, err := url.QueryUnescape(s); err == nil {
		return u
	}
	s = strings.ReplaceAll(s, "+", " ")
	return lenientPathUnescape(s)
}

func stripSchemeAndAuthority(s string) (string, bool) {
	if idx := strings.Index(s, "://"); idx != -1 {
		rest := s[idx+3:]
		if slashIdx := strings.IndexAny(rest, "/\\"); slashIdx != -1 {
			return rest[slashIdx:], true
		}
		return "/", true
	}
	return s, false
}

// ExtractCandidatePaths normalizes and extracts all representations of a request URI path,
// neutralizing common evasion techniques like double encoding, backslash substitution,
// matrix parameters, and null bytes.
func ExtractCandidatePaths(rawPath, pathStr, requestURI string) []string {
	pathsToCheck := []string{path.Clean(pathStr)}

	// 1. Add RequestURI path before query and fragment to catch raw gateway discrepancies
	rawURIPath := requestURI
	if idx := strings.IndexByte(rawURIPath, '?'); idx != -1 {
		rawURIPath = rawURIPath[:idx]
	}
	if idx := strings.IndexByte(rawURIPath, '#'); idx != -1 {
		rawURIPath = rawURIPath[:idx]
	}
	if rawURIPath != "" {
		pathsToCheck = append(pathsToCheck, path.Clean(rawURIPath))
	}

	// 1a. Extract path from absolute URIs (e.g. http://example.com/path, http://example.com\path)
	initials := make([]string, 0, 8)
	for _, initial := range []string{pathStr, rawURIPath, rawPath} {
		if initial == "" {
			continue
		}
		initials = append(initials, initial)
		if extracted, ok := stripSchemeAndAuthority(initial); ok {
			initials = append(initials, extracted)
			pathsToCheck = append(pathsToCheck, path.Clean(extracted))
		}
	}

	// 2. Add RawPath if specified
	if rawPath != "" && rawPath != pathStr {
		pathsToCheck = append(pathsToCheck, path.Clean(rawPath))
	}

	// 3. Perform iterative unescaping to prevent multi-layer URL encoding evasion (e.g. %252e%252e)
	for _, initial := range initials {
		if initial == "" {
			continue
		}
		curPath := initial
		for i := 0; i < 5; i++ {
			unescaped := lenientPathUnescape(curPath)
			if unescaped == curPath {
				break
			}
			pathsToCheck = append(pathsToCheck, path.Clean(unescaped))
			if extracted, ok := stripSchemeAndAuthority(unescaped); ok {
				pathsToCheck = append(pathsToCheck, path.Clean(extracted))
			}
			curPath = unescaped
		}
	}

	// 4. Check backslash-converted paths (Windows / IIS style path traversal / separator evasion)
	for _, p := range append([]string{}, pathsToCheck...) {
		if strings.ContainsRune(p, '\\') {
			slashConverted := strings.ReplaceAll(p, "\\", "/")
			pathsToCheck = append(pathsToCheck, path.Clean(slashConverted))
		}
	}

	// 5. Semicolon matrix parameter handling (e.g. /;.env, /api;.env, /static;jsessionid=123/.env)
	for _, p := range append([]string{}, pathsToCheck...) {
		if strings.ContainsRune(p, ';') {
			parts := strings.Split(p, "/")
			cleanedSegments := make([]string, len(parts))
			for i, seg := range parts {
				if before, _, ok := strings.Cut(seg, ";"); ok {
					cleanedSegments[i] = before
				} else {
					cleanedSegments[i] = seg
				}
			}
			matrixStripped := strings.Join(cleanedSegments, "/")
			pathsToCheck = append(pathsToCheck, path.Clean(matrixStripped))

			semiAsSlash := strings.ReplaceAll(p, ";", "/")
			pathsToCheck = append(pathsToCheck, path.Clean(semiAsSlash))
		}
	}

	// 6. Strip and truncate null bytes (prevents C-string termination evasion on extension-anchored rules)
	for _, p := range append([]string{}, pathsToCheck...) {
		if strings.ContainsRune(p, '\x00') {
			if before, _, found := strings.Cut(p, "\x00"); found {
				pathsToCheck = append(pathsToCheck, path.Clean(before))
			}
			pathsToCheck = append(pathsToCheck, path.Clean(strings.ReplaceAll(p, "\x00", "")))
		}
	}

	// 7. Strip embedded URI query (?) and fragments (#) to prevent regex anchor evasion
	for _, p := range append([]string{}, pathsToCheck...) {
		cut := p
		hasDelim := false
		if before, _, ok := strings.Cut(cut, "?"); ok {
			cut = before
			hasDelim = true
		}
		if before, _, ok := strings.Cut(cut, "#"); ok {
			cut = before
			hasDelim = true
		}
		if hasDelim && cut != "" {
			pathsToCheck = append(pathsToCheck, path.Clean(cut))
		}
	}

	// 8. Strip Windows NTFS Alternate Data Streams (::$DATA) evasion
	for _, p := range append([]string{}, pathsToCheck...) {
		if strings.Contains(strings.ToLower(p), "::$data") {
			var b strings.Builder
			i := 0
			for {
				idx := strings.Index(strings.ToLower(p[i:]), "::$data")
				if idx == -1 {
					b.WriteString(p[i:])
					break
				}
				b.WriteString(p[i : i+idx])
				i += idx + len("::$data")
			}
			cleaned := path.Clean(b.String())
			if cleaned != "" {
				pathsToCheck = append(pathsToCheck, cleaned)
			}
		}
	}

	// 9. Strip trailing dots and spaces from path segments (Windows/IIS Win32 API evasion)
	for _, p := range append([]string{}, pathsToCheck...) {
		if strings.ContainsAny(p, ". \t\r\n") {
			parts := strings.Split(p, "/")
			modified := false
			for i, seg := range parts {
				if seg == "." || seg == ".." || seg == "" {
					continue
				}
				trimmed := strings.TrimRight(seg, ". \t\r\n")
				if trimmed != seg && trimmed != "" {
					parts[i] = trimmed
					modified = true
				}
			}
			if modified {
				pathsToCheck = append(pathsToCheck, path.Clean(strings.Join(parts, "/")))
			}
		}
	}

	// Deduplicate candidates and ensure canonical leading slash
	candidatePaths := make([]string, 0, len(pathsToCheck)*2)
	seen := make(map[string]struct{}, len(pathsToCheck)*2)
	for _, p := range pathsToCheck {
		if p == "" {
			continue
		}
		if extracted, ok := stripSchemeAndAuthority(p); ok {
			p = extracted
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		p = path.Clean(p)
		if strings.HasPrefix(p, "/http:/") || strings.HasPrefix(p, "/https:/") {
			if secondSlash := strings.Index(p[1:], "/"); secondSlash != -1 {
				rest := p[1+secondSlash+1:]
				if slashIdx := strings.IndexAny(rest, "/\\"); slashIdx != -1 {
					p = path.Clean(rest[slashIdx:])
				} else {
					p = "/"
				}
			}
		}
		if _, exists := seen[p]; !exists {
			seen[p] = struct{}{}
			candidatePaths = append(candidatePaths, p)
		}
		if p != "/" && !strings.HasSuffix(p, "/") {
			pSlash := p + "/"
			if _, exists := seen[pSlash]; !exists {
				seen[pSlash] = struct{}{}
				candidatePaths = append(candidatePaths, pSlash)
			}
		}
	}

	return candidatePaths
}

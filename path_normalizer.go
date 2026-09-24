package traefik_warden

import (
	"net/url"
	"path"
	"strings"
)

// ExtractCandidatePaths normalizes and extracts all representations of a request URI path,
// neutralizing common evasion techniques like double encoding, backslash substitution,
// matrix parameters, and null bytes.
func ExtractCandidatePaths(rawPath, pathStr, requestURI string) []string {
	pathsToCheck := []string{path.Clean(pathStr)}

	// 1. Add RequestURI path before query to catch raw gateway discrepancies
	rawURIPath := requestURI
	if idx := strings.IndexByte(rawURIPath, '?'); idx != -1 {
		rawURIPath = rawURIPath[:idx]
	}
	if rawURIPath != "" {
		pathsToCheck = append(pathsToCheck, path.Clean(rawURIPath))
	}

	// 2. Add RawPath if specified
	if rawPath != "" && rawPath != pathStr {
		pathsToCheck = append(pathsToCheck, path.Clean(rawPath))
	}

	// 3. Perform iterative unescaping to prevent multi-layer URL encoding evasion (e.g. %252e%252e)
	for _, initial := range []string{pathStr, rawURIPath} {
		curPath := initial
		for i := 0; i < 3; i++ {
			unescaped, err := url.PathUnescape(curPath)
			if err != nil || unescaped == curPath {
				break
			}
			pathsToCheck = append(pathsToCheck, path.Clean(unescaped))
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
			paramSegments := make([]string, 0)
			for i, seg := range parts {
				if semiIdx := strings.IndexByte(seg, ';'); semiIdx != -1 {
					cleanedSegments[i] = seg[:semiIdx]
					paramSegments = append(paramSegments, seg[semiIdx+1:])
				} else {
					cleanedSegments[i] = seg
				}
			}
			matrixStripped := strings.Join(cleanedSegments, "/")
			pathsToCheck = append(pathsToCheck, path.Clean(matrixStripped))

			for _, param := range paramSegments {
				if param != "" {
					pathsToCheck = append(pathsToCheck, "/"+param, path.Clean("/"+param))
				}
			}

			semiAsSlash := strings.ReplaceAll(p, ";", "/")
			pathsToCheck = append(pathsToCheck, path.Clean(semiAsSlash))
		}
	}

	// 6. Strip null bytes
	for _, p := range append([]string{}, pathsToCheck...) {
		if strings.ContainsRune(p, '\x00') {
			pathsToCheck = append(pathsToCheck, path.Clean(strings.ReplaceAll(p, "\x00", "")))
		}
	}

	// Deduplicate candidates and ensure canonical leading slash
	candidatePaths := make([]string, 0, len(pathsToCheck))
	seen := make(map[string]struct{}, len(pathsToCheck))
	for _, p := range pathsToCheck {
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		p = path.Clean(p)
		if _, exists := seen[p]; !exists {
			seen[p] = struct{}{}
			candidatePaths = append(candidatePaths, p)
		}
	}

	return candidatePaths
}

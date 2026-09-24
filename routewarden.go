package traefik_warden

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// RouteWarden is the Traefik middleware plugin handler.
type RouteWarden struct {
	next            http.Handler
	name            string
	enabled         bool
	debug           bool
	securityLog     bool
	methods         map[string]struct{}
	blockRegexes    []*regexp.Regexp
	allowRegexes    []*regexp.Regexp
	ipFilter        *IPFilter
	checkQuery      bool
	checkHeaders    []string
	responseHandler *ResponseHandler
}

// New creates a new RouteWarden plugin handler.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		config = CreateConfig()
	}

	methodsMap := make(map[string]struct{})
	if len(config.Methods) == 0 {
		methodsMap["GET"] = struct{}{}
	} else {
		for _, m := range config.Methods {
			m = strings.ToUpper(strings.TrimSpace(m))
			if m != "" {
				methodsMap[m] = struct{}{}
			}
		}
		if len(methodsMap) == 0 {
			methodsMap["GET"] = struct{}{}
		}
	}

	var blockPatterns []string
	if config.EnableDefaultPatterns {
		blockPatterns = append(blockPatterns, DefaultBlockPatterns...)
	}
	blockPatterns = append(blockPatterns, config.PathPatterns...)
	blockPatterns = append(blockPatterns, config.BlockPatterns...)

	compiledBlockRegexes := make([]*regexp.Regexp, 0, len(blockPatterns))
	for _, p := range blockPatterns {
		if strings.TrimSpace(p) == "" {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("routewarden [%s]: invalid block regex pattern %q: %w", name, p, err)
		}
		compiledBlockRegexes = append(compiledBlockRegexes, re)
	}

	var allowPatterns []string
	if config.EnableDefaultAllowPatterns {
		allowPatterns = append(allowPatterns, DefaultAllowPatterns...)
	}
	allowPatterns = append(allowPatterns, config.AllowPatterns...)

	compiledAllowRegexes := make([]*regexp.Regexp, 0, len(allowPatterns))
	for _, p := range allowPatterns {
		if strings.TrimSpace(p) == "" {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("routewarden [%s]: invalid allow regex pattern %q: %w", name, p, err)
		}
		compiledAllowRegexes = append(compiledAllowRegexes, re)
	}

	ipFilter, err := NewIPFilter(config.AllowedIPs)
	if err != nil {
		return nil, fmt.Errorf("routewarden [%s]: %w", name, err)
	}

	respConfig := config.Response
	if respConfig == nil {
		respConfig = &ResponseConfig{Mode: "text"}
	}
	if strings.TrimSpace(config.Mode) != "" {
		respConfig.Mode = strings.TrimSpace(config.Mode)
	} else if strings.TrimSpace(config.Action) != "" {
		respConfig.Mode = strings.TrimSpace(config.Action)
	}

	isSilentDrop := strings.EqualFold(respConfig.Mode, "silentdrop") || strings.EqualFold(respConfig.Mode, "silent_drop") || strings.EqualFold(respConfig.Mode, "drop")
	respHandler, err := NewResponseHandler(respConfig, config.StatusCode, config.CustomResponseText, isSilentDrop)
	if err != nil {
		return nil, fmt.Errorf("routewarden [%s]: %w", name, err)
	}

	cleanedHeaders := make([]string, 0, len(config.CheckHeaders))
	for _, h := range config.CheckHeaders {
		h = strings.TrimSpace(h)
		if h != "" {
			cleanedHeaders = append(cleanedHeaders, h)
		}
	}

	rw := &RouteWarden{
		next:            next,
		name:            name,
		enabled:         config.Enabled,
		debug:           config.Debug,
		securityLog:     config.SecurityLog,
		methods:         methodsMap,
		blockRegexes:    compiledBlockRegexes,
		allowRegexes:    compiledAllowRegexes,
		ipFilter:        ipFilter,
		checkQuery:      config.CheckQuery,
		checkHeaders:    cleanedHeaders,
		responseHandler: respHandler,
	}

	rw.logDebug("initialized (enabled=%t, debug=%t, securityLog=%t, blockPatterns=%d, allowPatterns=%d, allowedIPs=%d, mode=%s)",
		rw.enabled, rw.debug, rw.securityLog, len(rw.blockRegexes), len(rw.allowRegexes), len(config.AllowedIPs), rw.responseHandler.config.Mode)

	return rw, nil
}

func (rw *RouteWarden) logDebug(format string, v ...interface{}) {
	if rw.debug {
		msg := fmt.Sprintf(format, v...)
		fmt.Fprintf(os.Stdout, "[DEBUG] routewarden [%s]: %s\n", rw.name, msg)
	}
}

// logSecurityEvent emits structured JSON security audit events (compatible with CrowdSec, SIEM, fail2ban).
func (rw *RouteWarden) logSecurityEvent(req *http.Request, matchedTarget string, pattern string, reason string) {
	if !rw.securityLog {
		return
	}
	clientIP := ExtractClientIP(req)
	mode := "text"
	if rw.responseHandler != nil {
		if rw.responseHandler.silentDrop {
			mode = "silentDrop"
		} else if rw.responseHandler.config != nil && rw.responseHandler.config.Mode != "" {
			mode = rw.responseHandler.config.Mode
		}
	}

	event := map[string]interface{}{
		"type":        "routewarden_block",
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"plugin":      rw.name,
		"client_ip":   clientIP,
		"method":      req.Method,
		"path":        matchedTarget,
		"request_uri": req.RequestURI,
		"pattern":     pattern,
		"action":      mode,
		"reason":      reason,
		"user_agent":  req.UserAgent(),
	}

	data, err := json.Marshal(event)
	if err == nil {
		fmt.Fprintf(os.Stdout, "%s\n", string(data))
	}
}

func (rw *RouteWarden) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if !rw.enabled {
		rw.next.ServeHTTP(w, req)
		return
	}

	// Only inspect requests whose HTTP method matches configured verbs (default: GET)
	if _, matchesMethod := rw.methods[strings.ToUpper(req.Method)]; !matchesMethod {
		rw.logDebug("method %s not in inspected methods, bypassing", req.Method)
		rw.next.ServeHTTP(w, req)
		return
	}

	// Exempt whitelisted client IPs or CIDR subnets from blocking
	if rw.ipFilter.IsAllowed(req) {
		rw.logDebug("client IP %s is whitelisted, allowing request", req.RemoteAddr)
		rw.next.ServeHTTP(w, req)
		return
	}

	// Canonicalize and inspect paths with anti-evasion protections
	candidatePaths := ExtractCandidatePaths(req.URL.RawPath, req.URL.Path, req.RequestURI)
	rw.logDebug("inspecting request %s %s with %d candidate paths: %v", req.Method, req.URL.Path, len(candidatePaths), candidatePaths)

	// 1. Check AllowPatterns first (Allowlist override)
	for _, p := range candidatePaths {
		if re := rw.findMatchingAllow(p); re != nil {
			rw.logDebug("path %q allowed by pattern %q", p, re.String())
			rw.next.ServeHTTP(w, req)
			return
		}
	}

	// 2. Check BlockPatterns against URL paths
	for _, p := range candidatePaths {
		if re := rw.findMatchingBlock(p); re != nil {
			rw.logDebug("path %q blocked by pattern %q (mode: %s)", p, re.String(), rw.responseHandler.config.Mode)
			rw.logSecurityEvent(req, p, re.String(), "path_blocked")
			rw.responseHandler.ServeBlockedRequest(w, req)
			return
		}
	}

	// 3. Optional: Check Query String if enabled
	if rw.checkQuery && req.URL.RawQuery != "" {
		unescapedQuery, err := url.QueryUnescape(req.URL.RawQuery)
		if err != nil {
			unescapedQuery = req.URL.RawQuery
		}

		if re := rw.findMatchingBlock(unescapedQuery); re != nil {
			rw.logDebug("unescaped query %q blocked by pattern %q", unescapedQuery, re.String())
			rw.logSecurityEvent(req, unescapedQuery, re.String(), "query_blocked")
			rw.responseHandler.ServeBlockedRequest(w, req)
			return
		}
		if re := rw.findMatchingBlock(req.URL.RawQuery); re != nil {
			rw.logDebug("raw query %q blocked by pattern %q", req.URL.RawQuery, re.String())
			rw.logSecurityEvent(req, req.URL.RawQuery, re.String(), "query_blocked")
			rw.responseHandler.ServeBlockedRequest(w, req)
			return
		}

		queryParams := req.URL.Query()
		for key, values := range queryParams {
			keyCandidates := append([]string{key}, ExtractCandidatePaths("", key, key)...)
			for _, kc := range keyCandidates {
				if re := rw.findMatchingBlock(kc); re != nil {
					rw.logDebug("query param key %q blocked by pattern %q", key, re.String())
					rw.logSecurityEvent(req, key, re.String(), "query_param_blocked")
					rw.responseHandler.ServeBlockedRequest(w, req)
					return
				}
			}
			for _, val := range values {
				valCandidates := append([]string{val}, ExtractCandidatePaths("", val, val)...)
				for _, vc := range valCandidates {
					if re := rw.findMatchingBlock(vc); re != nil {
						rw.logDebug("query param %q with value %q blocked by pattern %q", key, val, re.String())
						rw.logSecurityEvent(req, val, re.String(), "query_param_blocked")
						rw.responseHandler.ServeBlockedRequest(w, req)
						return
					}
				}
			}
		}
	}

	// 4. Optional: Check specified forwarded/rewrite headers for path evasion & sensitive endpoints
	if len(rw.checkHeaders) > 0 {
		for _, headerName := range rw.checkHeaders {
			headerVal := strings.TrimSpace(req.Header.Get(headerName))
			if headerVal == "" {
				continue
			}
			headerCandidates := ExtractCandidatePaths("", headerVal, headerVal)
			for _, hc := range headerCandidates {
				if re := rw.findMatchingBlock(hc); re != nil {
					rw.logDebug("header %q with value %q blocked by pattern %q", headerName, headerVal, re.String())
					rw.logSecurityEvent(req, headerVal, re.String(), "header_blocked")
					rw.responseHandler.ServeBlockedRequest(w, req)
					return
				}
			}
		}
	}

	rw.logDebug("request %s %s passed inspection", req.Method, req.URL.Path)
	rw.next.ServeHTTP(w, req)
}

func (rw *RouteWarden) findMatchingAllow(target string) *regexp.Regexp {
	for _, re := range rw.allowRegexes {
		if re.MatchString(target) {
			return re
		}
	}
	return nil
}

func (rw *RouteWarden) findMatchingBlock(target string) *regexp.Regexp {
	for _, re := range rw.blockRegexes {
		if re.MatchString(target) {
			return re
		}
	}
	return nil
}

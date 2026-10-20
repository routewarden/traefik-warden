package traefik_warden

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// RouteWarden is the Traefik middleware plugin handler.
type RouteWarden struct {
	next              http.Handler
	name              string
	enabled           bool
	debug             bool
	securityLog       bool
	methods           map[string]struct{}
	blockRegexes      []*regexp.Regexp
	allowRegexes      []*regexp.Regexp
	bodyRegexes       []*regexp.Regexp
	ipFilter          *IPFilter
	checkQuery        bool
	checkHeaders      []string
	checkBody         bool
	checkBodyMaxBytes int64
	responseHandler   *ResponseHandler
}

// New creates a new RouteWarden plugin handler.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		config = CreateConfig()
	}

	// If a configFile path is set, load it as the base and merge inline values on top.
	if config.ConfigFile != "" {
		fileData, err := os.ReadFile(config.ConfigFile)
		if err != nil {
			return nil, fmt.Errorf("routewarden [%s]: cannot read configFile %q: %w", name, config.ConfigFile, err)
		}

		type sharedResponseConfig struct {
			Mode                          *string           `json:"mode"`
			StatusCode                    *int              `json:"statusCode"`
			StatusCodeSnake               *int              `json:"status_code"`
			ContentType                   *string           `json:"contentType"`
			ContentTypeSnake              *string           `json:"content_type"`
			Body                          *string           `json:"body"`
			Headers                       map[string]string `json:"headers"`
			RedirectURL                   *string           `json:"redirectUrl"`
			RedirectURLSnake              *string           `json:"redirect_url"`
			ProxyURL                      *string           `json:"proxyUrl"`
			ProxyURLSnake                 *string           `json:"proxy_url"`
			Captcha                       *CaptchaConfig    `json:"captcha"`
			GzipBombMB                    *float64          `json:"gzipBombMB"`
			GzipBombMBSnake               *float64          `json:"gzip_bomb_mb"`
			RetryAfterSeconds             *int              `json:"retryAfterSeconds"`
			RetryAfterSecondsSnake        *int              `json:"retry_after_seconds"`
			TarpitDelayMs                 *int              `json:"tarpitDelayMs"`
			TarpitDelayMsSnake            *int              `json:"tarpit_delay_ms"`
			TarpitMaxDurationSeconds      *int              `json:"tarpitMaxDurationSeconds"`
			TarpitMaxDurationSecondsSnake *int              `json:"tarpit_max_duration_seconds"`
			StreamSizeMB                  *int              `json:"streamSizeMB"`
			StreamSizeMBSnake             *int              `json:"stream_size_mb"`
		}

		type sharedConfigFile struct {
			Enabled                         *bool                 `json:"enabled"`
			EnableDefaultPatterns           *bool                 `json:"enableDefaultPatterns"`
			EnableDefaultPatternsSnake      *bool                 `json:"enable_default_patterns"`
			EnableDefaultAllowPatterns      *bool                 `json:"enableDefaultAllowPatterns"`
			EnableDefaultAllowPatternsSnake *bool                 `json:"enable_default_allow_patterns"`
			BlockPatterns                   []string              `json:"blockPatterns"`
			BlockPatternsSnake              []string              `json:"block_patterns"`
			AllowPatterns                   []string              `json:"allowPatterns"`
			AllowPatternsSnake              []string              `json:"allow_patterns"`
			AllowedIPs                      []string              `json:"allowedIps"`
			AllowedIPsSnake                 []string              `json:"allowed_ips"`
			TrustedProxies                  []string              `json:"trustedProxies"`
			TrustedProxiesSnake             []string              `json:"trusted_proxies"`
			Methods                         []string              `json:"methods"`
			CheckQuery                      *bool                 `json:"checkQuery"`
			CheckQuerySnake                 *bool                 `json:"check_query"`
			CheckHeaders                    []string              `json:"checkHeaders"`
			CheckHeadersSnake               []string              `json:"check_headers"`
			CheckBody                       *bool                 `json:"checkBody"`
			CheckBodySnake                  *bool                 `json:"check_body"`
			CheckBodyMaxBytes               *int64                `json:"checkBodyMaxBytes"`
			CheckBodyMaxBytesSnake          *int64                `json:"check_body_max_bytes"`
			CheckBodyPatterns               []string              `json:"checkBodyPatterns"`
			CheckBodyPatternsSnake          []string              `json:"check_body_patterns"`
			StatusCode                      *int                  `json:"statusCode"`
			StatusCodeSnake                 *int                  `json:"status_code"`
			CustomResponseText              *string               `json:"customResponseText"`
			CustomResponseTextSnake         *string               `json:"custom_response_text"`
			Mode                            *string               `json:"mode"`
			Debug                           *bool                 `json:"debug"`
			SecurityLog                     *bool                 `json:"securityLog"`
			SecurityLogSnake                *bool                 `json:"security_log"`
			Response                        *sharedResponseConfig `json:"response"`
		}

		var scf sharedConfigFile
		if err := json.Unmarshal(fileData, &scf); err != nil {
			return nil, fmt.Errorf("routewarden [%s]: cannot parse configFile %q: %w", name, config.ConfigFile, err)
		}

		// Start from a fresh default so every file field is honoured.
		fileCfg := CreateConfig()
		if scf.Enabled != nil {
			fileCfg.Enabled = *scf.Enabled
		}
		if scf.EnableDefaultPatterns != nil {
			fileCfg.EnableDefaultPatterns = *scf.EnableDefaultPatterns
		} else if scf.EnableDefaultPatternsSnake != nil {
			fileCfg.EnableDefaultPatterns = *scf.EnableDefaultPatternsSnake
		}
		if scf.EnableDefaultAllowPatterns != nil {
			fileCfg.EnableDefaultAllowPatterns = *scf.EnableDefaultAllowPatterns
		} else if scf.EnableDefaultAllowPatternsSnake != nil {
			fileCfg.EnableDefaultAllowPatterns = *scf.EnableDefaultAllowPatternsSnake
		}
		if len(scf.BlockPatterns) > 0 {
			fileCfg.BlockPatterns = scf.BlockPatterns
		} else if len(scf.BlockPatternsSnake) > 0 {
			fileCfg.BlockPatterns = scf.BlockPatternsSnake
		}
		if len(scf.AllowPatterns) > 0 {
			fileCfg.AllowPatterns = scf.AllowPatterns
		} else if len(scf.AllowPatternsSnake) > 0 {
			fileCfg.AllowPatterns = scf.AllowPatternsSnake
		}
		if len(scf.AllowedIPs) > 0 {
			fileCfg.AllowedIPs = scf.AllowedIPs
		} else if len(scf.AllowedIPsSnake) > 0 {
			fileCfg.AllowedIPs = scf.AllowedIPsSnake
		}
		if len(scf.TrustedProxies) > 0 {
			fileCfg.TrustedProxies = scf.TrustedProxies
		} else if len(scf.TrustedProxiesSnake) > 0 {
			fileCfg.TrustedProxies = scf.TrustedProxiesSnake
		}
		if len(scf.Methods) > 0 {
			fileCfg.Methods = scf.Methods
		}
		if scf.CheckQuery != nil {
			fileCfg.CheckQuery = *scf.CheckQuery
		} else if scf.CheckQuerySnake != nil {
			fileCfg.CheckQuery = *scf.CheckQuerySnake
		}
		if len(scf.CheckHeaders) > 0 {
			fileCfg.CheckHeaders = scf.CheckHeaders
		} else if len(scf.CheckHeadersSnake) > 0 {
			fileCfg.CheckHeaders = scf.CheckHeadersSnake
		}
		if scf.CheckBody != nil {
			fileCfg.CheckBody = *scf.CheckBody
		} else if scf.CheckBodySnake != nil {
			fileCfg.CheckBody = *scf.CheckBodySnake
		}
		if scf.CheckBodyMaxBytes != nil {
			fileCfg.CheckBodyMaxBytes = *scf.CheckBodyMaxBytes
		} else if scf.CheckBodyMaxBytesSnake != nil {
			fileCfg.CheckBodyMaxBytes = *scf.CheckBodyMaxBytesSnake
		}
		if len(scf.CheckBodyPatterns) > 0 {
			fileCfg.CheckBodyPatterns = scf.CheckBodyPatterns
		} else if len(scf.CheckBodyPatternsSnake) > 0 {
			fileCfg.CheckBodyPatterns = scf.CheckBodyPatternsSnake
		}
		if scf.StatusCode != nil {
			fileCfg.StatusCode = *scf.StatusCode
		} else if scf.StatusCodeSnake != nil {
			fileCfg.StatusCode = *scf.StatusCodeSnake
		}
		if scf.CustomResponseText != nil {
			fileCfg.CustomResponseText = *scf.CustomResponseText
		} else if scf.CustomResponseTextSnake != nil {
			fileCfg.CustomResponseText = *scf.CustomResponseTextSnake
		}
		if scf.Mode != nil {
			fileCfg.Mode = *scf.Mode
		}
		if scf.Debug != nil {
			fileCfg.Debug = *scf.Debug
		}
		if scf.SecurityLog != nil {
			fileCfg.SecurityLog = *scf.SecurityLog
		} else if scf.SecurityLogSnake != nil {
			fileCfg.SecurityLog = *scf.SecurityLogSnake
		}
		if scf.Response != nil {
			if fileCfg.Response == nil {
				fileCfg.Response = &ResponseConfig{Mode: "text"}
			}
			if scf.Response.Mode != nil {
				fileCfg.Response.Mode = *scf.Response.Mode
			}
			if scf.Response.StatusCode != nil {
				fileCfg.Response.StatusCode = *scf.Response.StatusCode
			} else if scf.Response.StatusCodeSnake != nil {
				fileCfg.Response.StatusCode = *scf.Response.StatusCodeSnake
			}
			if scf.Response.ContentType != nil {
				fileCfg.Response.ContentType = *scf.Response.ContentType
			} else if scf.Response.ContentTypeSnake != nil {
				fileCfg.Response.ContentType = *scf.Response.ContentTypeSnake
			}
			if scf.Response.Body != nil {
				fileCfg.Response.Body = *scf.Response.Body
			}
			if scf.Response.Headers != nil {
				fileCfg.Response.Headers = scf.Response.Headers
			}
			if scf.Response.RedirectURL != nil {
				fileCfg.Response.RedirectURL = *scf.Response.RedirectURL
			} else if scf.Response.RedirectURLSnake != nil {
				fileCfg.Response.RedirectURL = *scf.Response.RedirectURLSnake
			}
			if scf.Response.ProxyURL != nil {
				fileCfg.Response.ProxyURL = *scf.Response.ProxyURL
			} else if scf.Response.ProxyURLSnake != nil {
				fileCfg.Response.ProxyURL = *scf.Response.ProxyURLSnake
			}
			if scf.Response.Captcha != nil {
				fileCfg.Response.Captcha = scf.Response.Captcha
			}
			if scf.Response.GzipBombMB != nil {
				fileCfg.Response.GzipBombMB = *scf.Response.GzipBombMB
			} else if scf.Response.GzipBombMBSnake != nil {
				fileCfg.Response.GzipBombMB = *scf.Response.GzipBombMBSnake
			}
			if scf.Response.RetryAfterSeconds != nil {
				fileCfg.Response.RetryAfterSeconds = *scf.Response.RetryAfterSeconds
			} else if scf.Response.RetryAfterSecondsSnake != nil {
				fileCfg.Response.RetryAfterSeconds = *scf.Response.RetryAfterSecondsSnake
			}
			if scf.Response.TarpitDelayMs != nil {
				fileCfg.Response.TarpitDelayMs = *scf.Response.TarpitDelayMs
			} else if scf.Response.TarpitDelayMsSnake != nil {
				fileCfg.Response.TarpitDelayMs = *scf.Response.TarpitDelayMsSnake
			}
			if scf.Response.TarpitMaxDurationSeconds != nil {
				fileCfg.Response.TarpitMaxDurationSeconds = *scf.Response.TarpitMaxDurationSeconds
			} else if scf.Response.TarpitMaxDurationSecondsSnake != nil {
				fileCfg.Response.TarpitMaxDurationSeconds = *scf.Response.TarpitMaxDurationSecondsSnake
			}
			if scf.Response.StreamSizeMB != nil {
				fileCfg.Response.StreamSizeMB = *scf.Response.StreamSizeMB
			} else if scf.Response.StreamSizeMBSnake != nil {
				fileCfg.Response.StreamSizeMB = *scf.Response.StreamSizeMBSnake
			}
		}

		// Apply explicit inline overrides (only where the caller explicitly modified values from CreateConfig)
		defaultCfg := CreateConfig()
		if config.Enabled != defaultCfg.Enabled {
			fileCfg.Enabled = config.Enabled
		}
		if config.EnableDefaultPatterns != defaultCfg.EnableDefaultPatterns {
			fileCfg.EnableDefaultPatterns = config.EnableDefaultPatterns
		}
		if config.EnableDefaultAllowPatterns != defaultCfg.EnableDefaultAllowPatterns {
			fileCfg.EnableDefaultAllowPatterns = config.EnableDefaultAllowPatterns
		}
		if len(config.BlockPatterns) > 0 {
			fileCfg.BlockPatterns = config.BlockPatterns
		}
		if len(config.AllowPatterns) > 0 {
			fileCfg.AllowPatterns = config.AllowPatterns
		}
		if len(config.AllowedIPs) > 0 {
			fileCfg.AllowedIPs = config.AllowedIPs
		}
		if len(config.TrustedProxies) > 0 {
			fileCfg.TrustedProxies = config.TrustedProxies
		}
		if len(config.Methods) > 0 && (len(config.Methods) != 1 || config.Methods[0] != "GET") {
			fileCfg.Methods = config.Methods
		}
		if config.StatusCode != defaultCfg.StatusCode && config.StatusCode != 0 {
			fileCfg.StatusCode = config.StatusCode
		}
		if config.CustomResponseText != defaultCfg.CustomResponseText && config.CustomResponseText != "" {
			fileCfg.CustomResponseText = config.CustomResponseText
		}
		if config.Mode != "" {
			fileCfg.Mode = config.Mode
			if fileCfg.Response != nil {
				fileCfg.Response.Mode = config.Mode
			}
		}
		if config.CheckQuery != defaultCfg.CheckQuery {
			fileCfg.CheckQuery = config.CheckQuery
		}
		if len(config.CheckHeaders) > 0 {
			fileCfg.CheckHeaders = config.CheckHeaders
		}
		if config.CheckBody != defaultCfg.CheckBody {
			fileCfg.CheckBody = config.CheckBody
		}
		if config.CheckBodyMaxBytes > 0 && config.CheckBodyMaxBytes != 65536 {
			fileCfg.CheckBodyMaxBytes = config.CheckBodyMaxBytes
		}
		if len(config.CheckBodyPatterns) > 0 {
			fileCfg.CheckBodyPatterns = config.CheckBodyPatterns
		}
		if config.Debug != defaultCfg.Debug {
			fileCfg.Debug = config.Debug
		}
		if config.SecurityLog != defaultCfg.SecurityLog {
			fileCfg.SecurityLog = config.SecurityLog
		}
		if config.Response != nil {
			if fileCfg.Response == nil {
				fileCfg.Response = config.Response
			} else {
				if config.Response.Mode != "" && config.Response.Mode != "text" {
					fileCfg.Response.Mode = config.Response.Mode
				}
				if config.Response.StatusCode != 0 {
					fileCfg.Response.StatusCode = config.Response.StatusCode
				}
				if config.Response.Body != "" {
					fileCfg.Response.Body = config.Response.Body
				}
				if config.Response.ContentType != "" {
					fileCfg.Response.ContentType = config.Response.ContentType
				}
				if len(config.Response.Headers) > 0 {
					fileCfg.Response.Headers = config.Response.Headers
				}
				if config.Response.RedirectURL != "" {
					fileCfg.Response.RedirectURL = config.Response.RedirectURL
				}
				if config.Response.ProxyURL != "" {
					fileCfg.Response.ProxyURL = config.Response.ProxyURL
				}
				if config.Response.Captcha != nil {
					fileCfg.Response.Captcha = config.Response.Captcha
				}
				if config.Response.GzipBombMB > 0 {
					fileCfg.Response.GzipBombMB = config.Response.GzipBombMB
				}
				if config.Response.RetryAfterSeconds > 0 {
					fileCfg.Response.RetryAfterSeconds = config.Response.RetryAfterSeconds
				}
				if config.Response.TarpitDelayMs > 0 {
					fileCfg.Response.TarpitDelayMs = config.Response.TarpitDelayMs
				}
				if config.Response.TarpitMaxDurationSeconds > 0 {
					fileCfg.Response.TarpitMaxDurationSeconds = config.Response.TarpitMaxDurationSeconds
				}
				if config.Response.StreamSizeMB > 0 {
					fileCfg.Response.StreamSizeMB = config.Response.StreamSizeMB
				}
			}
		}

		// Keep configFile path so callers can inspect it, but continue with merged config.
		fileCfg.ConfigFile = config.ConfigFile
		config = fileCfg
	}

	methodsMap := make(map[string]struct{})
	if len(config.Methods) == 0 {
		methodsMap["GET"] = struct{}{}
		if config.CheckBody || len(config.CheckBodyPatterns) > 0 {
			methodsMap["POST"] = struct{}{}
			methodsMap["PUT"] = struct{}{}
			methodsMap["PATCH"] = struct{}{}
		}
	} else if len(config.Methods) == 1 && strings.EqualFold(config.Methods[0], "GET") && (config.CheckBody || len(config.CheckBodyPatterns) > 0) {
		methodsMap["GET"] = struct{}{}
		methodsMap["POST"] = struct{}{}
		methodsMap["PUT"] = struct{}{}
		methodsMap["PATCH"] = struct{}{}
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

	ipFilter, err := NewIPFilter(config.AllowedIPs, config.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("routewarden [%s]: %w", name, err)
	}

	respConfig := config.Response
	if respConfig == nil {
		respConfig = &ResponseConfig{Mode: "text"}
	}
	if strings.TrimSpace(config.Mode) != "" {
		respConfig.Mode = strings.TrimSpace(config.Mode)
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

	compiledBodyRegexes := make([]*regexp.Regexp, 0, len(config.CheckBodyPatterns))
	for _, p := range config.CheckBodyPatterns {
		if strings.TrimSpace(p) == "" {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("routewarden [%s]: invalid check body regex pattern %q: %w", name, p, err)
		}
		compiledBodyRegexes = append(compiledBodyRegexes, re)
	}

	bodyMaxBytes := config.CheckBodyMaxBytes
	if bodyMaxBytes <= 0 {
		bodyMaxBytes = 64 * 1024
	}

	rw := &RouteWarden{
		next:              next,
		name:              name,
		enabled:           config.Enabled,
		debug:             config.Debug,
		securityLog:       config.SecurityLog,
		methods:           methodsMap,
		blockRegexes:      compiledBlockRegexes,
		allowRegexes:      compiledAllowRegexes,
		bodyRegexes:       compiledBodyRegexes,
		ipFilter:          ipFilter,
		checkQuery:        config.CheckQuery,
		checkHeaders:      cleanedHeaders,
		checkBody:         config.CheckBody || len(compiledBodyRegexes) > 0,
		checkBodyMaxBytes: bodyMaxBytes,
		responseHandler:   respHandler,
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

func (rw *RouteWarden) extractClientIP(req *http.Request) string {
	if rw.ipFilter != nil {
		return rw.ipFilter.ExtractClientIP(req)
	}
	return ExtractClientIP(req)
}

// logSecurityEvent emits structured JSON security audit events (compatible with CrowdSec, SIEM, fail2ban).
func (rw *RouteWarden) logSecurityEvent(req *http.Request, matchedTarget string, pattern string, reason string) {
	if !rw.securityLog {
		return
	}
	clientIP := rw.extractClientIP(req)
	mode := "text"
	statusCode := http.StatusForbidden
	if rw.responseHandler != nil {
		if rw.responseHandler.silentDrop {
			mode = "silentDrop"
			statusCode = 0
		} else if rw.responseHandler.config != nil {
			if rw.responseHandler.config.Mode != "" {
				mode = rw.responseHandler.config.Mode
			}
			if rw.responseHandler.config.StatusCode != 0 {
				statusCode = rw.responseHandler.config.StatusCode
			}
		}
	}

	event := map[string]interface{}{
		"type":            "routewarden_block",
		"timestamp":       time.Now().UTC().Format(time.RFC3339),
		"level":           "warn",
		"plugin":          rw.name,
		"client_ip":       clientIP,
		"method":          req.Method,
		"path":            matchedTarget,
		"request_uri":     req.RequestURI,
		"pattern":         pattern,
		"matched_pattern": pattern,
		"action":          mode,
		"status_code":     statusCode,
		"reason":          reason,
		"user_agent":      req.UserAgent(),
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
	_, hasWildcard := rw.methods["*"]
	_, hasAll := rw.methods["ALL"]
	_, matchesMethod := rw.methods[strings.ToUpper(req.Method)]
	if !hasWildcard && !hasAll && !matchesMethod {
		rw.logDebug("method %s not in inspected methods, bypassing", req.Method)
		rw.next.ServeHTTP(w, req)
		return
	}

	// Exempt whitelisted client IPs or CIDR subnets from blocking
	if rw.ipFilter.IsAllowed(req) {
		rw.logDebug("client IP %s is whitelisted, allowing request", rw.extractClientIP(req))
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
			// Bug 1 fix: cap the slice after append to prevent backing-array aliasing when
			// ExtractCandidatePaths returns zero elements (shared single-element array).
			keyCandidates := append([]string{key}, ExtractCandidatePaths("", key, key)...)
			keyCandidates = keyCandidates[:len(keyCandidates):len(keyCandidates)]
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
				valCandidates = valCandidates[:len(valCandidates):len(valCandidates)]
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
			headerCandidates := append([]string{headerVal}, ExtractCandidatePaths("", headerVal, headerVal)...)
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

	// 5. Optional: Check Request Body if enabled
	if rw.checkBody && req.Body != nil {
		maxBytes := rw.checkBodyMaxBytes
		if maxBytes <= 0 {
			maxBytes = 64 * 1024
		}

		origBody := req.Body
		bodyBytes, err := io.ReadAll(io.LimitReader(origBody, maxBytes))
		if err == nil && len(bodyBytes) > 0 {
			req.Body = &bodyReadCloser{
				Reader: io.MultiReader(bytes.NewReader(bodyBytes), origBody),
				Closer: origBody,
			}

			bodyStr := string(bodyBytes)
			unescapedBody, unerr := url.QueryUnescape(bodyStr)
			if unerr != nil {
				unescapedBody = bodyStr
			}

			bodyCandidates := []string{bodyStr, unescapedBody}
			patternsToCheck := rw.bodyRegexes
			if len(patternsToCheck) == 0 {
				patternsToCheck = rw.blockRegexes
			}

			for _, bc := range bodyCandidates {
				for _, re := range patternsToCheck {
					if re.MatchString(bc) {
						rw.logDebug("body payload blocked by pattern %q", re.String())
						rw.logSecurityEvent(req, "[body payload]", re.String(), "body_blocked")
						rw.responseHandler.ServeBlockedRequest(w, req)
						return
					}
				}
			}
		} else if origBody != nil {
			req.Body = &bodyReadCloser{
				Reader: bytes.NewReader(bodyBytes),
				Closer: origBody,
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

// bodyReadCloser combines an io.Reader and io.Closer to preserve the underlying
// connection/body closer when request bodies are buffered and replayed.
type bodyReadCloser struct {
	io.Reader
	io.Closer
}

func (b *bodyReadCloser) Close() error {
	if b.Closer != nil {
		return b.Closer.Close()
	}
	return nil
}


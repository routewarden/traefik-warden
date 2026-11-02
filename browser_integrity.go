package traefik_warden

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

var (
	reBrowserLike = regexp.MustCompile(`(?i)(Mozilla/\d+\.\d+|AppleWebKit/\d+|Gecko/\d+|Chrome/\d+|Safari/\d+|Firefox/\d+|Edg/\d+)`)
	reChromeVer   = regexp.MustCompile(`(?:Chrome|Chromium|Edg)/(\d+)`)
	reGreaseBrand = regexp.MustCompile(`(?i)(?:Not[ _?=/().;:A-Za-z0-9-]*Brand|Not[^\w\s]?A[^\w\s]?Brand)`)

	reScriptClientUA = regexp.MustCompile(`(?i)(` +
		`python-requests|requests/|aiohttp|httpx|scrapy|urllib/|urllib3|tornado|curl-cffi|mechanize|` +
		`axios|node-fetch|undici|got/\d+|superagent|needle/\d+|` +
		`go-http-client|` +
		`okhttp|apache-httpclient|java/\d+|httpclient|` +
		`guzzlehttp|guzzle/\d+|` +
		`reqwest/\d+|` +
		`faraday|httparty|rest-client|` +
		`curl/\d+|wget/\d+|libwww-perl|phantomjs|headlesschrome|puppeteer|playwright` +
		`)`)
)

// DetectBrowserImpersonation inspects whether a request claiming to be an interactive
// desktop or mobile browser lacks required companion headers or presents contradictory Client Hints.
func DetectBrowserImpersonation(ua string, headers http.Header, headerOrder ...[]string) (bool, string) {
	uaTrim := strings.TrimSpace(ua)
	if uaTrim == "" {
		return false, ""
	}

	// Only evaluate requests that claim to be a standard browser
	if !reBrowserLike.MatchString(uaTrim) {
		return false, ""
	}

	// Exclude search engine bots that have their own FCrDNS validation (Googlebot, Bingbot, Applebot)
	if claimsBot, _ := DetectSearchEngineBot(uaTrim); claimsBot {
		return false, ""
	}

	// Exclude recognized AI bots governed by AI bot registry profiles
	if isAIBot, _ := MatchAIBot(uaTrim, AIBotProfileAll); isAIBot {
		return false, ""
	}

	// 0. Header ordering checks (if explicit order slice provided)
	if len(headerOrder) > 0 && len(headerOrder[0]) > 0 {
		if isAnomaly, reason := DetectBrowserHeaderOrder(headerOrder[0], uaTrim); isAnomaly {
			return true, reason
		}
	}

	// 1. Mandatory companion headers expected from any real interactive browser
	acceptLang := headers.Get("Accept-Language")
	if strings.TrimSpace(acceptLang) == "" {
		return true, "missing_accept_language"
	}

	acceptEnc := headers.Get("Accept-Encoding")
	if strings.TrimSpace(acceptEnc) == "" {
		return true, "missing_accept_encoding"
	}

	uaLower := strings.ToLower(uaTrim)

	// 2. Client Hints platform cross-check (Sec-CH-UA-Platform vs User-Agent OS)
	secPlatformRaw := headers.Get("Sec-CH-UA-Platform")
	if secPlatformRaw != "" {
		platform := strings.ToLower(strings.Trim(strings.TrimSpace(secPlatformRaw), "\""))

		claimedWindows := strings.Contains(uaLower, "windows")
		claimedMac := strings.Contains(uaLower, "macintosh") || strings.Contains(uaLower, "mac os x")
		claimedLinux := strings.Contains(uaLower, "linux") && !strings.Contains(uaLower, "android")
		claimedAndroid := strings.Contains(uaLower, "android")
		claimedIOS := strings.Contains(uaLower, "iphone") || strings.Contains(uaLower, "ipad") || strings.Contains(uaLower, "ipod")

		switch platform {
		case "windows":
			if !claimedWindows {
				return true, "sec_ch_ua_platform_mismatch"
			}
		case "macos", "mac os x":
			if !claimedMac {
				return true, "sec_ch_ua_platform_mismatch"
			}
		case "linux":
			if !claimedLinux {
				return true, "sec_ch_ua_platform_mismatch"
			}
		case "android":
			if !claimedAndroid {
				return true, "sec_ch_ua_platform_mismatch"
			}
		case "ios":
			if !claimedIOS {
				return true, "sec_ch_ua_platform_mismatch"
			}
		}
	}

	// 3. Client Hints mobile cross-check (Sec-CH-UA-Mobile vs User-Agent form factor)
	secMobileRaw := headers.Get("Sec-CH-UA-Mobile")
	if secMobileRaw != "" {
		secMobile := strings.Trim(strings.TrimSpace(secMobileRaw), "\"? ")
		claimedMobile := strings.Contains(uaLower, "mobile") || strings.Contains(uaLower, "iphone") || strings.Contains(uaLower, "ipod") || strings.Contains(uaLower, "android")

		if secMobile == "1" && !claimedMobile {
			return true, "sec_ch_ua_mobile_mismatch"
		}
		if secMobile == "0" {
			if strings.Contains(uaLower, "iphone") || strings.Contains(uaLower, "ipod") || (strings.Contains(uaLower, "android") && strings.Contains(uaLower, "mobile")) {
				return true, "sec_ch_ua_mobile_mismatch"
			}
		}
	}

	// 4. Client Hints brand cross-check (Non-Chromium browsers forging Sec-CH-UA)
	secCHUA := headers.Get("Sec-CH-UA")
	if secCHUA != "" {
		isFirefox := strings.Contains(uaLower, "firefox")
		isSafariOnly := strings.Contains(uaLower, "safari") && !strings.Contains(uaLower, "chrome") && !strings.Contains(uaLower, "chromium") && !strings.Contains(uaLower, "edg")
		if (isFirefox || isSafariOnly) && strings.Contains(strings.ToLower(secCHUA), "chromium") {
			return true, "sec_ch_ua_brand_mismatch"
		}
	}

	// 5. Modern Chromium Client Hints (Sec-CH-UA) & Fetch Metadata validation (Sec-Fetch-* headers)
	if match := reChromeVer.FindStringSubmatch(uaTrim); len(match) > 1 {
		ver, err := strconv.Atoi(match[1])
		if err == nil {
			if ver >= 89 && secPlatformRaw != "" && strings.TrimSpace(secCHUA) == "" {
				return true, "missing_sec_ch_ua"
			}
			if ver >= 90 {
				fetchSite := headers.Get("Sec-Fetch-Site")
				fetchMode := headers.Get("Sec-Fetch-Mode")
				fetchDest := headers.Get("Sec-Fetch-Dest")
				if fetchSite == "" && fetchMode == "" && fetchDest == "" {
					return true, "missing_sec_fetch"
				}
				if strings.EqualFold(fetchDest, "document") && fetchMode != "" && !strings.EqualFold(fetchMode, "navigate") {
					return true, "sec_fetch_mode_mismatch"
				}
			}
			if ver >= 89 && secCHUA != "" {
				lowerCH := strings.ToLower(secCHUA)
				if strings.Contains(lowerCH, "google chrome") || strings.Contains(lowerCH, "chromium") {
					if !reGreaseBrand.MatchString(secCHUA) {
						return true, "missing_grease_brand"
					}
				}
			}
		}
	}

	return false, ""
}

// DetectBrowserHeaderOrder checks if an explicit list of request header keys
// shows ordering anomalies characteristic of script libraries forging a Chromium User-Agent.
func DetectBrowserHeaderOrder(headerOrder []string, ua string) (bool, string) {
	if len(headerOrder) == 0 || ua == "" {
		return false, ""
	}
	uaTrim := strings.TrimSpace(ua)
	if !reBrowserLike.MatchString(uaTrim) {
		return false, ""
	}
	match := reChromeVer.FindStringSubmatch(uaTrim)
	if len(match) <= 1 {
		return false, ""
	}
	ver, err := strconv.Atoi(match[1])
	if err != nil || ver < 89 {
		return false, ""
	}

	secChUaIdx := -1
	uaIdx := -1
	acceptIdx := -1

	for i, h := range headerOrder {
		lower := strings.ToLower(strings.TrimSpace(h))
		if lower == "sec-ch-ua" && secChUaIdx == -1 {
			secChUaIdx = i
		} else if lower == "user-agent" && uaIdx == -1 {
			uaIdx = i
		} else if lower == "accept" && acceptIdx == -1 {
			acceptIdx = i
		}
	}

	// Real Chromium always serializes Sec-CH-UA before User-Agent and before Accept.
	if secChUaIdx != -1 {
		if uaIdx != -1 && uaIdx < secChUaIdx {
			return true, "header_order_anomaly"
		}
		if acceptIdx != -1 && acceptIdx < secChUaIdx {
			return true, "header_order_anomaly"
		}
	}

	return false, ""
}

// DetectScriptClient inspects whether a request originates from an automated HTTP client library
// or headless automation framework.
func DetectScriptClient(ua string, headers http.Header) (bool, string) {
	// 1. Headless / automation framework header indicators
	if headers.Get("X-Playwright") != "" {
		return true, "playwright_headless"
	}
	if headers.Get("X-Puppeteer") != "" {
		return true, "puppeteer_headless"
	}
	if headers.Get("X-Selenium") != "" {
		return true, "selenium_headless"
	}
	if headers.Get("X-Scrapy") != "" {
		return true, "scrapy_crawler"
	}
	if headers.Get("X-Cypress") != "" {
		return true, "cypress_headless"
	}
	if headers.Get("Sec-WebDriver") != "" || headers.Get("X-Headless") != "" || headers.Get("X-Headless-Chrome") != "" || headers.Get("X-Automation") != "" {
		return true, "webdriver_automation"
	}

	// 2. Library User-Agent regex inspection
	uaTrim := strings.TrimSpace(ua)
	if uaTrim != "" {
		if loc := reScriptClientUA.FindString(uaTrim); loc != "" {
			return true, strings.ToLower(loc)
		}
	}

	return false, ""
}

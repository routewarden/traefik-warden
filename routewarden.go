package traefik_warden

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
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
	blockUAPatterns   []*regexp.Regexp
	allowUAPatterns   []*regexp.Regexp
	botDefenseLevel   string
	blockAIBots       bool
	aiBotProfile      string
	honeypotTrapPaths          []string
	enableRobotsTxtHoneypot    bool
	robotsTxtHoneypotSecret    string
	banTable                   *BanTable
	trapBanDuration            time.Duration
	verifySearchEngineBots     bool
	fcrdnsVerifier             *FCrDNSVerifier
	detectBrowserImpersonation bool
	blockScriptClients         bool
	blockCloudHosts            bool
	ipFilter                   *IPFilter
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
			AllowedASNs                     []string              `json:"allowedASNs"`
			AllowedASNsSnake                []string              `json:"allowed_asns"`
			BlockedASNs                     []string              `json:"blockedASNs"`
			BlockedASNsSnake                []string              `json:"blocked_asns"`
			ASNDB                           string                `json:"asnDB"`
			ASNDBSnake                      string                `json:"asn_db"`
			BotDefenseLevel                 *string               `json:"botDefenseLevel"`
			BotDefenseLevelSnake            *string               `json:"bot_defense_level"`
			BlockAIBots                     *bool                 `json:"blockAIBots"`
			BlockAIBotsSnake                *bool                 `json:"block_ai_bots"`
			AIBotProfile                    *string               `json:"aiBotProfile"`
			AIBotProfileSnake               *string               `json:"ai_bot_profile"`
			BlockUserAgents                 []string              `json:"blockUserAgents"`
			BlockUserAgentsSnake            []string              `json:"block_user_agents"`
			AllowUserAgents                 []string              `json:"allowUserAgents"`
			AllowUserAgentsSnake            []string              `json:"allow_user_agents"`
			HoneypotTrapPaths               []string              `json:"honeypotTrapPaths"`
			HoneypotTrapPathsSnake          []string              `json:"honeypot_trap_paths"`
			EnableRobotsTxtHoneypot         *bool                 `json:"enableRobotsTxtHoneypot"`
			EnableRobotsTxtHoneypotSnake    *bool                 `json:"enable_robots_txt_honeypot"`
			RobotsTxtHoneypotSecret         *string               `json:"robotsTxtHoneypotSecret"`
			RobotsTxtHoneypotSecretSnake    *string               `json:"robots_txt_honeypot_secret"`
			TrapBanDuration                 *string               `json:"trapBanDuration"`
			TrapBanDurationSnake            *string               `json:"trap_ban_duration"`
			VerifySearchEngineBots          *bool                 `json:"verifySearchEngineBots"`
			VerifySearchEngineBotsSnake     *bool                 `json:"verify_search_engine_bots"`
			DetectBrowserImpersonation      *bool                 `json:"detectBrowserImpersonation"`
			DetectBrowserImpersonationSnake *bool                 `json:"detect_browser_impersonation"`
			BlockScriptClients              *bool                 `json:"blockScriptClients"`
			BlockScriptClientsSnake         *bool                 `json:"block_script_clients"`
			BlockCloudHosts                 *bool                 `json:"blockCloudHosts"`
			BlockCloudHostsSnake            *bool                 `json:"block_cloud_hosts"`
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
			ExplicitFields                  []string              `json:"explicitFields"`
			ExplicitFieldsSnake             []string              `json:"explicit_fields"`
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
		if len(scf.AllowedASNs) > 0 {
			fileCfg.AllowedASNs = scf.AllowedASNs
		} else if len(scf.AllowedASNsSnake) > 0 {
			fileCfg.AllowedASNs = scf.AllowedASNsSnake
		}
		if len(scf.BlockedASNs) > 0 {
			fileCfg.BlockedASNs = scf.BlockedASNs
		} else if len(scf.BlockedASNsSnake) > 0 {
			fileCfg.BlockedASNs = scf.BlockedASNsSnake
		}
		fileCfg.ASNDB = scf.ASNDB
		if scf.ASNDBSnake != "" {
			fileCfg.ASNDB = scf.ASNDBSnake
		}
		if len(scf.ExplicitFields) > 0 {
			fileCfg.ExplicitFields = append(fileCfg.ExplicitFields, scf.ExplicitFields...)
		}
		if len(scf.ExplicitFieldsSnake) > 0 {
			fileCfg.ExplicitFields = append(fileCfg.ExplicitFields, scf.ExplicitFieldsSnake...)
		}
		if scf.BotDefenseLevel != nil {
			fileCfg.BotDefenseLevel = *scf.BotDefenseLevel
		} else if scf.BotDefenseLevelSnake != nil {
			fileCfg.BotDefenseLevel = *scf.BotDefenseLevelSnake
		}
		if fileCfg.BotDefenseLevel != "" {
			fileCfg.applyBotDefense(fileCfg.BotDefenseLevel)
		}

		if scf.BlockAIBots != nil {
			fileCfg.BlockAIBots = *scf.BlockAIBots
			fileCfg.MarkExplicit("blockAIBots")
		} else if scf.BlockAIBotsSnake != nil {
			fileCfg.BlockAIBots = *scf.BlockAIBotsSnake
			fileCfg.MarkExplicit("blockAIBots")
		}
		if scf.AIBotProfile != nil {
			fileCfg.AIBotProfile = *scf.AIBotProfile
			fileCfg.MarkExplicit("aiBotProfile")
		} else if scf.AIBotProfileSnake != nil {
			fileCfg.AIBotProfile = *scf.AIBotProfileSnake
			fileCfg.MarkExplicit("aiBotProfile")
		}
		if len(scf.BlockUserAgents) > 0 {
			fileCfg.BlockUserAgents = scf.BlockUserAgents
		} else if len(scf.BlockUserAgentsSnake) > 0 {
			fileCfg.BlockUserAgents = scf.BlockUserAgentsSnake
		}
		if len(scf.AllowUserAgents) > 0 {
			fileCfg.AllowUserAgents = scf.AllowUserAgents
		} else if len(scf.AllowUserAgentsSnake) > 0 {
			fileCfg.AllowUserAgents = scf.AllowUserAgentsSnake
		}
		if len(scf.HoneypotTrapPaths) > 0 {
			fileCfg.HoneypotTrapPaths = scf.HoneypotTrapPaths
		} else if len(scf.HoneypotTrapPathsSnake) > 0 {
			fileCfg.HoneypotTrapPaths = scf.HoneypotTrapPathsSnake
		}
		if scf.EnableRobotsTxtHoneypot != nil {
			fileCfg.EnableRobotsTxtHoneypot = *scf.EnableRobotsTxtHoneypot
			fileCfg.MarkExplicit("enableRobotsTxtHoneypot")
		} else if scf.EnableRobotsTxtHoneypotSnake != nil {
			fileCfg.EnableRobotsTxtHoneypot = *scf.EnableRobotsTxtHoneypotSnake
			fileCfg.MarkExplicit("enableRobotsTxtHoneypot")
		}
		if scf.RobotsTxtHoneypotSecret != nil {
			fileCfg.RobotsTxtHoneypotSecret = *scf.RobotsTxtHoneypotSecret
			fileCfg.MarkExplicit("robotsTxtHoneypotSecret")
		} else if scf.RobotsTxtHoneypotSecretSnake != nil {
			fileCfg.RobotsTxtHoneypotSecret = *scf.RobotsTxtHoneypotSecretSnake
			fileCfg.MarkExplicit("robotsTxtHoneypotSecret")
		}
		if scf.TrapBanDuration != nil {
			fileCfg.TrapBanDuration = *scf.TrapBanDuration
		} else if scf.TrapBanDurationSnake != nil {
			fileCfg.TrapBanDuration = *scf.TrapBanDurationSnake
		}
		if scf.VerifySearchEngineBots != nil {
			fileCfg.VerifySearchEngineBots = *scf.VerifySearchEngineBots
			fileCfg.MarkExplicit("verifySearchEngineBots")
		} else if scf.VerifySearchEngineBotsSnake != nil {
			fileCfg.VerifySearchEngineBots = *scf.VerifySearchEngineBotsSnake
			fileCfg.MarkExplicit("verifySearchEngineBots")
		}
		if scf.DetectBrowserImpersonation != nil {
			fileCfg.DetectBrowserImpersonation = *scf.DetectBrowserImpersonation
			fileCfg.MarkExplicit("detectBrowserImpersonation")
		} else if scf.DetectBrowserImpersonationSnake != nil {
			fileCfg.DetectBrowserImpersonation = *scf.DetectBrowserImpersonationSnake
			fileCfg.MarkExplicit("detectBrowserImpersonation")
		}
		if scf.BlockScriptClients != nil {
			fileCfg.BlockScriptClients = *scf.BlockScriptClients
			fileCfg.MarkExplicit("blockScriptClients")
		} else if scf.BlockScriptClientsSnake != nil {
			fileCfg.BlockScriptClients = *scf.BlockScriptClientsSnake
			fileCfg.MarkExplicit("blockScriptClients")
		}
		if scf.BlockCloudHosts != nil {
			fileCfg.BlockCloudHosts = *scf.BlockCloudHosts
			fileCfg.MarkExplicit("blockCloudHosts")
		} else if scf.BlockCloudHostsSnake != nil {
			fileCfg.BlockCloudHosts = *scf.BlockCloudHostsSnake
			fileCfg.MarkExplicit("blockCloudHosts")
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
		if config.AllowedASNs != nil {
			fileCfg.AllowedASNs = config.AllowedASNs
		}
		if config.BlockedASNs != nil {
			fileCfg.BlockedASNs = config.BlockedASNs
		}
		if config.ASNDB != "" {
			fileCfg.ASNDB = config.ASNDB
		}
		if config.BotDefenseLevel != "" {
			fileCfg.BotDefenseLevel = config.BotDefenseLevel
			fileCfg.applyBotDefense(config.BotDefenseLevel)
		}
		if config.IsExplicit("blockAIBots", "block_ai_bots") || config.BlockAIBots {
			fileCfg.BlockAIBots = config.BlockAIBots
		}
		if config.IsExplicit("aiBotProfile", "ai_bot_profile") || config.AIBotProfile != "" {
			fileCfg.AIBotProfile = config.AIBotProfile
		}
		if len(config.BlockUserAgents) > 0 {
			fileCfg.BlockUserAgents = config.BlockUserAgents
		}
		if len(config.AllowUserAgents) > 0 {
			fileCfg.AllowUserAgents = config.AllowUserAgents
		}
		if len(config.HoneypotTrapPaths) > 0 {
			fileCfg.HoneypotTrapPaths = config.HoneypotTrapPaths
		}
		if config.IsExplicit("enableRobotsTxtHoneypot", "enable_robots_txt_honeypot") || config.EnableRobotsTxtHoneypot {
			fileCfg.EnableRobotsTxtHoneypot = config.EnableRobotsTxtHoneypot
		}
		if config.IsExplicit("robotsTxtHoneypotSecret", "robots_txt_honeypot_secret") || config.RobotsTxtHoneypotSecret != "" {
			fileCfg.RobotsTxtHoneypotSecret = config.RobotsTxtHoneypotSecret
		}
		if config.TrapBanDuration != "" {
			fileCfg.TrapBanDuration = config.TrapBanDuration
		}
		if config.IsExplicit("verifySearchEngineBots", "verify_search_engine_bots") || config.VerifySearchEngineBots {
			fileCfg.VerifySearchEngineBots = config.VerifySearchEngineBots
		}
		if config.IsExplicit("detectBrowserImpersonation", "detect_browser_impersonation") || config.DetectBrowserImpersonation {
			fileCfg.DetectBrowserImpersonation = config.DetectBrowserImpersonation
		}
		if config.IsExplicit("blockScriptClients", "block_script_clients") || config.BlockScriptClients {
			fileCfg.BlockScriptClients = config.BlockScriptClients
		}
		if config.IsExplicit("blockCloudHosts", "block_cloud_hosts") || config.BlockCloudHosts {
			fileCfg.BlockCloudHosts = config.BlockCloudHosts
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
		if config.CheckBodyMaxBytes > 0 {
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
	} else if config.BotDefenseLevel != "" {
		config.applyBotDefense(config.BotDefenseLevel)
	}

	if config.BlockAIBots && config.AIBotProfile == "" {
		config.AIBotProfile = "train_only"
	}

	methodsMap := make(map[string]struct{})
	if len(config.Methods) == 0 {
		methodsMap["GET"] = struct{}{}
		if config.CheckBody || len(config.CheckBodyPatterns) > 0 {
			methodsMap["POST"] = struct{}{}
			methodsMap["PUT"] = struct{}{}
			methodsMap["PATCH"] = struct{}{}
			methodsMap["DELETE"] = struct{}{}
		}
	} else if len(config.Methods) == 1 && strings.EqualFold(config.Methods[0], "GET") && (config.CheckBody || len(config.CheckBodyPatterns) > 0) {
		methodsMap["GET"] = struct{}{}
		methodsMap["POST"] = struct{}{}
		methodsMap["PUT"] = struct{}{}
		methodsMap["PATCH"] = struct{}{}
		methodsMap["DELETE"] = struct{}{}
	} else {
		for _, m := range config.Methods {
			m = strings.ToUpper(strings.TrimSpace(m))
			if m != "" {
				methodsMap[m] = struct{}{}
			}
		}
		if len(methodsMap) == 0 {
			methodsMap["GET"] = struct{}{}
			if config.CheckBody || len(config.CheckBodyPatterns) > 0 {
				methodsMap["POST"] = struct{}{}
				methodsMap["PUT"] = struct{}{}
				methodsMap["PATCH"] = struct{}{}
				methodsMap["DELETE"] = struct{}{}
			}
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

	ipFilter.asn, err = NewASNFilterEx(config.AllowedASNs, config.BlockedASNs, config.ASNDB, config.BlockCloudHosts)
	if err != nil {
		return nil, fmt.Errorf("routewarden [%s]: %w", name, err)
	}

	compiledBlockUARegexes := make([]*regexp.Regexp, 0, len(config.BlockUserAgents))
	for _, p := range config.BlockUserAgents {
		if strings.TrimSpace(p) == "" {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("routewarden [%s]: invalid block user agent regex pattern %q: %w", name, p, err)
		}
		compiledBlockUARegexes = append(compiledBlockUARegexes, re)
	}

	compiledAllowUARegexes := make([]*regexp.Regexp, 0, len(config.AllowUserAgents))
	for _, p := range config.AllowUserAgents {
		if strings.TrimSpace(p) == "" {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("routewarden [%s]: invalid allow user agent regex pattern %q: %w", name, p, err)
		}
		compiledAllowUARegexes = append(compiledAllowUARegexes, re)
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

	banDuration := ParseBanDuration(config.TrapBanDuration)
	var banTable *BanTable
	if len(config.HoneypotTrapPaths) > 0 || config.EnableRobotsTxtHoneypot {
		banTable = NewBanTable(10000)
	}

	var fcrdns *FCrDNSVerifier
	if config.VerifySearchEngineBots {
		fcrdns = NewFCrDNSVerifier(6*time.Hour, 500*time.Millisecond)
	}

	rw := &RouteWarden{
		next:                   next,
		name:                   name,
		enabled:                config.Enabled,
		debug:                  config.Debug,
		securityLog:            config.SecurityLog,
		methods:                methodsMap,
		blockRegexes:           compiledBlockRegexes,
		allowRegexes:           compiledAllowRegexes,
		bodyRegexes:            compiledBodyRegexes,
		blockUAPatterns:        compiledBlockUARegexes,
		allowUAPatterns:        compiledAllowUARegexes,
		botDefenseLevel:        config.BotDefenseLevel,
		blockAIBots:            config.BlockAIBots,
		aiBotProfile:           config.AIBotProfile,
		honeypotTrapPaths:      config.HoneypotTrapPaths,
		enableRobotsTxtHoneypot:    config.EnableRobotsTxtHoneypot,
		robotsTxtHoneypotSecret:    config.RobotsTxtHoneypotSecret,
		banTable:               banTable,
		trapBanDuration:        banDuration,
		verifySearchEngineBots:     config.VerifySearchEngineBots,
		fcrdnsVerifier:             fcrdns,
		detectBrowserImpersonation: config.DetectBrowserImpersonation,
		blockScriptClients:         config.BlockScriptClients,
		blockCloudHosts:            config.BlockCloudHosts,
		ipFilter:                   ipFilter,
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

// SetFCrDNSLookupFuncs overrides the DNS lookup functions for testing purposes.
func (rw *RouteWarden) SetFCrDNSLookupFuncs(
	lookupAddr func(ctx context.Context, addr string) ([]string, error),
	lookupIP func(ctx context.Context, host string) ([]net.IP, error),
) {
	if rw.fcrdnsVerifier != nil {
		rw.fcrdnsVerifier.lookupAddr = lookupAddr
		rw.fcrdnsVerifier.lookupIP = lookupIP
	}
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
			statusCode = rw.responseHandler.EffectiveStatusCode()
		}
	}

	verdict := "BLOCK"
	cleanMode := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(mode), "_", ""))
	switch cleanMode {
	case "tarpit", "markovtarpit":
		verdict = "TARPIT"
	case "captcha", "ratelimitchallenge", "challenge":
		verdict = "CHALLENGE"
	}

	event := map[string]any{
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
		"verdict":         verdict,
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
	if len(rw.methods) > 0 {
		_, hasWildcard := rw.methods["*"]
		_, hasAll := rw.methods["ALL"]
		_, matchesMethod := rw.methods[strings.ToUpper(req.Method)]
		if !hasWildcard && !hasAll && !matchesMethod {
			rw.logDebug("method %s not in inspected methods, bypassing", req.Method)
			rw.next.ServeHTTP(w, req)
			return
		}
	}

	// Exempt whitelisted client IPs or CIDR subnets from blocking
	if rw.ipFilter.IsAllowed(req) {
		rw.logDebug("client IP %s is whitelisted, allowing request", rw.extractClientIP(req))
		rw.next.ServeHTTP(w, req)
		return
	}

	// Blocked ASN check
	if rw.ipFilter != nil {
		if isBlockedASN, asnNum := rw.ipFilter.IsBlockedASN(req); isBlockedASN {
			clientIP := rw.extractClientIP(req)
			rw.logDebug("client IP %s is in blocked ASN %d, dropping request", clientIP, asnNum)
			rw.logSecurityEvent(req, fmt.Sprintf("AS%d", asnNum), fmt.Sprintf("AS%d", asnNum), "asn_blocked")
			rw.responseHandler.ServeBlockedRequest(w, req)
			return
		}
	}

	clientIP := rw.extractClientIP(req)

	// Active Ban Table Check
	if rw.banTable != nil && rw.banTable.IsBanned(clientIP) {
		rw.logDebug("client IP %s is actively banned, dropping request", clientIP)
		rw.logSecurityEvent(req, clientIP, "ban_table", "ip_banned")
		rw.responseHandler.ServeBlockedRequest(w, req)
		return
	}

	// Check PoW solution cookie (__rw_pow) or header (X-RW-PoW)
	powToken := extractPoWToken(req)
	isPoWValid := false
	if powToken != "" && rw.responseHandler != nil && rw.responseHandler.config != nil {
		secret := rw.responseHandler.config.PoWSecret
		if secret == "" {
			secret = DefaultPoWSecret
		}
		timeout := rw.responseHandler.config.PoWTimeoutSeconds
		if timeout <= 0 {
			timeout = DefaultPoWTimeoutSeconds
		}
		isPoWValid, _ = VerifyPoWSolution(clientIP, secret, powToken, timeout, time.Now())
	}

	serveBlock := func(target, pattern, reason string) {
		if isPoWValid {
			rw.logDebug("client %s PoW verified, bypassing block %s (%s)", clientIP, pattern, reason)
			rw.forwardRequest(w, req)
			return
		}
		rw.logSecurityEvent(req, target, pattern, reason)
		rw.responseHandler.ServeBlockedRequest(w, req)
	}

	// User-Agent & AI Bot Inspection
	ua := req.UserAgent()
	uaAllowed := false
	for _, re := range rw.allowUAPatterns {
		if re.MatchString(ua) {
			uaAllowed = true
			break
		}
	}

	if !uaAllowed {
		// Search engine bot impersonation verification (FCrDNS)
		if rw.verifySearchEngineBots && rw.fcrdnsVerifier != nil {
			if claimsBot, engine := DetectSearchEngineBot(ua); claimsBot {
				if !rw.fcrdnsVerifier.Verify(req.Context(), clientIP, engine) {
					rw.logDebug("client %s spoofed search engine %s (User-Agent: %q), failed FCrDNS", clientIP, engine, ua)
					serveBlock(ua, string(engine)+"_spoofed", "search_engine_spoofed")
					return
				}
				// Verified legitimate search engine spider; exempt from generic bot blocks
				uaAllowed = true
			}
		}
	}

	if !uaAllowed {
		uaBlocked := false
		uaPattern := ""
		uaReason := ""

		for _, re := range rw.blockUAPatterns {
			if re.MatchString(ua) {
				uaBlocked = true
				uaPattern = re.String()
				uaReason = "user_agent_blocked"
				break
			}
		}

		if !uaBlocked && rw.blockAIBots {
			if matched, botType := MatchAIBot(ua, rw.aiBotProfile); matched {
				uaBlocked = true
				uaPattern = botType
				uaReason = "ai_bot_blocked"
			}
		}

		if !uaBlocked && rw.detectBrowserImpersonation {
			if isSpoofed, reason := DetectBrowserImpersonation(ua, req.Header); isSpoofed {
				uaBlocked = true
				uaPattern = reason
				uaReason = "browser_spoofed"
			}
		}

		if !uaBlocked && rw.blockScriptClients {
			if isScript, clientType := DetectScriptClient(ua, req.Header); isScript {
				uaBlocked = true
				uaPattern = clientType
				uaReason = "script_client_blocked"
			}
		}

		if uaBlocked {
			rw.logDebug("client %s User-Agent %q blocked by pattern %q (reason: %s)", clientIP, ua, uaPattern, uaReason)
			serveBlock(ua, uaPattern, uaReason)
			return
		}
	}

	// Canonicalize and inspect paths with anti-evasion protections
	candidatePaths := ExtractCandidatePaths(req.URL.RawPath, req.URL.Path, req.RequestURI)
	rw.logDebug("inspecting request %s %s with %d candidate paths: %v", req.Method, req.URL.Path, len(candidatePaths), candidatePaths)

	// Honeypot spider trap check (static and dynamic robots.txt traps)
	var activeTraps []string
	if len(rw.honeypotTrapPaths) > 0 {
		activeTraps = append(activeTraps, rw.honeypotTrapPaths...)
	}
	if rw.enableRobotsTxtHoneypot {
		_, dynPrefixes := GetActiveRobotsHoneypotTraps(rw.robotsTxtHoneypotSecret, time.Now())
		activeTraps = append(activeTraps, dynPrefixes...)
	}

	if len(activeTraps) > 0 {
		for _, candPath := range candidatePaths {
			for _, trapPath := range activeTraps {
				cleanTrap := strings.TrimSpace(trapPath)
				if cleanTrap != "" && !strings.HasPrefix(cleanTrap, "/") {
					cleanTrap = "/" + cleanTrap
				}
				baseTrap := strings.TrimRight(cleanTrap, "/")
				if baseTrap == "" {
					continue
				}
				prefixTrap := baseTrap + "/"
				lowerCand := strings.ToLower(candPath)
				lowerBase := strings.ToLower(baseTrap)
				lowerPrefix := strings.ToLower(prefixTrap)
				if lowerCand == lowerBase || strings.HasPrefix(lowerCand, lowerPrefix) {
					if rw.banTable != nil && clientIP != "" {
						rw.banTable.Ban(clientIP, rw.trapBanDuration)
					}
					rw.logDebug("client %s triggered honeypot spider trap %q (path: %q), banned for %v", clientIP, cleanTrap, candPath, rw.trapBanDuration)
					rw.logSecurityEvent(req, candPath, cleanTrap, "honeypot_trap_triggered")
					rw.responseHandler.ServeBlockedRequest(w, req)
					return
				}
			}
		}
	}

	// 1. Check AllowPatterns first (Allowlist override)
	for _, p := range candidatePaths {
		if re := rw.findMatchingAllow(p); re != nil {
			rw.logDebug("path %q allowed by pattern %q", p, re.String())
			rw.forwardRequest(w, req)
			return
		}
	}

	// Datacenter & Cloud Hosting IP Classifier
	if !uaAllowed && rw.blockCloudHosts && rw.ipFilter != nil && rw.ipFilter.asn != nil {
		if isCloud, cloudASN, provider := rw.ipFilter.asn.IsCloudHost(clientIP); isCloud {
			reason := "cloud_host_blocked"
			if reBrowserLike.MatchString(ua) {
				reason = "datacenter_browser_impersonation"
			}
			matchedPattern := fmt.Sprintf("AS%d (%s)", cloudASN, provider)
			rw.logDebug("client %s origin ASN %d (%s) blocked by cloud host classifier (reason: %s)", clientIP, cloudASN, provider, reason)
			serveBlock(clientIP, matchedPattern, reason)
			return
		}
	}

	// 2. Check BlockPatterns against URL paths
	for _, p := range candidatePaths {
		if re := rw.findMatchingBlock(p); re != nil {
			rw.logDebug("path %q blocked by pattern %q (mode: %s)", p, re.String(), rw.responseHandler.config.Mode)
			serveBlock(p, re.String(), "path_blocked")
			return
		}
	}

	// 3. Optional: Check Query String if enabled
	if rw.checkQuery && req.URL.RawQuery != "" {
		unescapedQuery := lenientQueryUnescape(req.URL.RawQuery)

		if re := rw.findMatchingBlock(unescapedQuery); re != nil {
			rw.logDebug("unescaped query %q blocked by pattern %q", unescapedQuery, re.String())
			serveBlock(unescapedQuery, re.String(), "query_blocked")
			return
		}
		if re := rw.findMatchingBlock(req.URL.RawQuery); re != nil {
			rw.logDebug("raw query %q blocked by pattern %q", req.URL.RawQuery, re.String())
			serveBlock(req.URL.RawQuery, re.String(), "query_blocked")
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
					serveBlock(key, re.String(), "query_param_blocked")
					return
				}
			}
			for _, val := range values {
				valCandidates := append([]string{val}, ExtractCandidatePaths("", val, val)...)
				valCandidates = valCandidates[:len(valCandidates):len(valCandidates)]
				for _, vc := range valCandidates {
					if re := rw.findMatchingBlock(vc); re != nil {
						rw.logDebug("query param %q with value %q blocked by pattern %q", key, val, re.String())
						serveBlock(val, re.String(), "query_param_blocked")
						return
					}
				}
			}
		}

		// Also split raw and unescaped query strings on '&' and ';' to catch keys/values even when
		// malformed encodings, semicolons, or encoded delimiters (%26, %3b) cause ParseQuery to error
		queriesToParse := []string{req.URL.RawQuery}
		if unescapedQuery != req.URL.RawQuery {
			queriesToParse = append(queriesToParse, unescapedQuery)
		}
		for _, qStr := range queriesToParse {
			for _, pair := range strings.FieldsFunc(qStr, func(r rune) bool { return r == '&' || r == ';' }) {
				if k, v, ok := strings.Cut(pair, "="); ok {
					kCandidates := append([]string{k}, ExtractCandidatePaths("", k, k)...)
					kCandidates = kCandidates[:len(kCandidates):len(kCandidates)]
					for _, kc := range kCandidates {
						if re := rw.findMatchingBlock(kc); re != nil {
							rw.logDebug("query param key %q blocked by pattern %q", k, re.String())
							serveBlock(k, re.String(), "query_param_blocked")
							return
						}
					}
					vCandidates := append([]string{v}, ExtractCandidatePaths("", v, v)...)
					vCandidates = vCandidates[:len(vCandidates):len(vCandidates)]
					for _, vc := range vCandidates {
						if re := rw.findMatchingBlock(vc); re != nil {
							rw.logDebug("query param val %q blocked by pattern %q", v, re.String())
							serveBlock(v, re.String(), "query_param_blocked")
							return
						}
					}
				} else if pair != "" {
					pCandidates := append([]string{pair}, ExtractCandidatePaths("", pair, pair)...)
					pCandidates = pCandidates[:len(pCandidates):len(pCandidates)]
					for _, pc := range pCandidates {
						if re := rw.findMatchingBlock(pc); re != nil {
							rw.logDebug("query item %q blocked by pattern %q", pair, re.String())
							serveBlock(pair, re.String(), "query_param_blocked")
							return
						}
					}
				}
			}
		}
	}

	// 4. Optional: Check specified forwarded/rewrite headers for path evasion & sensitive endpoints
	if len(rw.checkHeaders) > 0 {
		for _, headerName := range rw.checkHeaders {
			for _, rawHeaderVal := range req.Header.Values(headerName) {
				rawHeaderVal = strings.TrimSpace(rawHeaderVal)
				if rawHeaderVal == "" {
					continue
				}
				headerVals := []string{rawHeaderVal}
				if strings.HasPrefix(rawHeaderVal, "\"") && strings.HasSuffix(rawHeaderVal, "\"") && len(rawHeaderVal) >= 2 {
					unquoted := strings.TrimSpace(rawHeaderVal[1 : len(rawHeaderVal)-1])
					if unquoted != "" && unquoted != rawHeaderVal {
						headerVals = append(headerVals, unquoted)
					}
				} else if strings.HasPrefix(rawHeaderVal, "'") && strings.HasSuffix(rawHeaderVal, "'") && len(rawHeaderVal) >= 2 {
					unquoted := strings.TrimSpace(rawHeaderVal[1 : len(rawHeaderVal)-1])
					if unquoted != "" && unquoted != rawHeaderVal {
						headerVals = append(headerVals, unquoted)
					}
				}
				if strings.Contains(rawHeaderVal, ",") {
					for _, part := range strings.Split(rawHeaderVal, ",") {
						part = strings.TrimSpace(part)
						if strings.HasPrefix(part, "\"") && strings.HasSuffix(part, "\"") && len(part) >= 2 {
							part = strings.TrimSpace(part[1 : len(part)-1])
						} else if strings.HasPrefix(part, "'") && strings.HasSuffix(part, "'") && len(part) >= 2 {
							part = strings.TrimSpace(part[1 : len(part)-1])
						}
						if part != "" {
							headerVals = append(headerVals, part)
						}
					}
				}

				for _, headerVal := range headerVals {
					headerCandidates := append([]string{headerVal}, ExtractCandidatePaths("", headerVal, headerVal)...)
					for _, hc := range headerCandidates {
						if re := rw.findMatchingBlock(hc); re != nil {
							rw.logDebug("header %q with value %q blocked by pattern %q", headerName, headerVal, re.String())
							serveBlock(rawHeaderVal, re.String(), "header_blocked")
							return
						}
					}
				}
			}
		}
	}

	// 5. Optional: Check Request Body if enabled
	if rw.checkBody && req.Body != nil && req.Body != http.NoBody {
		maxBytes := rw.checkBodyMaxBytes
		if maxBytes <= 0 {
			maxBytes = 64 * 1024
		}

		origBody := req.Body
		bodyBytes, _ := io.ReadAll(io.LimitReader(origBody, maxBytes))
		if len(bodyBytes) > 0 {
			req.Body = &bodyReadCloser{
				Reader: io.MultiReader(bytes.NewReader(bodyBytes), origBody),
				Closer: origBody,
			}

			bodyStr := string(bodyBytes)
			unescapedBody := lenientQueryUnescape(bodyStr)

			bodyCandidates := []string{bodyStr, unescapedBody}

			// Form urlencoded parameters extraction (&, ;)
			if parsedValues, err := url.ParseQuery(bodyStr); err == nil && len(parsedValues) > 0 {
				for k, vs := range parsedValues {
					bodyCandidates = append(bodyCandidates, k)
					bodyCandidates = append(bodyCandidates, ExtractCandidatePaths("", k, k)...)
					for _, v := range vs {
						bodyCandidates = append(bodyCandidates, v)
						bodyCandidates = append(bodyCandidates, ExtractCandidatePaths(v, v, v)...)
					}
				}
			}
			bodiesToParse := []string{bodyStr}
			if unescapedBody != bodyStr {
				bodiesToParse = append(bodiesToParse, unescapedBody)
			}
			for _, bStr := range bodiesToParse {
				for _, pair := range strings.FieldsFunc(bStr, func(r rune) bool { return r == '&' || r == ';' }) {
					if k, v, ok := strings.Cut(pair, "="); ok {
						bodyCandidates = append(bodyCandidates, k, v)
						bodyCandidates = append(bodyCandidates, ExtractCandidatePaths("", k, k)...)
						bodyCandidates = append(bodyCandidates, ExtractCandidatePaths("", v, v)...)
					}
				}
			}

			// JSON payload string values extraction
			trimmedBody := strings.TrimSpace(bodyStr)
			if (strings.HasPrefix(trimmedBody, "{") && strings.HasSuffix(trimmedBody, "}")) ||
				(strings.HasPrefix(trimmedBody, "[") && strings.HasSuffix(trimmedBody, "]")) {
				var jsonVal any
				if err := json.Unmarshal([]byte(trimmedBody), &jsonVal); err == nil {
					var extractJSON func(v any)
					extractJSON = func(v any) {
						switch val := v.(type) {
						case string:
							bodyCandidates = append(bodyCandidates, val)
							bodyCandidates = append(bodyCandidates, ExtractCandidatePaths("", val, val)...)
						case []any:
							for _, item := range val {
								extractJSON(item)
							}
						case map[string]any:
							for k, item := range val {
								bodyCandidates = append(bodyCandidates, k)
								bodyCandidates = append(bodyCandidates, ExtractCandidatePaths("", k, k)...)
								extractJSON(item)
							}
						}
					}
					extractJSON(jsonVal)
				}
			}
			patternsToCheck := rw.bodyRegexes
			if len(patternsToCheck) == 0 {
				patternsToCheck = rw.blockRegexes
			}

			for _, bc := range bodyCandidates {
				for _, re := range patternsToCheck {
					if re.MatchString(bc) {
						rw.logDebug("body payload blocked by pattern %q", re.String())
						serveBlock("[body payload]", re.String(), "body_blocked")
						return
					}
				}
			}
		} else {
			// Restore already-read bytes so downstream sees a complete body even
			// when io.ReadAll returned an error after partially consuming origBody.
			req.Body = &bodyReadCloser{
				Reader: io.MultiReader(bytes.NewReader(bodyBytes), origBody),
				Closer: origBody,
			}
		}
	}

	rw.logDebug("request %s %s passed inspection", req.Method, req.URL.Path)
	rw.forwardRequest(w, req)
}

func (rw *RouteWarden) forwardRequest(w http.ResponseWriter, req *http.Request) {
	if rw.enableRobotsTxtHoneypot && IsRobotsTxtPath(req.URL.Path) && (req.Method == http.MethodGet || req.Method == http.MethodHead) {
		buf := &robotsResponseBuffer{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
			header:         make(http.Header),
		}
		rw.next.ServeHTTP(buf, req)

		activeTrap, _ := GetActiveRobotsHoneypotTraps(rw.robotsTxtHoneypotSecret, time.Now())
		var finalBody []byte
		if buf.statusCode == http.StatusNotFound {
			buf.statusCode = http.StatusOK
			finalBody = InjectRobotsTxtTrap(nil, activeTrap)
		} else if buf.statusCode >= 200 && buf.statusCode < 300 {
			finalBody = InjectRobotsTxtTrap(buf.buf.Bytes(), activeTrap)
		} else {
			buf.flushOriginal()
			return
		}

		for k, vv := range buf.header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.Header().Del("Content-Length")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(buf.statusCode)
		w.Write(finalBody)
		return
	}

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

func (cfg *Config) applyBotDefense(level string) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "light", "relaxed":
		if !cfg.IsExplicit("blockAIBots", "block_ai_bots") {
			cfg.BlockAIBots = true
		}
		if !cfg.IsExplicit("aiBotProfile", "ai_bot_profile") && cfg.AIBotProfile == "" {
			cfg.AIBotProfile = "train_only"
		}
		if !cfg.IsExplicit("blockScriptClients", "block_script_clients") {
			cfg.BlockScriptClients = true
		}
		if !cfg.IsExplicit("verifySearchEngineBots", "verify_search_engine_bots") {
			cfg.VerifySearchEngineBots = true
		}
	case "standard", "moderate":
		if !cfg.IsExplicit("blockAIBots", "block_ai_bots") {
			cfg.BlockAIBots = true
		}
		if !cfg.IsExplicit("aiBotProfile", "ai_bot_profile") && cfg.AIBotProfile == "" {
			cfg.AIBotProfile = "train_only"
		}
		if !cfg.IsExplicit("blockScriptClients", "block_script_clients") {
			cfg.BlockScriptClients = true
		}
		if !cfg.IsExplicit("detectBrowserImpersonation", "detect_browser_impersonation") {
			cfg.DetectBrowserImpersonation = true
		}
		if !cfg.IsExplicit("verifySearchEngineBots", "verify_search_engine_bots") {
			cfg.VerifySearchEngineBots = true
		}
	case "strict":
		if !cfg.IsExplicit("blockAIBots", "block_ai_bots") {
			cfg.BlockAIBots = true
		}
		if !cfg.IsExplicit("aiBotProfile", "ai_bot_profile") && cfg.AIBotProfile == "" {
			cfg.AIBotProfile = "all"
		}
		if !cfg.IsExplicit("blockScriptClients", "block_script_clients") {
			cfg.BlockScriptClients = true
		}
		if !cfg.IsExplicit("detectBrowserImpersonation", "detect_browser_impersonation") {
			cfg.DetectBrowserImpersonation = true
		}
		if !cfg.IsExplicit("verifySearchEngineBots", "verify_search_engine_bots") {
			cfg.VerifySearchEngineBots = true
		}
	case "aggressive", "paranoia":
		if !cfg.IsExplicit("blockAIBots", "block_ai_bots") {
			cfg.BlockAIBots = true
		}
		if !cfg.IsExplicit("aiBotProfile", "ai_bot_profile") && cfg.AIBotProfile == "" {
			cfg.AIBotProfile = "aggressive"
		}
		if !cfg.IsExplicit("blockScriptClients", "block_script_clients") {
			cfg.BlockScriptClients = true
		}
		if !cfg.IsExplicit("detectBrowserImpersonation", "detect_browser_impersonation") {
			cfg.DetectBrowserImpersonation = true
		}
		if !cfg.IsExplicit("verifySearchEngineBots", "verify_search_engine_bots") {
			cfg.VerifySearchEngineBots = true
		}
	}
}

// applyBotDefenseLevel applies preset security configurations for the given level.
// Explicitly configured settings take precedence over presets.
func applyBotDefenseLevel(level string, blockAIBots *bool, aiBotProfile *string, detectBrowser *bool, blockScripts *bool, verifySearch *bool) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "light", "relaxed":
		*blockAIBots = true
		if *aiBotProfile == "" {
			*aiBotProfile = "train_only"
		}
		*blockScripts = true
		*verifySearch = true
	case "standard", "moderate":
		*blockAIBots = true
		if *aiBotProfile == "" {
			*aiBotProfile = "train_only"
		}
		*blockScripts = true
		*detectBrowser = true
		*verifySearch = true
	case "strict":
		*blockAIBots = true
		if *aiBotProfile == "" {
			*aiBotProfile = "all"
		}
		*blockScripts = true
		*detectBrowser = true
		*verifySearch = true
	case "aggressive", "paranoia":
		*blockAIBots = true
		if *aiBotProfile == "" {
			*aiBotProfile = "aggressive"
		}
		*blockScripts = true
		*detectBrowser = true
		*verifySearch = true
	}
}

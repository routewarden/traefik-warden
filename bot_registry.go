package traefik_warden

import (
	"regexp"
	"strings"
)

// AIBotProfile represents the bot filtering strategy profile.
type AIBotProfile string

const (
	AIBotProfileAll        = "all"
	AIBotProfileTrainOnly  = "train_only"
	AIBotProfileAggressive = "aggressive"
	AIBotProfileSearchOnly = "search_only"
	AIBotProfileAgentsOnly = "agents_only"
	AIBotProfileCustom     = "custom"
)

var (
	// Training/Harvester crawlers (Tier 1): Mass scrape content for LLM pre-training.
	reAITrainingBots = regexp.MustCompile(`(?i)(GPTBot|ClaudeBot|anthropic|Claude-Web|Google-Extended|Bytespider|CCBot|Applebot-Extended|cohere|cohere-ai|Amazonbot|Diffbot|ImagesiftBot|FacebookBot|Meta-ExternalAgent|Meta-ExternalFetcher|Omgilibot|Timpibot|Webzio|YouBot|MistralBot|DeepSeekBot|Exabot|MetaphorBot|Cotalker|PetalBot)`)

	// Search and real-time conversational agents (Tier 2): Retrieve live pages to answer user prompts and cite sources.
	reAISearchBots = regexp.MustCompile(`(?i)(OAI-SearchBot|ChatGPT-User|PerplexityBot|Perplexity-Search|GrokBot|Twitterbot|DuckAssistBot|BingPreview)`)

	// Aggressive bots known to disregard crawl delays, robots.txt, or hammer infrastructure.
	reAIAggressiveBots = regexp.MustCompile(`(?i)(Bytespider|ClaudeBot|CCBot|Diffbot|PetalBot)`)

	// Autonomous AI Agents & Scraper Frameworks (Tier 3).
	reAIAgents = regexp.MustCompile(`(?i)(Firecrawl|Apify|Zyte|BrightData|Crawlbase|ScrapingBee|Octoparse|AutoGPT|LangChain|LlamaIndex|AgentGPT)`)
)

// MatchAIBot evaluates a User-Agent against the chosen profile.
// It returns true and the matched category name if the bot matches the blocking rule.
func MatchAIBot(userAgent string, profile string) (bool, string) {
	ua := strings.TrimSpace(userAgent)
	if ua == "" {
		return false, ""
	}

	normProfile := strings.ToLower(strings.TrimSpace(profile))
	if normProfile == "" {
		normProfile = AIBotProfileTrainOnly
	}

	switch normProfile {
	case AIBotProfileAll:
		if reAITrainingBots.MatchString(ua) {
			return true, "ai_training_bot"
		}
		if reAISearchBots.MatchString(ua) {
			return true, "ai_search_bot"
		}
		if reAIAggressiveBots.MatchString(ua) {
			return true, "ai_aggressive_bot"
		}
		if reAIAgents.MatchString(ua) {
			return true, "ai_agent_bot"
		}
		return false, ""

	case AIBotProfileAggressive:
		if reAIAggressiveBots.MatchString(ua) {
			return true, "ai_aggressive_bot"
		}
		if reAIAgents.MatchString(ua) {
			return true, "ai_agent_bot"
		}
		return false, ""

	case AIBotProfileSearchOnly:
		if reAISearchBots.MatchString(ua) {
			return true, "ai_search_bot"
		}
		return false, ""

	case AIBotProfileAgentsOnly:
		if reAIAgents.MatchString(ua) {
			return true, "ai_agent_bot"
		}
		return false, ""

	case AIBotProfileCustom:
		return false, ""

	case AIBotProfileTrainOnly:
		fallthrough
	default:
		// Train only: block training crawlers and autonomous agents, allow search bots (e.g. Perplexity, OAI-SearchBot)
		if reAITrainingBots.MatchString(ua) {
			return true, "ai_training_bot"
		}
		if reAIAgents.MatchString(ua) {
			return true, "ai_agent_bot"
		}
		return false, ""
	}
}

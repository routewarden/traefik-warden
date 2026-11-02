package traefik_warden

import "testing"

func TestMatchAIBot(t *testing.T) {
	tests := []struct {
		name        string
		ua          string
		profile     string
		wantMatched bool
		wantType    string
	}{
		{
			name:        "Empty UA",
			ua:          "",
			profile:     "train_only",
			wantMatched: false,
		},
		{
			name:        "Normal Browser (Chrome)",
			ua:          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			profile:     "all",
			wantMatched: false,
		},
		{
			name:        "GPTBot on train_only",
			ua:          "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)",
			profile:     "train_only",
			wantMatched: true,
			wantType:    "ai_training_bot",
		},
		{
			name:        "Bytespider on train_only",
			ua:          "Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; Bytespider; spider-feedback@bytedance.com)",
			profile:     "train_only",
			wantMatched: true,
			wantType:    "ai_training_bot",
		},
		{
			name:        "MistralBot on train_only",
			ua:          "MistralBot/1.0",
			profile:     "train_only",
			wantMatched: true,
			wantType:    "ai_training_bot",
		},
		{
			name:        "DeepSeekBot on train_only",
			ua:          "Mozilla/5.0 (compatible; DeepSeekBot/1.0; +https://www.deepseek.com)",
			profile:     "train_only",
			wantMatched: true,
			wantType:    "ai_training_bot",
		},
		{
			name:        "PerplexityBot on train_only (citation search allowed)",
			ua:          "Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)",
			profile:     "train_only",
			wantMatched: false,
		},
		{
			name:        "PerplexityBot on search_only (blocked)",
			ua:          "Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)",
			profile:     "search_only",
			wantMatched: true,
			wantType:    "ai_search_bot",
		},
		{
			name:        "GrokBot on search_only (blocked)",
			ua:          "Mozilla/5.0 (compatible; GrokBot/1.0)",
			profile:     "search_only",
			wantMatched: true,
			wantType:    "ai_search_bot",
		},
		{
			name:        "GPTBot on search_only (not blocked under search_only)",
			ua:          "GPTBot/1.0",
			profile:     "search_only",
			wantMatched: false,
		},
		{
			name:        "Firecrawl on agents_only (blocked)",
			ua:          "Firecrawl/1.0 (+https://firecrawl.dev)",
			profile:     "agents_only",
			wantMatched: true,
			wantType:    "ai_agent_bot",
		},
		{
			name:        "Apify on agents_only (blocked)",
			ua:          "ApifyClient/1.2.3",
			profile:     "agents_only",
			wantMatched: true,
			wantType:    "ai_agent_bot",
		},
		{
			name:        "GPTBot on agents_only (not blocked under agents_only)",
			ua:          "GPTBot/1.0",
			profile:     "agents_only",
			wantMatched: false,
		},
		{
			name:        "Firecrawl on all (blocked)",
			ua:          "Firecrawl/1.0",
			profile:     "all",
			wantMatched: true,
			wantType:    "ai_agent_bot",
		},
		{
			name:        "PerplexityBot on train_only (citation search allowed)",
			ua:          "Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)",
			profile:     "train_only",
			wantMatched: false,
		},
		{
			name:        "PerplexityBot on all (blocked)",
			ua:          "Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)",
			profile:     "all",
			wantMatched: true,
			wantType:    "ai_search_bot",
		},
		{
			name:        "OAI-SearchBot on all",
			ua:          "OAI-SearchBot/1.0",
			profile:     "all",
			wantMatched: true,
			wantType:    "ai_search_bot",
		},
		{
			name:        "Bytespider on aggressive",
			ua:          "Bytespider/1.0",
			profile:     "aggressive",
			wantMatched: true,
			wantType:    "ai_aggressive_bot",
		},
		{
			name:        "Google-Extended on aggressive (only aggressive list blocked)",
			ua:          "Google-Extended",
			profile:     "aggressive",
			wantMatched: false,
		},
		{
			name:        "Google-Extended on train_only",
			ua:          "Google-Extended",
			profile:     "train_only",
			wantMatched: true,
			wantType:    "ai_training_bot",
		},
		{
			name:        "Custom profile does not match builtins",
			ua:          "GPTBot/1.0",
			profile:     "custom",
			wantMatched: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMatched, gotType := MatchAIBot(tt.ua, tt.profile)
			if gotMatched != tt.wantMatched {
				t.Errorf("MatchAIBot(%q, %q) gotMatched = %v, want %v", tt.ua, tt.profile, gotMatched, tt.wantMatched)
			}
			if gotMatched && gotType != tt.wantType {
				t.Errorf("MatchAIBot(%q, %q) gotType = %q, want %q", tt.ua, tt.profile, gotType, tt.wantType)
			}
		})
	}
}

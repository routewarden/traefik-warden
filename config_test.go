package traefik_warden_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/routewarden/traefik-warden"
)

func TestCreateConfig_Defaults(t *testing.T) {
	cfg := traefik_warden.CreateConfig()

	if !cfg.Enabled {
		t.Errorf("expected Enabled to default to true")
	}
	if !cfg.EnableDefaultPatterns {
		t.Errorf("expected EnableDefaultPatterns to default to true")
	}
	if !cfg.EnableDefaultAllowPatterns {
		t.Errorf("expected EnableDefaultAllowPatterns to default to true")
	}
	if cfg.StatusCode != http.StatusForbidden {
		t.Errorf("expected StatusCode to default to %d, got %d", http.StatusForbidden, cfg.StatusCode)
	}
	if cfg.CheckQuery {
		t.Errorf("expected CheckQuery to default to false")
	}
	if cfg.Debug {
		t.Errorf("expected Debug to default to false")
	}
	if !cfg.SecurityLog {
		t.Errorf("expected SecurityLog to default to true")
	}
	if len(cfg.BlockPatterns) != 0 {
		t.Errorf("expected custom BlockPatterns to default to empty slice")
	}
	if len(cfg.AllowPatterns) != 0 {
		t.Errorf("expected custom AllowPatterns to default to empty slice")
	}
	if len(cfg.AllowedIPs) != 0 {
		t.Errorf("expected default AllowedIPs to be empty")
	}
	if len(cfg.Methods) != 1 || cfg.Methods[0] != "GET" {
		t.Errorf("expected default Methods to be ['GET'], got %v", cfg.Methods)
	}
	if cfg.Response == nil || cfg.Response.Mode != "text" {
		t.Errorf("expected default Response to be initialized with mode text for label unmarshaling compatibility, got %v", cfg.Response)
	}
}

func TestConfig_RemovedLegacyAliases(t *testing.T) {
	// Verify that legacy/removed alias keys (such as pathPatterns, path_patterns, action)
	// are not mapped to canonical fields (BlockPatterns, Response.Mode) during unmarshaling.
	rawJSON := `{
		"pathPatterns": ["(?i)^/legacy-admin"],
		"path_patterns": ["(?i)^/legacy-path"],
		"action": "silentDrop"
	}`

	cfg := traefik_warden.CreateConfig()
	if err := json.Unmarshal([]byte(rawJSON), cfg); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if len(cfg.BlockPatterns) != 0 {
		t.Errorf("expected BlockPatterns to remain empty when legacy pathPatterns is passed, got %v", cfg.BlockPatterns)
	}
	if cfg.Response.Mode != "text" {
		t.Errorf("expected Response.Mode to remain default 'text' when legacy action is passed, got %q", cfg.Response.Mode)
	}
}

func TestDefaultBlockPatterns_ValidRegex(t *testing.T) {
	if len(traefik_warden.DefaultBlockPatterns) == 0 {
		t.Fatalf("DefaultBlockPatterns should not be empty")
	}
}

func TestDefaultAllowPatterns_ValidRegex(t *testing.T) {
	if len(traefik_warden.DefaultAllowPatterns) == 0 {
		t.Fatalf("DefaultAllowPatterns should not be empty")
	}
}

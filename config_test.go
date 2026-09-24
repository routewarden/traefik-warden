package traefik_warden_test

import (
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

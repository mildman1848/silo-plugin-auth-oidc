package provider

import (
	"testing"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestConfigFromEntries(t *testing.T) {
	value, err := structpb.NewStruct(map[string]any{
		"issuer_url":         "https://auth.example.test",
		"client_id":          "silo",
		"client_secret":      "secret",
		"scopes":             "openid profile email groups",
		"subject_claim":      "sub",
		"email_claim":        "mail",
		"display_name_claim": "preferred_username",
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := configFromEntries([]*pluginv1.ConfigEntry{{Key: "oidc", Value: value}})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IssuerURL != "https://auth.example.test" || cfg.ClientID != "silo" || cfg.ClientSecret != "secret" {
		t.Fatalf("unexpected config: %#v", cfg)
	}
	if len(cfg.Scopes) != 4 || cfg.EmailClaim != "mail" || cfg.DisplayNameClaim != "preferred_username" {
		t.Fatalf("unexpected optional config: %#v", cfg)
	}
}

func TestProviderStateValue(t *testing.T) {
	state, err := structpb.NewStruct(map[string]any{"code_verifier": "verifier-1"})
	if err != nil {
		t.Fatal(err)
	}
	if got := providerStateValue(state, "code_verifier"); got != "verifier-1" {
		t.Fatalf("providerStateValue = %q", got)
	}
}

package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAuthorizeURLIncludesPKCEAndScopes(t *testing.T) {
	client := &Client{
		cfg:       Config{ClientID: "silo", Scopes: []string{"openid", "profile", "email"}},
		discovery: Discovery{AuthorizationEndpoint: "https://idp.example.test/oauth2/authorize"},
	}
	got, err := client.AuthorizeURL("https://silo.example.test/callback", "state-1", "verifier-1")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("response_type") != "code" || q.Get("client_id") != "silo" || q.Get("state") != "state-1" {
		t.Fatalf("unexpected authorize params: %s", got)
	}
	if q.Get("scope") != "openid profile email" {
		t.Fatalf("scope = %q", q.Get("scope"))
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Fatalf("missing PKCE params: %s", got)
	}
}

func TestExchangeCodeUsesTokenAndUserinfoEndpoints(t *testing.T) {
	var gotTokenBody string
	var gotTokenUser, gotTokenPassword string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			gotTokenBody = string(body)
			gotTokenUser, gotTokenPassword, _ = r.BasicAuth()
			_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: "access-token", TokenType: "Bearer"})
		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer access-token" {
				t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(UserInfo{"sub": "user-1", "email": "user@example.test", "name": "User One"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := &Client{
		cfg:        Config{ClientID: "silo", ClientSecret: "secret", Scopes: []string{"openid"}, SubjectClaim: "sub", EmailClaim: "email", DisplayNameClaim: "name"},
		discovery:  Discovery{TokenEndpoint: server.URL + "/token", UserinfoEndpoint: server.URL + "/userinfo"},
		httpClient: server.Client(),
	}
	info, err := client.ExchangeCode(context.Background(), "code-1", "https://silo/callback", "verifier-1")
	if err != nil {
		t.Fatal(err)
	}
	if info["sub"] != "user-1" {
		t.Fatalf("userinfo = %#v", info)
	}
	if gotTokenUser != "silo" || gotTokenPassword != "secret" {
		t.Fatalf("token BasicAuth = %q/%q", gotTokenUser, gotTokenPassword)
	}
	if strings.Contains(gotTokenBody, "client_secret=") || !strings.Contains(gotTokenBody, "code_verifier=verifier-1") {
		t.Fatalf("token body should contain PKCE verifier but not client_secret: %s", gotTokenBody)
	}
}

func TestClaimsToIdentityFallbacks(t *testing.T) {
	client := &Client{cfg: Config{SubjectClaim: "sub", EmailClaim: "email", DisplayNameClaim: "name"}}
	sub, display, email := client.ClaimsToIdentity(UserInfo{"sub": "u1", "email": "u@example.test", "preferred_username": "philipp"})
	if sub != "u1" || display != "philipp" || email != "u@example.test" {
		t.Fatalf("identity = %q %q %q", sub, display, email)
	}
}

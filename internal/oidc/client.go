package oidc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	IssuerURL        string
	ClientID         string
	ClientSecret     string
	Scopes           []string
	SubjectClaim     string
	EmailClaim       string
	DisplayNameClaim string
}

type Discovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	Issuer                string `json:"issuer"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type UserInfo map[string]any

type Client struct {
	cfg        Config
	discovery  Discovery
	httpClient *http.Client
}

func New(ctx context.Context, cfg Config) (*Client, error) {
	cfg.IssuerURL = strings.TrimRight(strings.TrimSpace(cfg.IssuerURL), "/")
	cfg.ClientID = strings.TrimSpace(cfg.ClientID)
	cfg.ClientSecret = strings.TrimSpace(cfg.ClientSecret)
	cfg.SubjectClaim = defaultString(cfg.SubjectClaim, "sub")
	cfg.EmailClaim = defaultString(cfg.EmailClaim, "email")
	cfg.DisplayNameClaim = defaultString(cfg.DisplayNameClaim, "name")
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}
	if cfg.IssuerURL == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("issuer_url, client_id, and client_secret are required")
	}
	client := &Client{cfg: cfg, httpClient: &http.Client{Timeout: 20 * time.Second}}
	disc, err := client.discover(ctx)
	if err != nil {
		return nil, err
	}
	client.discovery = disc
	return client, nil
}

func (c *Client) AuthorizeURL(redirectURI, state, verifier string) (string, error) {
	if strings.TrimSpace(redirectURI) == "" || strings.TrimSpace(state) == "" || strings.TrimSpace(verifier) == "" {
		return "", errors.New("redirect_uri, state, and code verifier are required")
	}
	challenge := codeChallenge(verifier)
	u, err := url.Parse(c.discovery.AuthorizationEndpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", c.cfg.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(c.cfg.Scopes, " "))
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (c *Client) ExchangeCode(ctx context.Context, code, redirectURI, verifier string) (UserInfo, error) {
	values := url.Values{}
	values.Set("grant_type", "authorization_code")
	values.Set("code", strings.TrimSpace(code))
	values.Set("redirect_uri", strings.TrimSpace(redirectURI))
	values.Set("client_id", c.cfg.ClientID)
	values.Set("client_secret", c.cfg.ClientSecret)
	values.Set("code_verifier", strings.TrimSpace(verifier))
	var token TokenResponse
	if err := c.doForm(ctx, c.discovery.TokenEndpoint, values, &token); err != nil {
		return nil, err
	}
	if strings.TrimSpace(token.AccessToken) == "" {
		return nil, errors.New("OIDC token response did not include an access_token")
	}
	userinfoEndpoint := strings.TrimSpace(c.discovery.UserinfoEndpoint)
	if userinfoEndpoint == "" {
		claims, err := decodeJWTClaims(token.IDToken)
		if err != nil {
			return nil, errors.New("OIDC provider has no userinfo endpoint and id_token claims could not be decoded")
		}
		return claims, nil
	}
	return c.UserInfo(ctx, token.AccessToken)
}

func (c *Client) UserInfo(ctx context.Context, accessToken string) (UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.discovery.UserinfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(accessToken))
	var info UserInfo
	if err := c.do(req, &info); err != nil {
		return nil, err
	}
	return info, nil
}

func (c *Client) ClaimsToIdentity(info UserInfo) (subject, displayName, email string) {
	subject = claimString(info, c.cfg.SubjectClaim)
	displayName = claimString(info, c.cfg.DisplayNameClaim)
	email = claimString(info, c.cfg.EmailClaim)
	if displayName == "" {
		displayName = claimString(info, "preferred_username")
	}
	if displayName == "" {
		displayName = email
	}
	if displayName == "" {
		displayName = subject
	}
	return subject, displayName, email
}

func (c *Client) discover(ctx context.Context) (Discovery, error) {
	discoveryURL := c.cfg.IssuerURL + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return Discovery{}, err
	}
	req.Header.Set("Accept", "application/json")
	var disc Discovery
	if err := c.do(req, &disc); err != nil {
		return Discovery{}, fmt.Errorf("OIDC discovery failed: %w", err)
	}
	if disc.AuthorizationEndpoint == "" || disc.TokenEndpoint == "" {
		return Discovery{}, errors.New("OIDC discovery document is missing authorization_endpoint or token_endpoint")
	}
	return disc, nil
}

func (c *Client) doForm(ctx context.Context, endpoint string, values url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.do(req, out)
}

func (c *Client) do(req *http.Request, out any) error {
	res, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("OIDC endpoint returned %d", res.StatusCode)
	}
	if out == nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode OIDC response: %w", err)
	}
	return nil
}

func NewCodeVerifier() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func codeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func decodeJWTClaims(token string) (UserInfo, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, errors.New("invalid jwt")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims UserInfo
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func claimString(info UserInfo, key string) string {
	if info == nil || strings.TrimSpace(key) == "" {
		return ""
	}
	value, ok := info[key]
	if !ok || value == nil {
		return ""
	}
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return fmt.Sprintf("%.0f", v)
	case int:
		return fmt.Sprintf("%d", v)
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

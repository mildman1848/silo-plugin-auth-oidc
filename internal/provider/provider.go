package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/mildman1848/silo-plugin-auth-oidc/internal/oidc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

type OIDCProvider struct {
	pluginv1.UnimplementedAuthProviderServer
	mu  sync.RWMutex
	cfg oidc.Config
}

func (p *OIDCProvider) Configure(entries []*pluginv1.ConfigEntry) error {
	cfg, err := configFromEntries(entries)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.cfg = cfg
	p.mu.Unlock()
	return nil
}

func (p *OIDCProvider) Authenticate(context.Context, *pluginv1.AuthenticateRequest) (*pluginv1.AuthenticateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "OIDC password authentication is not supported; use OAuth/OIDC login")
}

func (p *OIDCProvider) InitAuthorize(ctx context.Context, req *pluginv1.InitAuthorizeRequest) (*pluginv1.InitAuthorizeResponse, error) {
	client, err := oidc.New(ctx, p.config())
	if err != nil {
		return nil, safeInvalidArgument(err)
	}
	verifier, err := oidc.NewCodeVerifier()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to create OIDC PKCE verifier")
	}
	authorizeURL, err := client.AuthorizeURL(req.GetRedirectUri(), req.GetState(), verifier)
	if err != nil {
		return nil, safeInvalidArgument(err)
	}
	stateStruct, err := structpb.NewStruct(map[string]any{"code_verifier": verifier})
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to encode OIDC provider state")
	}
	return &pluginv1.InitAuthorizeResponse{AuthorizeUrl: authorizeURL, ProviderState: stateStruct}, nil
}

func (p *OIDCProvider) ExchangeCode(ctx context.Context, req *pluginv1.ExchangeCodeRequest) (*pluginv1.AuthenticateResponse, error) {
	client, err := oidc.New(ctx, p.config())
	if err != nil {
		return nil, safeInvalidArgument(err)
	}
	verifier := providerStateValue(req.GetProviderState(), "code_verifier")
	if verifier == "" {
		return nil, safeInvalidArgument(errors.New("missing OIDC PKCE verifier"))
	}
	info, err := client.ExchangeCode(ctx, req.GetCode(), req.GetRedirectUri(), verifier)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "OIDC code exchange failed")
	}
	subject, displayName, email := client.ClaimsToIdentity(info)
	if strings.TrimSpace(subject) == "" {
		return nil, status.Error(codes.Unauthenticated, "OIDC response did not include a subject claim")
	}
	claimsStruct, err := structpb.NewStruct(map[string]any(info))
	if err != nil {
		claimsStruct = nil
	}
	return &pluginv1.AuthenticateResponse{
		ExternalSubject: subject,
		DisplayName:     displayName,
		Email:           email,
		Claims:          claimsStruct,
	}, nil
}

func (p *OIDCProvider) RefreshSession(context.Context, *pluginv1.RefreshSessionRequest) (*pluginv1.AuthenticateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "OIDC session refresh is not implemented")
}

func (p *OIDCProvider) config() oidc.Config {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cfg
}

func configFromEntries(entries []*pluginv1.ConfigEntry) (oidc.Config, error) {
	values := map[string]string{}
	for _, entry := range entries {
		if entry == nil || entry.GetKey() != "oidc" || entry.GetValue() == nil {
			continue
		}
		for k, v := range entry.GetValue().AsMap() {
			if s := strings.TrimSpace(toString(v)); s != "" {
				values[k] = s
			}
		}
	}
	scopes := strings.Fields(first(values["scopes"], "openid profile email"))
	return oidc.Config{
		IssuerURL:        values["issuer_url"],
		ClientID:         values["client_id"],
		ClientSecret:     values["client_secret"],
		Scopes:           scopes,
		SubjectClaim:     first(values["subject_claim"], "sub"),
		EmailClaim:       first(values["email_claim"], "email"),
		DisplayNameClaim: first(values["display_name_claim"], "name"),
	}, nil
}

func providerStateValue(state *structpb.Struct, key string) string {
	if state == nil {
		return ""
	}
	return strings.TrimSpace(toString(state.AsMap()[key]))
}

func toString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case fmt.Stringer:
		return v.String()
	case nil:
		return ""
	default:
		return ""
	}
}

func first(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func safeInvalidArgument(err error) error {
	if err == nil {
		return nil
	}
	return status.Error(codes.InvalidArgument, err.Error())
}

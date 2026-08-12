# silo-plugin-auth-oidc

Generic Silo `auth_provider.v1` plugin for OAuth2/OIDC SSO.

## Scope

Supported in v1:

- OIDC discovery from `issuer_url`
- Authorization Code flow
- Client secret token exchange
- Userinfo claim lookup
- Silo auto-provisioning / identity binding through `auth_provider.v1`

Designed for:

- Authelia
- Authentik
- Keycloak
- other standard OIDC providers

Not supported in v1:

- LDAP direct bind
- SAML
- group-to-role mapping
- refresh-session handling

## Silo config

Install the plugin, configure the global OIDC settings, then enable the auth binding in Silo Admin → Plugins.

Keep a local admin recovery login until SSO has been verified.

## Build

```bash
go test ./...
go build -ldflags "-X main.version=0.1.0" -o bin/silo-plugin-auth-oidc .
./bin/silo-plugin-auth-oidc manifest
```

## License

AGPL-3.0-or-later.

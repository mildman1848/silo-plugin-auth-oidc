# silo-plugin-auth-oidc

Generic Silo `auth_provider.v1` plugin for OAuth2/OIDC SSO.

## Scope

Supported in v1:

- OIDC discovery from `issuer_url`
- Authorization Code flow
- Client secret token exchange using HTTP Basic authentication
- Userinfo claim lookup, with ID-token claim fallback when no userinfo endpoint exists
- Silo auto-provisioning / identity binding through `auth_provider.v1`
- Pre-linking existing local Silo users to an OIDC subject via `scripts/link-existing-user.sh`

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

### Existing-user mapping

Silo stores OAuth/OIDC account links in `plugin_auth_identities`:

```text
plugin_installation_id + external_subject -> users.id
```

The plugin returns `external_subject` from the configured OIDC subject claim. By default this is `sub`. For Authelia that is often a stable opaque subject, not necessarily the visible username. If you set `subject_claim=preferred_username`, the external subject can be `philipp`, but changing the subject claim after users have already logged in changes identity matching. That is technically possible. Whether it is wise is another matter.

Recommended approach:

1. Decide the OIDC claim Silo should treat as `external_subject` before first SSO login.
2. Best practice is a stable opaque `sub`; pragmatic migrations can use `preferred_username` when existing local Silo usernames already match SSO usernames.
3. Configure `subject_claim` accordingly. For Authelia + existing local user `philipp`, use `preferred_username` and map `external_subject=philipp`.
4. Link the existing Silo user to that subject before enabling broad auto-provisioning.
5. Verify the mapped login lands in the existing account, not a newly created one.

Use the included helper script from an environment that can run `psql` against the Silo database:

```bash
# Dry-run: resolves the Silo user and OIDC plugin installation, but does not write.
PSQL_COMMAND='docker compose exec -T postgres psql -U silo -d silo' \
  scripts/link-existing-user.sh \
  --user philipp \
  --external-subject '<oidc-sub-from-userinfo-or-id-token>'

# Apply after reviewing the dry-run output.
PSQL_COMMAND='docker compose exec -T postgres psql -U silo -d silo' \
  scripts/link-existing-user.sh \
  --user philipp \
  --external-subject '<oidc-sub-from-userinfo-or-id-token>' \
  --apply
```

By default the script resolves the OIDC plugin installation dynamically from `plugin_id` (`mildman1848.oidc`). If multiple OIDC plugin installations exist, pass the actual installation id shown by Silo or queried from `plugin_installations`:

```bash
PSQL_COMMAND='docker compose exec -T postgres psql -U silo -d silo' \
  scripts/link-existing-user.sh \
  --user philipp \
  --external-subject '<oidc-sub>' \
  --plugin-installation-id '<actual-installation-id>' \
  --apply
```

The script is idempotent: it uses the Silo unique key on `(plugin_installation_id, external_subject)` and updates `user_id` if the mapping already exists.

Security notes:

- Make a DB backup first.
- Do not paste raw OIDC tokens into logs or chat.
- Leave local admin recovery enabled until at least one SSO login has been tested.
- Prefer linking known existing users over turning on auto-provisioning blindly.

## Build

```bash
go test ./...
go build -ldflags "-X main.version=0.1.4" -o bin/silo-plugin-auth-oidc .
./bin/silo-plugin-auth-oidc manifest
```

## License

AGPL-3.0-or-later.

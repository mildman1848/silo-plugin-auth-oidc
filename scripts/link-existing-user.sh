#!/usr/bin/env bash
set -euo pipefail

# Link an existing local Silo user to an OIDC external subject.
# The script is intentionally host-agnostic: set PSQL_COMMAND to your psql wrapper
# if the database is only reachable through docker compose.
#
# Examples:
#   PSQL_COMMAND='docker compose exec -T postgres psql -U silo -d silo' \
#     scripts/link-existing-user.sh --user philipp --external-subject philipp --apply
#
#   PSQL_COMMAND='docker exec -i silo-postgres psql -U silo -d silo' \
#     scripts/link-existing-user.sh --user philipp --external-subject '<oidc-sub>' --plugin-installation-id 11 --apply

usage() {
  cat <<'USAGE'
Usage:
  link-existing-user.sh --user <username-or-email> --external-subject <subject> [options]

Options:
  --plugin-installation-id <id>  Use a specific OIDC plugin installation id.
  --plugin-id <id>              Plugin id to auto-detect. Default: mildman1848.oidc
  --apply                       Write the mapping. Without this, the script runs a dry-run.
  -h, --help                    Show this help.

Environment:
  PSQL_COMMAND                  Command used to run psql. Default: psql -U silo -d silo

Safety:
  - Dry-run by default.
  - Fails if the local user cannot be found exactly by username/email.
  - Fails if the OIDC plugin installation cannot be detected uniquely.
  - Uses ON CONFLICT on (plugin_installation_id, external_subject), so re-runs are idempotent.
USAGE
}

USER_LOOKUP=""
EXTERNAL_SUBJECT=""
PLUGIN_INSTALLATION_ID=""
PLUGIN_ID="mildman1848.oidc"
APPLY="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)
      USER_LOOKUP="${2:-}"; shift 2 ;;
    --external-subject)
      EXTERNAL_SUBJECT="${2:-}"; shift 2 ;;
    --plugin-installation-id)
      PLUGIN_INSTALLATION_ID="${2:-}"; shift 2 ;;
    --plugin-id)
      PLUGIN_ID="${2:-}"; shift 2 ;;
    --apply)
      APPLY="true"; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2 ;;
  esac
done

if [[ -z "$USER_LOOKUP" || -z "$EXTERNAL_SUBJECT" ]]; then
  echo "--user and --external-subject are required" >&2
  usage >&2
  exit 2
fi

if [[ "$EXTERNAL_SUBJECT" =~ ^[[:space:]]*$ ]]; then
  echo "External subject must not be blank" >&2
  exit 2
fi

PSQL_COMMAND="${PSQL_COMMAND:-psql -U silo -d silo}"
TMP_SQL="$(mktemp)"
trap 'rm -f "$TMP_SQL"' EXIT

cat >"$TMP_SQL" <<'SQL'
\set ON_ERROR_STOP on

BEGIN;

CREATE TEMP TABLE _silo_oidc_link_input AS
SELECT
  NULLIF(:'plugin_installation_id', '')::bigint AS requested_installation_id,
  NULLIF(:'plugin_id', '')::text AS plugin_id,
  :'user_lookup'::text AS user_lookup,
  :'external_subject'::text AS external_subject,
  (:'apply' = 'true') AS apply;

CREATE TEMP TABLE _silo_oidc_link_user AS
SELECT u.id, u.username, u.email, u.enabled
FROM public.users u, _silo_oidc_link_input i
WHERE u.username::text = i.user_lookup OR u.email::text = i.user_lookup;

DO $$
DECLARE
  user_count integer;
BEGIN
  SELECT count(*) INTO user_count FROM _silo_oidc_link_user;
  IF user_count <> 1 THEN
    RAISE EXCEPTION 'Expected exactly one Silo user for %, found %', (SELECT user_lookup FROM _silo_oidc_link_input), user_count;
  END IF;
END $$;

CREATE TEMP TABLE _silo_oidc_link_installation AS
SELECT pi.id, pi.plugin_id, pi.version, pi.enabled
FROM public.plugin_installations pi, _silo_oidc_link_input i
WHERE (i.requested_installation_id IS NOT NULL AND pi.id = i.requested_installation_id)
   OR (i.requested_installation_id IS NULL AND pi.plugin_id = i.plugin_id);

DO $$
DECLARE
  installation_count integer;
BEGIN
  SELECT count(*) INTO installation_count FROM _silo_oidc_link_installation;
  IF installation_count <> 1 THEN
    RAISE EXCEPTION 'Expected exactly one OIDC plugin installation, found %. Pass --plugin-installation-id.', installation_count;
  END IF;
END $$;

\echo 'Resolved mapping:'
SELECT
  i.id AS plugin_installation_id,
  i.plugin_id,
  u.id AS user_id,
  u.username,
  u.email,
  x.external_subject,
  CASE WHEN x.apply THEN 'apply' ELSE 'dry-run' END AS mode
FROM _silo_oidc_link_installation i
CROSS JOIN _silo_oidc_link_user u
CROSS JOIN _silo_oidc_link_input x;

INSERT INTO public.plugin_auth_identities (
  plugin_installation_id,
  external_subject,
  user_id,
  created_at,
  updated_at
)
SELECT i.id, x.external_subject, u.id, NOW(), NOW()
FROM _silo_oidc_link_installation i
CROSS JOIN _silo_oidc_link_user u
CROSS JOIN _silo_oidc_link_input x
WHERE x.apply
ON CONFLICT (plugin_installation_id, external_subject)
DO UPDATE SET
  user_id = EXCLUDED.user_id,
  updated_at = NOW();

\echo 'Current identity row:'
SELECT ai.id, ai.plugin_installation_id, pi.plugin_id, ai.external_subject, ai.user_id, u.username, u.email, ai.updated_at
FROM public.plugin_auth_identities ai
JOIN public.plugin_installations pi ON pi.id = ai.plugin_installation_id
JOIN public.users u ON u.id = ai.user_id
JOIN _silo_oidc_link_input x ON x.external_subject = ai.external_subject
JOIN _silo_oidc_link_installation i ON i.id = ai.plugin_installation_id;

COMMIT;
SQL

# Feed SQL through stdin so PSQL_COMMAND can point at a containerized psql
# (`docker compose exec -T ... psql`). A host-side temp file path would not exist
# inside the container.
# shellcheck disable=SC2086
$PSQL_COMMAND \
  -v user_lookup="$USER_LOOKUP" \
  -v external_subject="$EXTERNAL_SUBJECT" \
  -v plugin_id="$PLUGIN_ID" \
  -v plugin_installation_id="$PLUGIN_INSTALLATION_ID" \
  -v apply="$APPLY" \
  < "$TMP_SQL"

if [[ "$APPLY" != "true" ]]; then
  echo
  echo "Dry-run only. Re-run with --apply after reviewing the resolved mapping." >&2
fi

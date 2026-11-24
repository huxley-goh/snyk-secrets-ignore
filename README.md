# Snyk Secrets Ignore Report

Lists the **open Snyk Secrets issues** in an Organization and shows which ones are covered by an active ignore policy.

- **Table 1:** open Secrets *with* an active ignore policy (ignore type, reason, expiry, review status, policy ID)
- **Table 2:** open Secrets *without* an active ignore policy (with a note if an ignore exists but is expired, rejected or pending)

Each row shows severity, secret, repository, integration (`CLI` or `SCM (<origin>)`), project name and file location. Resolved issues are excluded.

## How it works

Three paginated REST API calls run in parallel:

| Endpoint | Used for |
| --- | --- |
| `GET /orgs/{org_id}/policies` | `conditions_group.conditions[].value` is the finding UUID |
| `GET /orgs/{org_id}/issues?type=secrets` | `attributes.key_asset` is matched to the finding UUID |
| `GET /orgs/{org_id}/projects?expand=target` | project name, repository and origin |

An ignore is **active** if its review is `approved` or `not-required` and it has not expired.

## Requirements

- [uv](https://docs.astral.sh/uv/) (installs Python 3.11+ and `requests` automatically)
- A Snyk API token with access to the Org (a service account token is recommended)

## Usage

```bash
export SNYK_TOKEN=<your-token>
uv run snyk_secrets_ignores.py --org-id <ORG_UUID>
```

| Option | Description |
| --- | --- |
| `--org-id` | Organization ID (UUID). Required. |
| `--region` | `US` (default), `US2`, `EU` or `AU`. Must match your token's region. |
| `--version` | REST API version (default `2026-09-09`). |
| `--width N` | Table width in columns (default: terminal width). |
| `--csv` | Also write `secrets_ignores.csv` in the current folder (both tables, with a `group` column). |
| `--json` | Also write `secrets_ignores.json` in the current folder. |

## Troubleshooting

- **HTTP 401:** the token is invalid or for a different region. Set `--region` to match.
- **HTTP 403/404:** the token lacks access to the Org, or the Org ID is wrong.
- **`uv` certificate error:** try `uv run --system-certs ...`.
- **Cells wrap heavily:** use a wider terminal or `--width`, or read the CSV/JSON output.

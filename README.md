# Snyk Secrets Ignore Report

Shows which **open** Snyk Secrets issues in an Org are covered by an active ignore policy, and can create an ignore for one.

- **Table 1:** open Secrets *with* an active ignore (type, reason, expiry, review, policy ID)
- **Table 2:** open Secrets *without* one (the Note column says if an ignore exists but is expired, rejected or pending)

Rows show severity, secret, repository, integration (`CLI` or `SCM (<origin>)`), project and file location. Resolved issues are excluded. An ignore is *active* if its review is `approved` or `not-required` and it has not expired.

## Requirements

- [uv](https://docs.astral.sh/uv/) (installs Python 3.11+ and `requests` automatically)
- A Snyk API token with access to the Org (`SNYK_TOKEN`)

## Report

```bash
export SNYK_TOKEN=<your-token>
uv run snyk_secrets_ignores.py --org-id <ORG_UUID>
```

| Option | Description |
| --- | --- |
| `--org-id` | **Required.** Organization ID (UUID). |
| `--region` | `US` (default), `US2`, `EU` or `AU`. Must match the token's region. |
| `--version` | REST API version (default `2026-09-09`). |
| `--width N` | Table width (default: terminal width). |
| `--csv`, `--json` | Also write `secrets_ignores.csv` / `secrets_ignores.json` in the current folder. |

## Create an ignore

```bash
uv run snyk_secrets_ignores.py --org-id <ORG_UUID> --ignore <ID> --reason "Test fixture"
```

| Parameter | Required | Description |
| --- | --- | --- |
| `SNYK_TOKEN` | Yes | Environment variable; token must be able to create policies. |
| `--org-id` | Yes | Organization ID (UUID). |
| `--ignore ID` | Yes | The *Issue ID* from Table 2, or the `finding_id` from the CSV/JSON output. |
| `--expires YYYY-MM-DD` | With `temporary-ignore` | Future date. |
| `--ignore-type` | No | `wont-fix` (default), `temporary-ignore` or `not-vulnerable`. |
| `--reason`, `--name` | No | Reason, and policy name (default `Ignore secret: <title>`). |
| `--yes` | No | Skip the `[y/N]` prompt (needed when not in an interactive terminal). |

The script checks the finding is a Secrets issue in the Org with no active ignore, shows what will be ignored, asks for confirmation, then creates the policy. If your Org requires approval the ignore is `pending` until approved. The create call is never retried.

Long IDs can wrap in a narrow table: widen the terminal, use `--width`, or copy from the `--json` output.

## Troubleshooting

- **HTTP 401:** invalid token or wrong `--region`.
- **HTTP 403/404:** the token lacks access to the Org, or the Org ID is wrong.
- **`uv` certificate error:** use `uv run --system-certs ...`.
- **"No Secrets issue ... matches":** the ID is not an issue ID or `key_asset` in that Org.

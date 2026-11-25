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

## APIs used

All calls are [Snyk REST API](https://docs.snyk.io/snyk-api) requests to `https://api.<region>.snyk.io/rest` (auth: `Authorization: token $SNYK_TOKEN`, results paged with `limit=100` and `links.next` until exhausted). The three reads run in parallel.

| API | Endpoint | Used for |
| --- | --- | --- |
| Issues | `GET /orgs/{org_id}/issues?type=secrets` | Secrets issues: `id`, `status`, `title`, severity, file location, `key_asset`, and the project (`relationships.scan_item`). |
| Policies | `GET /orgs/{org_id}/policies` | Existing policies: ignore type, reason, expiry, `review` status, and the finding UUID in `conditions_group.conditions[].value`. |
| Projects | `GET /orgs/{org_id}/projects?expand=target` | Project name, repository (target) and `origin` (CLI vs SCM). |
| Policies (create) | `POST /orgs/{org_id}/policies` | Only with `--ignore`: creates the ignore policy. |

### How an issue is mapped to its ignore

```
Issue (id)  ──key_asset──▶  finding UUID  ◀──conditions[].value──  Ignore policy
                                                  (field snyk/asset/finding/v1)
Issue ──scan_item──▶ project id ──▶ Projects API ──▶ project name, repository, integration
```

1. **Issue → asset:** each Secrets issue has an `id` (the *Issue ID*) and an `attributes.key_asset`, which is the finding UUID that identifies the secret.
2. **Asset → policy:** an ignore policy targets a finding through a condition with field `snyk/asset/finding/v1`, operator `includes`, and the finding UUID as its `value`. The script indexes every policy by those values and looks up each issue's `key_asset`.
3. **Active check:** a matching policy counts as active only if `review` is `approved` or `not-required` and it has not expired. Otherwise the issue lands in Table 2 with a note.

`--ignore <ID>` runs the same lookup in reverse: it resolves the Issue ID (or the finding UUID) to the issue's `key_asset`, then `POST`s a policy whose condition `value` is that UUID, so the next report maps the issue to it.

## Troubleshooting

- **HTTP 401:** invalid token or wrong `--region`.
- **HTTP 403/404:** the token lacks access to the Org, or the Org ID is wrong.
- **`uv` certificate error:** use `uv run --system-certs ...`.
- **"No Secrets issue ... matches":** the ID is not an issue ID or `key_asset` in that Org.

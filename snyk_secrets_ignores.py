#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "requests>=2.31",
# ]
# ///
"""
Snyk Secrets report for one Organization: which Secrets findings are covered by an
active ignore policy, and which are not.

Fetched in parallel
-------------------
* GET /rest/orgs/{org_id}/policies          -> conditions_group.conditions[].value = finding UUID
* GET /rest/orgs/{org_id}/issues?type=secrets -> attributes.key_asset = finding UUID
* GET /rest/orgs/{org_id}/projects          -> project id -> project name

Every list is paginated via links.next until exhausted.

Output
------
Table 1  OPEN Secrets WITH an active ignore policy   (issue joined to its policy)
Table 2  OPEN Secrets WITHOUT an active ignore policy

"Active" means the policy is not expired and its review status is `approved` or
`not-required`. A matching policy that is expired, rejected or still pending review
does not suppress the finding, so that finding lands in Table 2 with a note saying why.
Resolved issues are excluded everywhere, and policies matching no open Secrets issue are ignored.

Usage
-----
    export SNYK_TOKEN=<personal access token or service account token>
    uv run snyk_secrets_ignores.py --org-id <ORG_UUID>
    uv run snyk_secrets_ignores.py --org-id <ORG_UUID> --region EU --csv --json
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import sys
import textwrap
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from urllib.parse import quote

import requests

REGIONS = {
    "US": "https://api.snyk.io",  # SNYK-US-01
    "US2": "https://api.us.snyk.io",  # SNYK-US-02
    "EU": "https://api.eu.snyk.io",  # SNYK-EU-01
    "AU": "https://api.au.snyk.io",  # SNYK-AU-01
}
FINDING_FIELD = "snyk/asset/finding/v1"
DEFAULT_VERSION = "2026-09-09"
CSV_NAME = "secrets_ignores.csv"
JSON_NAME = "secrets_ignores.json"
PAGE_LIMIT = 100  # max allowed by these endpoints
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
EFFECTIVE_REVIEWS = {"approved", "not-required"}
SCM_ORIGINS = {
    "github", "github-cloud-app", "github-enterprise", "github-server-app",
    "gitlab", "bitbucket-cloud", "bitbucket-server", "bitbucket-connect-app", "azure-repos",
}


# --------------------------------------------------------------------------- HTTP
def make_session(token: str) -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "Authorization": f"token {token}",
            "Content-Type": "application/vnd.api+json",
            "Accept": "application/vnd.api+json",
        }
    )
    return s


def get_json(session: requests.Session, url: str, params: dict | None = None) -> dict:
    """GET with simple retry on 429 / 5xx."""
    for attempt in range(6):
        resp = session.get(url, params=params, timeout=60)
        if resp.status_code == 429 or resp.status_code >= 500:
            wait = int(resp.headers.get("Retry-After", 2 ** attempt))
            print(f"  ... HTTP {resp.status_code}, retrying in {wait}s", file=sys.stderr)
            time.sleep(wait)
            continue
        if not resp.ok:
            sys.exit(f"HTTP {resp.status_code} for {resp.url}\n{resp.text[:1000]}")
        return resp.json()
    sys.exit(f"Giving up after repeated failures for {url}")


def next_url(body: dict, host: str) -> str | None:
    """Resolve links.next (string or {href}) to an absolute URL on the Snyk host."""
    nxt = (body.get("links") or {}).get("next")
    if isinstance(nxt, dict):
        nxt = nxt.get("href")
    if not nxt:
        return None
    if nxt.startswith("http"):
        # Never send the API token to a host other than the configured Snyk region.
        if not nxt.startswith(host + "/rest/"):
            sys.exit(f"Refusing to follow pagination link to unexpected host: {nxt}")
        return nxt
    if not nxt.startswith("/"):
        sys.exit(f"Unexpected pagination link: {nxt}")
    if not nxt.startswith("/rest/"):
        nxt = "/rest" + nxt  # docs show relative links without the /rest prefix
    return host + nxt


def paginate(session: requests.Session, host: str, path: str, params: dict) -> Iterator[dict]:
    """Yield every resource in data[], following links.next until exhausted."""
    url: str | None = f"{host}/rest{path}"
    first = True
    page = 0
    while url:
        body = get_json(session, url, params if first else None)
        first = False
        page += 1
        data = body.get("data") or []
        print(f"  {path.rsplit('/', 1)[-1]} page {page}: {len(data)} records", file=sys.stderr)
        yield from data
        url = next_url(body, host)


def integration_label(origin: str | None) -> str:
    """CLI vs SCM (with the concrete origin), e.g. 'SCM (github-cloud-app)'."""
    if not origin:
        return "-"
    if origin == "cli":
        return "CLI"
    if origin in SCM_ORIGINS:
        return f"SCM ({origin})"
    return origin


def project_info(project: dict) -> dict:
    """Project name, repository (target display name), repo URL and onboarding integration."""
    attrs = project.get("attributes") or {}
    name = attrs.get("name") or project.get("id")
    target = (((project.get("relationships") or {}).get("target") or {}).get("data") or {})
    tattrs = target.get("attributes") or {}
    return {
        "name": name,
        # Target display name is the repo ("owner/repo"); fall back to the part of the
        # project name before ':' (SCM projects are named "owner/repo:path").
        "repository": tattrs.get("display_name") or str(name).split(":", 1)[0],
        "repository_url": tattrs.get("url") or "-",
        "origin": attrs.get("origin") or "-",
        "integration": integration_label(attrs.get("origin")),
    }


def fetch_all(token: str, host: str, org_id: str, version: str) -> tuple[list, list, dict]:
    """Fetch policies, Secrets issues and projects concurrently; return once all are done."""
    org = quote(str(uuid.UUID(org_id)), safe="")  # percent-encoded canonical UUID: cannot alter the URL path
    base = {"version": version, "limit": PAGE_LIMIT}
    jobs = {
        "policies": (f"/orgs/{org}/policies", base),
        "issues": (f"/orgs/{org}/issues", {**base, "type": "secrets"}),
        "projects": (f"/orgs/{org}/projects", {**base, "expand": "target"}),
    }
    # One Session per thread: requests.Session is not guaranteed to be thread-safe.
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = {
            name: pool.submit(lambda p=path, q=params: list(paginate(make_session(token), host, p, q)))
            for name, (path, params) in jobs.items()
        }
        results = {name: f.result() for name, f in futures.items()}  # re-raises on failure
    projects = {p["id"]: project_info(p) for p in results["projects"]}
    return results["policies"], results["issues"], projects


# --------------------------------------------------------------------------- data
def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def day(value: str | None) -> str:
    dt = parse_ts(value)
    return dt.strftime("%Y-%m-%d") if dt else (value or "-")


def finding_ids(policy: dict) -> list[str]:
    """conditions_group.conditions[].value for the finding field."""
    group = (policy.get("attributes") or {}).get("conditions_group") or {}
    return [
        c["value"]
        for c in group.get("conditions", [])
        if c.get("field") == FINDING_FIELD and c.get("value")
    ]


def policy_state(policy: dict, now: datetime) -> tuple[bool, str]:
    """(is_active, note). Active = not expired and review approved / not-required."""
    pa = policy.get("attributes") or {}
    action = (pa.get("action") or {}).get("data") or {}
    review = pa.get("review")
    expires = parse_ts(action.get("expires"))
    if review == "rejected":
        return False, "ignore request rejected"
    if review == "pending":
        return False, "ignore pending review"
    if review not in EFFECTIVE_REVIEWS:
        return False, f"ignore review status: {review}"
    if expires and expires < now:
        return False, f"ignore expired {day(action.get('expires'))}"
    return True, ""


def issue_location(issue: dict) -> str:
    """file:line of the first source location in the issue coordinates."""
    for coord in (issue.get("attributes") or {}).get("coordinates") or []:
        for rep in coord.get("representations") or []:
            loc = rep.get("sourceLocation") if isinstance(rep, dict) else None
            if loc and loc.get("file"):
                line = ((loc.get("region") or {}).get("start") or {}).get("line")
                return f"{loc['file']}:{line}" if line else loc["file"]
    return "-"


def build_report(policies, issues, projects) -> tuple[list[dict], list[dict]]:
    """Return (with_ignore rows, without_ignore rows), considering OPEN Secrets issues only."""
    now = datetime.now(timezone.utc)

    by_finding: dict[str, list[dict]] = {}
    for pol in policies:
        for fid in finding_ids(pol):
            by_finding.setdefault(fid.lower(), []).append(pol)

    with_ignore, without_ignore = [], []

    for issue in issues:
        if (issue.get("attributes") or {}).get("status") != "open":
            continue  # resolved issues are out of scope
        ia = issue.get("attributes") or {}
        rel = issue.get("relationships") or {}
        key_asset = ia.get("key_asset") or ""
        project_id = ((rel.get("scan_item") or {}).get("data") or {}).get("id")
        proj = projects.get(project_id) or {}
        base = {
            "severity": ia.get("effective_severity_level") or "-",
            "secret": ia.get("title") or "-",
            "project": proj.get("name", project_id or "-"),
            "repository": proj.get("repository", "-"),
            "repository_url": proj.get("repository_url", "-"),
            "integration": proj.get("integration", "-"),
            "origin": proj.get("origin", "-"),
            "location": issue_location(issue),
            "issue_status": ia.get("status") or "-",
            "issue_id": issue.get("id"),
            "project_id": project_id,
            "finding_id": key_asset,
        }
        candidates = by_finding.get(key_asset.lower(), []) if key_asset else []
        active, notes = [], []
        for pol in candidates:
            ok, note = policy_state(pol, now)
            (active if ok else notes).append((pol, note))

        if active:
            for pol, _ in active:
                pa = pol.get("attributes") or {}
                data = (pa.get("action") or {}).get("data") or {}
                with_ignore.append(
                    {
                        **base,
                        "ignore_type": data.get("ignore_type") or "-",
                        "reason": data.get("reason") or "-",
                        "expires": day(data.get("expires")) if data.get("expires") else "never",
                        "review": pa.get("review") or "-",
                        "policy_id": pol["id"],
                        "policy_name": pa.get("name") or "-",
                        "created_by": (pa.get("created_by") or {}).get("name") or "-",
                        "created_at": day(pa.get("created_at")),
                    }
                )
        else:
            without_ignore.append({**base, "note": "; ".join(n for _, n in notes) or "-"})

    def sort_key(r: dict):
        return (SEVERITY_ORDER.get(str(r["severity"]).lower(), 9), str(r["project"]).lower(), str(r["secret"]).lower())

    with_ignore.sort(key=sort_key)
    without_ignore.sort(key=sort_key)
    return with_ignore, without_ignore


# --------------------------------------------------------------------------- rendering
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
SEVERITY_STYLE = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": DIM,
}


def render_table(
    title: str,
    columns: list[tuple[str, str]],  # (header, row key)
    rows: list[dict],
    width: int,
    color: bool,
    subtitle: str = "",
) -> str:
    """Boxed table that wraps long cells and shrinks the widest columns to fit `width`."""
    out = [f"{BOLD if color else ''}{title}{RESET if color else ''}"]
    if subtitle:
        out.append(f"{DIM if color else ''}{subtitle}{RESET if color else ''}")
    if not rows:
        out.append("  (none)")
        return "\n".join(out) + "\n"

    headers = [h for h, _ in columns]
    cells = [[str(r.get(k, "")) for _, k in columns] for r in rows]
    widths = [max(len(h), *(len(row[i]) for row in cells)) for i, h in enumerate(headers)]
    min_w = [max(len(h), 8) for h in headers]

    # Shrink the widest shrinkable column until the table fits the terminal.
    overhead = 3 * len(headers) + 1
    while sum(widths) + overhead > width:
        i = max((i for i in range(len(widths)) if widths[i] > min_w[i]), key=lambda i: widths[i], default=None)
        if i is None:
            break
        widths[i] -= 1

    def line(left: str, mid: str, right: str) -> str:
        return left + mid.join("─" * (w + 2) for w in widths) + right

    def style(header: str, text: str) -> str:
        if not color:
            return text
        if header == "Severity":
            return SEVERITY_STYLE.get(text.strip().lower(), "") + text + RESET
        return text

    def row_lines(values: list[str], header_row: bool = False) -> list[str]:
        wrapped = [
            textwrap.wrap(v, w, break_long_words=True, break_on_hyphens=False) or [""]
            for v, w in zip(values, widths)
        ]
        height = max(len(c) for c in wrapped)
        lines = []
        for n in range(height):
            parts = []
            for h, col, w in zip(headers, wrapped, widths):
                text = (col[n] if n < len(col) else "").ljust(w)
                if header_row:
                    text = f"{BOLD}{text}{RESET}" if color else text
                else:
                    text = style(h, text)
                parts.append(f" {text} ")
            lines.append("│" + "│".join(parts) + "│")
        return lines

    out.append(line("╭", "┬", "╮"))
    out.extend(row_lines(headers, header_row=True))
    out.append(line("├", "┼", "┤"))
    for n, values in enumerate(cells):
        out.extend(row_lines(values))
        out.append(line("├", "┼", "┤") if n < len(cells) - 1 else line("╰", "┴", "╯"))
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- CLI
def uuid_arg(value: str) -> str:
    """argparse type: org id must be a UUID so it can't alter the request URL path."""
    try:
        return str(uuid.UUID(value))
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a valid UUID: {value!r}")


def region_host(region: str) -> str:
    """Map a validated region code to its fixed API host (always returns a hard-coded URL)."""
    if region == "US2":
        return "https://api.us.snyk.io"
    if region == "EU":
        return "https://api.eu.snyk.io"
    if region == "AU":
        return "https://api.au.snyk.io"
    return "https://api.snyk.io"


def version_arg(value: str) -> str:
    """argparse type: API version such as 2026-09-09 or 2024-10-15~beta."""
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}(~(experimental|beta))?", value):
        raise argparse.ArgumentTypeError(f"not a valid API version: {value!r}")
    return value


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--org-id", required=True, type=uuid_arg, help="Snyk Organization ID (UUID)")
    ap.add_argument("--region", default="US", choices=REGIONS, help="Snyk region (default US = api.snyk.io)")
    ap.add_argument("--version", type=version_arg, default=DEFAULT_VERSION, help=f"REST API version (default {DEFAULT_VERSION})")
    ap.add_argument("--width", type=int, help="table width in columns (default: terminal width)")
    ap.add_argument("--csv", action="store_true", help=f"write both tables to ./{CSV_NAME} (adds a 'group' column)")
    ap.add_argument("--json", action="store_true", help=f"write {{with_ignore, without_ignore}} to ./{JSON_NAME}")
    args = ap.parse_args()
    csv_path = Path.cwd() / CSV_NAME if args.csv else None
    json_path = Path.cwd() / JSON_NAME if args.json else None

    token = os.environ.get("SNYK_TOKEN")
    if not token:
        sys.exit("Set SNYK_TOKEN (personal access token or service account token).")

    print("Fetching policies, Secrets issues and projects in parallel...", file=sys.stderr)
    policies, issues, projects = fetch_all(token, region_host(args.region), args.org_id, args.version)
    with_ignore, without_ignore = build_report(policies, issues, projects)

    width = args.width or shutil.get_terminal_size(fallback=(160, 24)).columns
    color = sys.stdout.isatty() and "NO_COLOR" not in os.environ

    open_total = len(with_ignore) + len(without_ignore)
    print(
        f"\nOrg {args.org_id}\n"
        "Scope: OPEN Secrets issues only (resolved issues are excluded from every count and table)\n"
        f"  Open Secrets issues ............ {open_total}\n"
        f"    with an active ignore ........ {len(with_ignore)}\n"
        f"    without an active ignore ..... {len(without_ignore)}\n"
    )
    print(
        render_table(
            f"Open Secrets WITH an active ignore policy ({len(with_ignore)})",
            [
                ("Severity", "severity"),
                ("Secret", "secret"),
                ("Repository", "repository"),
                ("Integration", "integration"),
                ("Project", "project"),
                ("Location", "location"),
                ("Ignore type", "ignore_type"),
                ("Reason", "reason"),
                ("Expires", "expires"),
                ("Review", "review"),
                ("Policy ID", "policy_id"),
            ],
            with_ignore,
            width,
            color,
        )
    )
    print(
        render_table(
            f"Open Secrets WITHOUT an active ignore policy ({len(without_ignore)})",
            [
                ("Severity", "severity"),
                ("Secret", "secret"),
                ("Repository", "repository"),
                ("Integration", "integration"),
                ("Project", "project"),
                ("Location", "location"),
                ("Note", "note"),
                ("Issue ID", "issue_id"),
            ],
            without_ignore,
            width,
            color,
        )
    )

    if csv_path:
        rows = [{"group": "with_ignore", **r} for r in with_ignore] + [
            {"group": "without_ignore", **r} for r in without_ignore
        ]
        fields = list(dict.fromkeys(k for r in rows for k in r))
        with csv_path.open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields, restval="")
            w.writeheader()
            w.writerows(rows)
        print(f"Wrote {csv_path}")
    if json_path:
        with json_path.open("w") as f:
            json.dump({"with_ignore": with_ignore, "without_ignore": without_ignore}, f, indent=2)
        print(f"Wrote {json_path}")


if __name__ == "__main__":
    main()

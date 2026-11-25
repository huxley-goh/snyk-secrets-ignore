#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["requests>=2.31"]
# ///
"""
Report which OPEN Snyk Secrets issues in an Org have an active ignore policy, or create one.

  export SNYK_TOKEN=<token>
  uv run snyk_secrets_ignores.py --org-id <ORG_UUID> [--region EU] [--csv] [--json]
  uv run snyk_secrets_ignores.py --org-id <ORG_UUID> --ignore <ISSUE_ID|FINDING_ID> [--reason ...]

An ignore is active if its review is approved / not-required and it has not expired.
Policy finding UUID (conditions_group.conditions[].value) is matched to issue key_asset.
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

REGION_CHOICES = ("US", "US2", "EU", "AU")
FINDING_FIELD = "snyk/asset/finding/v1"
DEFAULT_VERSION = "2026-09-09"
CSV_NAME, JSON_NAME = "secrets_ignores.csv", "secrets_ignores.json"
PAGE_LIMIT = 100  # API maximum
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
EFFECTIVE_REVIEWS = {"approved", "not-required"}
IGNORE_TYPES = ("wont-fix", "temporary-ignore", "not-vulnerable")
SCM_ORIGINS = {
    "github", "github-cloud-app", "github-enterprise", "github-server-app", "gitlab",
    "bitbucket-cloud", "bitbucket-server", "bitbucket-connect-app", "azure-repos",
}
BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"
SEVERITY_COLOR = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": DIM}


# --------------------------------------------------------------------------- HTTP
def region_host(region: str) -> str:
    """Fixed API host per region (always a hard-coded URL, never built from input)."""
    if region == "US2":
        return "https://api.us.snyk.io"
    if region == "EU":
        return "https://api.eu.snyk.io"
    if region == "AU":
        return "https://api.au.snyk.io"
    return "https://api.snyk.io"


def org_path(org_id: str) -> str:
    return f"/orgs/{quote(str(uuid.UUID(org_id)), safe='')}"  # canonical UUID, cannot alter the URL path


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
    """GET with retry on 429 / 5xx."""
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
    """Resolve links.next (string or {href}) to an absolute URL, only on the Snyk host."""
    nxt = (body.get("links") or {}).get("next")
    if isinstance(nxt, dict):
        nxt = nxt.get("href")
    if not nxt:
        return None
    if nxt.startswith("http"):
        if not nxt.startswith(host + "/rest/"):  # never send the token to another host
            sys.exit(f"Refusing to follow pagination link to unexpected host: {nxt}")
        return nxt
    if not nxt.startswith("/"):
        sys.exit(f"Unexpected pagination link: {nxt}")
    return host + (nxt if nxt.startswith("/rest/") else "/rest" + nxt)


def paginate(session: requests.Session, host: str, path: str, params: dict) -> Iterator[dict]:
    """Yield every resource in data[], following links.next until exhausted."""
    url: str | None = f"{host}/rest{path}"
    page = 0
    while url:
        body = get_json(session, url, params if page == 0 else None)
        page += 1
        data = body.get("data") or []
        print(f"  {path.rsplit('/', 1)[-1]} page {page}: {len(data)} records", file=sys.stderr)
        yield from data
        url = next_url(body, host)


def project_info(project: dict) -> dict:
    attrs = project.get("attributes") or {}
    name = attrs.get("name") or project.get("id")
    target = ((project.get("relationships") or {}).get("target") or {}).get("data") or {}
    tattrs = target.get("attributes") or {}
    origin = attrs.get("origin")
    if origin == "cli":
        integration = "CLI"
    elif origin in SCM_ORIGINS:
        integration = f"SCM ({origin})"
    else:
        integration = origin or "-"
    return {
        "name": name,
        # SCM projects are named "owner/repo:path", so fall back to the part before ':'
        "repository": tattrs.get("display_name") or str(name).split(":", 1)[0],
        "repository_url": tattrs.get("url") or "-",
        "integration": integration,
    }


def fetch_all(token: str, host: str, org_id: str, version: str) -> tuple[list, list, dict]:
    """Fetch policies, Secrets issues and projects concurrently."""
    org, base = org_path(org_id), {"version": version, "limit": PAGE_LIMIT}
    jobs = {
        "policies": (f"{org}/policies", base),
        "issues": (f"{org}/issues", {**base, "type": "secrets"}),
        "projects": (f"{org}/projects", {**base, "expand": "target"}),
    }
    # One Session per thread: requests.Session is not guaranteed to be thread-safe.
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = {
            name: pool.submit(lambda p=path, q=params: list(paginate(make_session(token), host, p, q)))
            for name, (path, params) in jobs.items()
        }
        results = {name: f.result() for name, f in futures.items()}  # re-raises on failure
    return results["policies"], results["issues"], {p["id"]: project_info(p) for p in results["projects"]}


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
    group = (policy.get("attributes") or {}).get("conditions_group") or {}
    return [c["value"] for c in group.get("conditions", []) if c.get("field") == FINDING_FIELD and c.get("value")]


def policy_state(policy: dict, now: datetime) -> tuple[bool, str]:
    """(is_active, note explaining why not)."""
    pa = policy.get("attributes") or {}
    data = (pa.get("action") or {}).get("data") or {}
    review, expires = pa.get("review"), parse_ts(data.get("expires"))
    if review not in EFFECTIVE_REVIEWS:
        notes = {"rejected": "ignore request rejected", "pending": "ignore pending review"}
        return False, notes.get(review, f"ignore review status: {review}")
    if expires and expires < now:
        return False, f"ignore expired {day(data.get('expires'))}"
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


def issue_row(issue: dict, projects: dict) -> dict:
    """Display fields shared by the report and the create-ignore preview."""
    ia = issue.get("attributes") or {}
    project_id = (((issue.get("relationships") or {}).get("scan_item") or {}).get("data") or {}).get("id")
    proj = projects.get(project_id) or {}
    return {
        "severity": ia.get("effective_severity_level") or "-",
        "secret": ia.get("title") or "-",
        "repository": proj.get("repository", "-"),
        "repository_url": proj.get("repository_url", "-"),
        "integration": proj.get("integration", "-"),
        "project": proj.get("name", project_id or "-"),
        "location": issue_location(issue),
        "issue_status": ia.get("status") or "-",
        "issue_id": issue.get("id"),
        "project_id": project_id,
        "finding_id": ia.get("key_asset") or "",
    }


def policies_by_finding(policies: list[dict]) -> dict[str, list[dict]]:
    index: dict[str, list[dict]] = {}
    for pol in policies:
        for fid in finding_ids(pol):
            index.setdefault(fid.lower(), []).append(pol)
    return index


def build_report(policies, issues, projects) -> tuple[list[dict], list[dict]]:
    """(with_ignore rows, without_ignore rows) for OPEN Secrets issues only."""
    now, index = datetime.now(timezone.utc), policies_by_finding(policies)
    with_ignore, without_ignore = [], []

    for issue in issues:
        if (issue.get("attributes") or {}).get("status") != "open":
            continue
        row = issue_row(issue, projects)
        states = [(pol, *policy_state(pol, now)) for pol in index.get(row["finding_id"].lower(), [])]
        active = [pol for pol, ok, _ in states if ok]
        if not active:
            without_ignore.append({**row, "note": "; ".join(note for _, _, note in states) or "-"})
            continue
        for pol in active:
            pa = pol.get("attributes") or {}
            data = (pa.get("action") or {}).get("data") or {}
            with_ignore.append(
                {
                    **row,
                    "ignore_type": data.get("ignore_type") or "-",
                    "reason": data.get("reason") or "-",
                    "expires": day(data["expires"]) if data.get("expires") else "never",
                    "review": pa.get("review") or "-",
                    "policy_id": pol["id"],
                    "created_by": (pa.get("created_by") or {}).get("name") or "-",
                    "created_at": day(pa.get("created_at")),
                }
            )

    def sort_key(r: dict):
        return (SEVERITY_ORDER.get(str(r["severity"]).lower(), 9), str(r["project"]).lower(), str(r["secret"]).lower())

    return sorted(with_ignore, key=sort_key), sorted(without_ignore, key=sort_key)


# --------------------------------------------------------------------------- rendering
def render_table(title: str, columns: list[tuple[str, str]], rows: list[dict], width: int, color: bool) -> str:
    """Boxed table; wraps long cells and shrinks the widest columns to fit `width`."""
    bold, reset = (BOLD, RESET) if color else ("", "")
    out = [f"{bold}{title}{reset}"]
    if not rows:
        return "\n".join(out + ["  (none)"]) + "\n"

    headers = [h for h, _ in columns]
    cells = [[str(r.get(k, "")) for _, k in columns] for r in rows]
    widths = [max(len(h), *(len(row[i]) for row in cells)) for i, h in enumerate(headers)]
    min_w = [max(len(h), 8) for h in headers]
    while sum(widths) + 3 * len(headers) + 1 > width:
        i = max((i for i in range(len(widths)) if widths[i] > min_w[i]), key=lambda i: widths[i], default=None)
        if i is None:
            break
        widths[i] -= 1

    def rule(left: str, mid: str, right: str) -> str:
        return left + mid.join("─" * (w + 2) for w in widths) + right

    def row_lines(values: list[str], header: bool = False) -> list[str]:
        wrapped = [textwrap.wrap(v, w, break_long_words=True, break_on_hyphens=False) or [""] for v, w in zip(values, widths)]
        lines = []
        for n in range(max(len(c) for c in wrapped)):
            parts = []
            for h, col, w in zip(headers, wrapped, widths):
                text = (col[n] if n < len(col) else "").ljust(w)
                if color and header:
                    text = f"{BOLD}{text}{RESET}"
                elif color and h == "Severity":
                    text = SEVERITY_COLOR.get(text.strip().lower(), "") + text + RESET
                parts.append(f" {text} ")
            lines.append("│" + "│".join(parts) + "│")
        return lines

    out += [rule("╭", "┬", "╮"), *row_lines(headers, header=True), rule("├", "┼", "┤")]
    for n, values in enumerate(cells):
        out += row_lines(values)
        out.append(rule("├", "┼", "┤") if n < len(cells) - 1 else rule("╰", "┴", "╯"))
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- create ignore
def create_ignore(args, token: str) -> None:
    """Look up the finding, show what will be ignored, confirm, then POST the policy."""
    host = region_host(args.region)
    print("Looking up the finding...", file=sys.stderr)
    policies, issues, projects = fetch_all(token, host, args.org_id, args.version)

    ref = args.ignore.lower()
    issue = next(
        (i for i in issues if ref in (str(i.get("id", "")).lower(), ((i.get("attributes") or {}).get("key_asset") or "").lower())),
        None,
    )
    if issue is None:
        sys.exit(f"No Secrets issue in this Org matches {args.ignore!r} (checked issue ID and key_asset).")
    row = issue_row(issue, projects)
    if not row["finding_id"]:
        sys.exit(f"Issue {row['issue_id']} has no key_asset, so an ignore policy cannot target it.")

    now = datetime.now(timezone.utc)
    for pol in policies_by_finding(policies).get(row["finding_id"].lower(), []):
        if policy_state(pol, now)[0]:
            sys.exit(f"This finding already has an active ignore policy: {pol['id']}")

    name = (args.name or f"Ignore secret: {row['secret']}")[:255]
    print("\nAbout to CREATE this ignore policy in your Snyk Organization:\n")
    for label, value in (
        ("Secret", row["secret"]), ("Severity", row["severity"]), ("Repository", row["repository"]),
        ("Integration", row["integration"]), ("Project", row["project"]), ("Location", row["location"]),
        ("Finding ID", row["finding_id"]), ("Policy name", name), ("Ignore type", args.ignore_type),
        ("Expires", args.expires or "never"), ("Reason", args.reason or "-"),
    ):
        print(f"  {label:<12} {value}")
    print()

    if not args.yes:
        if not sys.stdin.isatty():
            sys.exit("Not an interactive terminal: re-run with --yes to confirm creating the ignore.")
        if input("Create this ignore? [y/N] ").strip().lower() not in ("y", "yes"):
            sys.exit("Aborted. Nothing was created.")

    action = {"ignore_type": args.ignore_type, "reason": args.reason, "expires": args.expires}
    body = {
        "data": {
            "type": "policy",
            "attributes": {
                "name": name,
                "action_type": "ignore",
                "action": {"data": {k: v for k, v in action.items() if v}},
                "conditions_group": {
                    "logical_operator": "and",
                    "conditions": [{"field": FINDING_FIELD, "operator": "includes", "value": row["finding_id"]}],
                },
                "source": "api",
            },
        }
    }
    # POST is not idempotent, so no automatic retry.
    resp = make_session(token).post(
        f"{host}/rest{org_path(args.org_id)}/policies", params={"version": args.version}, data=json.dumps(body), timeout=60
    )
    if resp.status_code != 201:
        sys.exit(f"HTTP {resp.status_code} creating ignore policy:\n{resp.text[:1500]}")
    created = resp.json().get("data") or {}
    review = (created.get("attributes") or {}).get("review") or "-"
    print(f"Created ignore policy {created.get('id')} (review status: {review}).")
    if review == "pending":
        print("It is pending approval and has no effect until approved.")


# --------------------------------------------------------------------------- CLI
def uuid_arg(value: str) -> str:
    try:
        return str(uuid.UUID(value))
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a valid UUID: {value!r}")


def version_arg(value: str) -> str:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}(~(experimental|beta))?", value):
        raise argparse.ArgumentTypeError(f"not a valid API version: {value!r}")
    return value


def finding_arg(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", value):
        raise argparse.ArgumentTypeError(f"not a valid issue / finding ID: {value!r}")
    return value


def expires_arg(value: str) -> str:
    """Future YYYY-MM-DD (or ISO timestamp) -> RFC 3339 UTC."""
    dt = parse_ts(value + "T00:00:00Z" if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) else value)
    if dt is None:
        raise argparse.ArgumentTypeError(f"not a valid date: {value!r} (use YYYY-MM-DD)")
    if dt <= datetime.now(timezone.utc):
        raise argparse.ArgumentTypeError(f"expiry must be in the future: {value!r}")
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--org-id", required=True, type=uuid_arg, help="Snyk Organization ID (UUID)")
    ap.add_argument("--region", default="US", choices=REGION_CHOICES, help="Snyk region (default US)")
    ap.add_argument("--version", type=version_arg, default=DEFAULT_VERSION, help=f"REST API version (default {DEFAULT_VERSION})")
    ap.add_argument("--width", type=int, help="table width (default: terminal width)")
    ap.add_argument("--csv", action="store_true", help=f"also write ./{CSV_NAME}")
    ap.add_argument("--json", action="store_true", help=f"also write ./{JSON_NAME}")
    ig = ap.add_argument_group("create an ignore instead of printing the report")
    ig.add_argument("--ignore", metavar="ID", type=finding_arg, help="Secrets issue ID or finding UUID (key_asset) to ignore")
    ig.add_argument("--ignore-type", choices=IGNORE_TYPES, help="default wont-fix")
    ig.add_argument("--reason", help="reason for the ignore")
    ig.add_argument("--expires", type=expires_arg, help="expiry YYYY-MM-DD (required for temporary-ignore)")
    ig.add_argument("--name", help="policy name (default 'Ignore secret: <title>')")
    ig.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    args = ap.parse_args()

    if args.ignore:
        args.ignore_type = args.ignore_type or "wont-fix"
        if args.ignore_type == "temporary-ignore" and not args.expires:
            ap.error("--ignore-type temporary-ignore requires --expires YYYY-MM-DD")
        if args.csv or args.json:
            ap.error("--csv/--json apply to the report, not to --ignore")
    else:
        used = [f for f, v in (("--ignore-type", args.ignore_type), ("--reason", args.reason), ("--expires", args.expires),
                               ("--name", args.name), ("--yes", args.yes)) if v]
        if used:
            ap.error(f"{', '.join(used)} can only be used together with --ignore")

    token = os.environ.get("SNYK_TOKEN")
    if not token:
        sys.exit("Set SNYK_TOKEN (personal access token or service account token).")
    if args.ignore:
        return create_ignore(args, token)

    print("Fetching policies, Secrets issues and projects in parallel...", file=sys.stderr)
    policies, issues, projects = fetch_all(token, region_host(args.region), args.org_id, args.version)
    with_ignore, without_ignore = build_report(policies, issues, projects)

    width = args.width or shutil.get_terminal_size(fallback=(160, 24)).columns
    color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    print(
        f"\nOrg {args.org_id}\n"
        "Scope: OPEN Secrets issues only (resolved issues are excluded from every count and table)\n"
        f"  Open Secrets issues ............ {len(with_ignore) + len(without_ignore)}\n"
        f"    with an active ignore ........ {len(with_ignore)}\n"
        f"    without an active ignore ..... {len(without_ignore)}\n"
    )
    common = [("Severity", "severity"), ("Secret", "secret"), ("Repository", "repository"),
              ("Integration", "integration"), ("Project", "project"), ("Location", "location")]
    print(render_table(
        f"Open Secrets WITH an active ignore policy ({len(with_ignore)})",
        common + [("Ignore type", "ignore_type"), ("Reason", "reason"), ("Expires", "expires"),
                  ("Review", "review"), ("Policy ID", "policy_id")],
        with_ignore, width, color,
    ))
    print(render_table(
        f"Open Secrets WITHOUT an active ignore policy ({len(without_ignore)})",
        common + [("Note", "note"), ("Issue ID", "issue_id")],
        without_ignore, width, color,
    ))

    if args.csv:
        rows = [{"group": "with_ignore", **r} for r in with_ignore] + [{"group": "without_ignore", **r} for r in without_ignore]
        with (Path.cwd() / CSV_NAME).open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(dict.fromkeys(k for r in rows for k in r)), restval="")
            w.writeheader()
            w.writerows(rows)
        print(f"Wrote {Path.cwd() / CSV_NAME}")
    if args.json:
        with (Path.cwd() / JSON_NAME).open("w") as f:
            json.dump({"with_ignore": with_ignore, "without_ignore": without_ignore}, f, indent=2)
        print(f"Wrote {Path.cwd() / JSON_NAME}")


if __name__ == "__main__":
    main()

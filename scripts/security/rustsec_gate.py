#!/usr/bin/env python3
"""Run RustSec without hidden ignores and enforce narrow, expiring exceptions."""

from __future__ import annotations

import datetime as dt
import json
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "security" / "advisory-exceptions.toml"


def fail(message: str) -> None:
    print(f"security gate: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    policy = tomllib.loads(POLICY.read_text(encoding="utf-8"))
    if policy.get("version") != 1:
        fail("unsupported advisory exception policy version")

    today = dt.datetime.now(dt.timezone.utc).date()
    exceptions: dict[tuple[str, str, str], dict[str, object]] = {}
    for item in policy.get("exception", []):
        key = (item["advisory"], item["package"], item["version"])
        if key in exceptions:
            fail(f"duplicate exception for {key}")
        expires = dt.date.fromisoformat(item["expires"])
        if expires < today:
            fail(f"expired exception for {key}: {expires}")
        for field in ("owner", "rationale", "controls"):
            if not str(item.get(field, "")).strip():
                fail(f"exception for {key} has no {field}")
        exceptions[key] = item

    result = subprocess.run(
        ["cargo", "audit", "--json"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        fail(f"cargo audit did not produce valid JSON: {error}")

    findings = report.get("vulnerabilities", {}).get("list", [])
    used: set[tuple[str, str, str]] = set()
    blocked = []
    for finding in findings:
        key = (
            finding["advisory"]["id"],
            finding["package"]["name"],
            finding["package"]["version"],
        )
        title = finding["advisory"]["title"]
        if key in exceptions:
            used.add(key)
            item = exceptions[key]
            print(
                f"REVIEWED EXCEPTION {key[0]} {key[1]} {key[2]} "
                f"(expires {item['expires']}): {title}"
            )
        else:
            blocked.append((key, title))
            print(f"BLOCKED {key[0]} {key[1]} {key[2]}: {title}", file=sys.stderr)

    stale = set(exceptions) - used
    if stale:
        fail(f"exception no longer matches the resolved graph; remove or update it: {sorted(stale)}")
    if blocked:
        fail(f"{len(blocked)} unreviewed RustSec vulnerability finding(s)")
    if result.returncode not in (0, 1):
        fail(f"cargo audit failed operationally with exit code {result.returncode}")

    print(f"security gate: {len(findings)} finding(s), all resolved or narrowly reviewed")


if __name__ == "__main__":
    main()

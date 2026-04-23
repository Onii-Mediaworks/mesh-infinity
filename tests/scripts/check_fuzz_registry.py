#!/usr/bin/env python3
"""Validate Mesh Infinity's fuzz target registry.

This script enforces the safety-process contract around `fuzz/targets.toml`.
It is intentionally strict: the purpose is to prevent silent drift between
active cargo-fuzz targets, committed corpora, and the registry that tracks
required safety surfaces.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path


VALID_STATUSES = {
    "active",
    "blocked-unimplemented",
    "blocked-design-pending",
    "not-applicable",
}

REQUIRED_FIELDS = {"name", "status", "owner_module", "threat", "required_by_spec"}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def fail(errors: list[str]) -> None:
    for error in errors:
        print(f"ERROR: {error}")
    raise SystemExit(1)


def main() -> None:
    root = repo_root()
    registry_path = root / "fuzz" / "targets.toml"
    data = tomllib.loads(registry_path.read_text(encoding="utf-8"))
    entries = data.get("target", [])

    errors: list[str] = []
    seen_names: set[str] = set()

    fuzz_target_dir = root / "fuzz" / "fuzz_targets"
    existing_targets = {path.stem for path in fuzz_target_dir.glob("*.rs")}

    active_targets: set[str] = set()

    for index, entry in enumerate(entries):
        missing = REQUIRED_FIELDS - entry.keys()
        if missing:
            errors.append(
                f"registry entry #{index + 1} missing required fields: {sorted(missing)}"
            )
            continue

        name = entry["name"]
        status = entry["status"]
        owner_module = root / entry["owner_module"]

        if name in seen_names:
            errors.append(f"duplicate fuzz registry entry for target '{name}'")
        seen_names.add(name)

        if status not in VALID_STATUSES:
            errors.append(f"target '{name}' has invalid status '{status}'")

        if not isinstance(entry["required_by_spec"], bool):
            errors.append(f"target '{name}' has non-boolean required_by_spec")

        if status == "active":
            active_targets.add(name)
            if name not in existing_targets:
                errors.append(f"active target '{name}' is missing fuzz_targets/{name}.rs")
            corpus_dir = root / "fuzz" / "corpus" / name
            if not corpus_dir.is_dir():
                errors.append(f"active target '{name}' is missing corpus directory {corpus_dir}")
            if not owner_module.exists():
                errors.append(f"active target '{name}' owner_module does not exist: {owner_module}")

        if status == "blocked-unimplemented":
            if owner_module.exists():
                errors.append(
                    f"target '{name}' is blocked-unimplemented but owner_module exists: {owner_module}"
                )
            if not entry.get("unblock_condition"):
                errors.append(f"target '{name}' is blocked-unimplemented but lacks unblock_condition")

        if status == "blocked-design-pending":
            if not owner_module.exists():
                errors.append(
                    f"target '{name}' is blocked-design-pending but owner_module does not exist: {owner_module}"
                )
            if not entry.get("unblock_condition"):
                errors.append(f"target '{name}' is blocked-design-pending but lacks unblock_condition")

        if status == "not-applicable" and not entry.get("reason"):
            errors.append(f"target '{name}' is not-applicable but lacks reason")

        if name in existing_targets and status != "active":
            errors.append(
                f"target '{name}' has a fuzz harness file but registry status is '{status}', expected 'active'"
            )

    missing_registry_entries = existing_targets - seen_names
    for name in sorted(missing_registry_entries):
        errors.append(f"fuzz target '{name}' exists on disk but is missing from fuzz/targets.toml")

    if errors:
        fail(errors)

    print(
        f"fuzz registry OK: {len(entries)} entries, {len(active_targets)} active, "
        f"{len(existing_targets)} harness files"
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Replay Mesh Infinity's committed fuzz corpus and fixed reproducers.

This script is intentionally strict. The point is to make committed seeds and
fixed reproducer inputs part of normal CI, not an aspirational note in docs.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path


TARGET_RE = re.compile(r"^Target:\s*(?P<target>[A-Za-z0-9_\\-]+)\s*$", re.MULTILINE)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def load_active_targets(root: Path) -> list[str]:
    registry = tomllib.loads((root / "fuzz" / "targets.toml").read_text(encoding="utf-8"))
    return [
        entry["name"]
        for entry in registry.get("target", [])
        if entry.get("status") == "active"
    ]


def parse_artifact_target(readme_path: Path) -> str | None:
    match = TARGET_RE.search(readme_path.read_text(encoding="utf-8"))
    if not match:
        return None
    return match.group("target")


def replay_input(root: Path, target: str, input_path: Path) -> None:
    print(f"Replaying {input_path.relative_to(root)} with {target}")
    subprocess.run(
        ["cargo", "+nightly", "fuzz", "run", target, str(input_path)],
        cwd=root,
        check=True,
    )


def validate_fixed_artifacts(root: Path, active_targets: set[str]) -> list[tuple[str, Path]]:
    fixed_root = root / "fuzz" / "artifacts" / "fixed"
    if not fixed_root.exists():
        return []

    errors: list[str] = []
    replay_cases: list[tuple[str, Path]] = []

    for artifact_dir in sorted(path for path in fixed_root.iterdir() if path.is_dir()):
        input_path = artifact_dir / "input.bin"
        readme_path = artifact_dir / "README.md"

        if not input_path.is_file():
            errors.append(f"{artifact_dir} is missing input.bin")
            continue
        if not readme_path.is_file():
            errors.append(f"{artifact_dir} is missing README.md")
            continue

        target = parse_artifact_target(readme_path)
        if target is None:
            errors.append(
                f"{readme_path} is missing a 'Target: <fuzz_target>' line for corpus replay"
            )
            continue
        if target not in active_targets:
            errors.append(
                f"{artifact_dir} declares target '{target}', but it is not an active fuzz target"
            )
            continue

        replay_cases.append((target, input_path))

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        raise SystemExit(1)

    return replay_cases


def main() -> None:
    root = repo_root()
    active_targets = load_active_targets(root)
    active_target_set = set(active_targets)

    replay_cases: list[tuple[str, Path]] = []

    for target in active_targets:
        corpus_dir = root / "fuzz" / "corpus" / target
        if not corpus_dir.is_dir():
            print(f"ERROR: active target '{target}' is missing corpus directory {corpus_dir}")
            raise SystemExit(1)

        inputs = sorted(path for path in corpus_dir.iterdir() if path.is_file())
        if not inputs:
            print(f"ERROR: active target '{target}' has no committed corpus files in {corpus_dir}")
            raise SystemExit(1)

        replay_cases.extend((target, path) for path in inputs)

    replay_cases.extend(validate_fixed_artifacts(root, active_target_set))

    if not replay_cases:
        print("ERROR: no corpus replay cases found")
        raise SystemExit(1)

    print(f"replaying {len(replay_cases)} committed fuzz inputs")
    for target, input_path in replay_cases:
        replay_input(root, target, input_path)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        print(f"ERROR: replay command failed with exit code {exc.returncode}")
        raise SystemExit(exc.returncode) from exc

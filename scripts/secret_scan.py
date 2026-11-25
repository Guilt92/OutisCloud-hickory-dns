#!/usr/bin/env python3
"""Report tracked config files with live-looking secret assignments (never print values)."""

import os
import re
import subprocess
from urllib.parse import urlsplit

PATTERN = re.compile(
    r"(?im)^\s*(?:export\s+)?[\"']?([A-Z0-9_-]*(?:PASSWORD|SECRET|TOKEN|PRIVATE_KEY|API_KEY|DATABASE_URL|DSN)[A-Z0-9_-]*)[\"']?\s*[:=]\s*(.+?)\s*$"
)
CONFIG_EXT = {".yaml", ".yml", ".toml", ".ini", ".conf", ".env"}
PLACEHOLDERS = {
    "", "changeme", "change-me", "change_me", "example", "placeholder", "your-secret", "x",
    "redacted", "postgres", "admin", "test", "test-password", "secret", "password",
}
SOURCE_EXT = {".rs", ".js", ".jsx", ".ts", ".tsx", ".py", ".sh", ".cjs", ".md"}


def is_safe_ci_fixture(name: str, key: str, value: str) -> bool:
    lowered = value.lower()
    key_lower = key.lower()
    # CI uses intentionally weak credentials only for disposable local
    # PostgreSQL services; these values are not deployable credentials.
    if key_lower == "test_database_url":
        try:
            if urlsplit(value).hostname in {"localhost", "127.0.0.1", "::1"}:
                return True
        except ValueError:
            pass
    return (
        name.startswith(".github/workflows/")
        and key_lower == "postgres_password"
        and "test" in lowered
    )


def findings_for_text(name: str, text: str) -> list[tuple[str, str]]:
    findings = []
    for match in PATTERN.finditer(text):
        key, value = match.group(1), match.group(2).strip().strip("\"'")
        lowered = value.lower()
        key_lower = key.lower()
        if is_safe_ci_fixture(name, key, value):
            continue
        if key_lower.endswith(("ref", "refs", "keys")):
            continue
        if lowered in PLACEHOLDERS or value.startswith(("${", "<", "{{", "$")):
            continue
        if len(value) < 16:
            continue
        findings.append((name, key))
    return findings


def scan_tracked_files() -> list[tuple[str, str]]:
    tracked = subprocess.check_output(["git", "ls-files"], text=True).splitlines()
    findings = []
    for name in tracked:
        base = os.path.basename(name)
        if base == ".env.example":
            continue
        if name.endswith(tuple(SOURCE_EXT)):
            continue
        is_env = base.startswith(".env") or "/env/" in name or name.endswith(".env")
        if not is_env and os.path.splitext(name)[1].lower() not in CONFIG_EXT:
            continue
        try:
            text = open(name, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        findings.extend(findings_for_text(name, text))
    return findings


def main() -> int:
    findings = scan_tracked_files()
    if findings:
        print("Potential live secrets in tracked config files:")
        for name, key in sorted(set(findings)):
            print(f"  {name}: {key}")
        return 1
    print("No live-looking secret assignments found in tracked config files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

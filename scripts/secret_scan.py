#!/usr/bin/env python3
"""Report tracked config files with live-looking secret assignments (never print values)."""

import os
import re
import subprocess

PATTERN = re.compile(
    r"(?im)^\s*(?:export\s+)?[\"']?([A-Z0-9_-]*(?:PASSWORD|SECRET|TOKEN|PRIVATE_KEY|API_KEY|DATABASE_URL|DSN)[A-Z0-9_-]*)[\"']?\s*[:=]\s*(.+?)\s*$"
)
CONFIG_EXT = {".yaml", ".yml", ".toml", ".ini", ".conf", ".env"}
PLACEHOLDERS = {
    "", "changeme", "change-me", "change_me", "example", "placeholder", "your-secret", "x",
    "redacted", "postgres", "admin", "test", "test-password", "secret", "password",
}
SOURCE_EXT = {".rs", ".js", ".jsx", ".ts", ".tsx", ".py", ".sh", ".cjs", ".md"}

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
    for match in PATTERN.finditer(text):
        key, value = match.group(1), match.group(2).strip().strip("\"'")
        lowered = value.lower()
        key_lower = key.lower()
        if key_lower.endswith(("ref", "refs", "keys")):
            continue
        if lowered in PLACEHOLDERS or value.startswith(("${", "<", "{{", "$")):
            continue
        if len(value) < 16:
            continue
        findings.append((name, key))

if findings:
    print("Potential live secrets in tracked config files:")
    for name, key in sorted(set(findings)):
        print(f"  {name}: {key}")
    raise SystemExit(1)

print("No live-looking secret assignments found in tracked config files")

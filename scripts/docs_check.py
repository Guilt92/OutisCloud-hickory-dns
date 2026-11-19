#!/usr/bin/env python3
"""Lightweight Markdown consistency check: relative links and stale claims."""

import os
import re
import subprocess

LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
FORBIDDEN = {
    "DELIVERY_SUMMARY.md": ["READY FOR PRODUCTION", "admin123", "production-ready DNS Manager UI"],
}

tracked = [p for p in subprocess.check_output(["git", "ls-files"], text=True).splitlines() if p.endswith(".md")]
tracked_set = set(tracked)
missing = []
for name in tracked:
    if not os.path.exists(name):
        continue
    text = open(name, encoding="utf-8", errors="ignore").read()
    for target in LINK.findall(text):
        target = target.split("#", 1)[0].split("?", 1)[0].strip()
        if not target or re.match(r"^(https?:|mailto:)", target):
            continue
        candidate = os.path.normpath(os.path.join(os.path.dirname(name), target))
        if candidate not in tracked_set and not os.path.exists(candidate):
            missing.append((name, target))

errors = []
for name, phrases in FORBIDDEN.items():
    if not os.path.exists(name):
        continue
    text = open(name, encoding="utf-8", errors="ignore").read()
    for phrase in phrases:
        if phrase in text:
            errors.append(f"{name}: stale phrase {phrase!r}")

for name, target in sorted(set(missing)):
    print(f"WARN broken relative link: {name} -> {target}")
for error in errors:
    print(f"ERROR {error}")

if errors:
    raise SystemExit(1)
print(f"Docs check complete: {len(tracked)} Markdown files, {len(set(missing))} broken-link warnings")

#!/usr/bin/env python3
"""Generate replacement values for tracked secrets without exposing them.

By default this is a dry run: it reports which keys would change and their
generated lengths. Pass --write FILE to atomically replace values in a local
file. Never run --write against production until the coordinated rotation
window and deployment plan are approved.
"""

import argparse
import os
import re
import secrets
import string
import tempfile

KEYS = (
    "JWT_SECRET",
    "DATABASE_PASSWORD",
    "POSTGRES_PASSWORD",
    "ADMIN_PASSWORD",
    "GF_SECURITY_ADMIN_PASSWORD",
)


def value_for(key: str) -> str:
    alphabet = string.ascii_letters + string.digits + "-_"
    length = 64 if key == "JWT_SECRET" else 32
    return "".join(secrets.choice(alphabet) for _ in range(length))


def replace(path: str, values: dict[str, str]) -> None:
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    for key, value in values.items():
        pattern = re.compile(rf"(?m)^{re.escape(key)}=.*$")
        if pattern.search(text):
            text = pattern.sub(f"{key}={value}", text)
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".secret-rotate-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", metavar="FILE", help="atomically replace values in FILE")
    args = parser.parse_args()
    values = {key: value_for(key) for key in KEYS}
    if args.write:
        replace(args.write, values)
        for key in values:
            print(f"rotated {key} in {args.write} (value hidden)")
    else:
        for key, value in values.items():
            print(f"would rotate {key} (length {len(value)})")


if __name__ == "__main__":
    main()

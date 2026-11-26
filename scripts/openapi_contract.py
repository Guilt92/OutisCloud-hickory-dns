#!/usr/bin/env python3
"""Generate/check the OpenAPI path catalog from Actix route registrations."""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "crates/control_api/src"
OUTPUT = ROOT / "crates/control_api/openapi-paths.json"
ROUTE = re.compile(
    r"\.route\(\s*\"([^\"]+)\"\s*,\s*web::(get|post|put|patch|delete)\s*\(\s*\)",
    re.IGNORECASE,
)
METHODS = {"get", "post", "put", "patch", "delete"}


def extract_routes():
    routes = set()
    for source in SOURCE.glob("*.rs"):
        if source.name.endswith("_tests.rs"):
            continue
        for path, method in ROUTE.findall(source.read_text()):
            routes.add((path, method.lower()))
    return sorted(routes)


def operation(path, method):
    parts = [part for part in path.split("/") if part and not part.startswith("{")]
    tag = parts[2] if len(parts) > 2 and parts[0] == "api" else (parts[0] if parts else "service")
    operation_id = re.sub(r"[^a-zA-Z0-9]+", "_", f"{method}_{path}").strip("_")
    responses = {
        "200": {"description": "Request completed"},
        "400": {"description": "Invalid request"},
        "401": {"description": "Authentication required"},
        "403": {"description": "Insufficient permission"},
        "404": {"description": "Resource not found"},
        "429": {"description": "Rate limit exceeded"},
        "500": {"description": "Internal error"},
        "default": {"description": "Request error"},
    }
    if method == "post":
        responses["201"] = {"description": "Resource created"}
    result = {
        "operationId": operation_id,
        "tags": [tag.replace("-", " ").title()],
        "responses": responses,
    }
    path_parameters = re.findall(r"\{([^}]+)\}", path)
    if path_parameters:
        result["parameters"] = [
            {
                "name": name,
                "in": "path",
                "required": True,
                "schema": {"type": "string"},
            }
            for name in path_parameters
        ]
    if path.startswith("/api/") and path not in {
        "/api/v1/auth/login",
        "/api/v1/auth/refresh",
        "/api/v1/auth/mfa/setup",
        "/api/v1/auth/mfa/enable",
    }:
        result["security"] = [{"BearerAuth": []}]
    if method in {"post", "put", "patch"} and not path.endswith("/login"):
        result["requestBody"] = {
            "required": False,
            "content": {
                "application/json": {
                    "schema": {"type": "object", "additionalProperties": True}
                }
            },
        }
    return result


def render():
    paths = {}
    for path, method in extract_routes():
        paths.setdefault(path, {})[method] = operation(path, method)
    return json.dumps(paths, indent=2, sort_keys=True) + "\n"


def validate(paths):
    operation_ids = set()
    errors = []
    for path, methods in paths.items():
        expected_parameters = set(re.findall(r"\{([^}]+)\}", path))
        for method, item in methods.items():
            if method not in METHODS:
                errors.append(f"{path}: unsupported method {method}")
            operation_id = item.get("operationId")
            if not operation_id or operation_id in operation_ids:
                errors.append(f"{path} {method}: missing or duplicate operationId")
            operation_ids.add(operation_id)
            if not item.get("responses"):
                errors.append(f"{path} {method}: no responses documented")
            actual_parameters = {
                parameter.get("name")
                for parameter in item.get("parameters", [])
                if parameter.get("in") == "path" and parameter.get("required")
            }
            if actual_parameters != expected_parameters:
                errors.append(f"{path} {method}: path parameter definitions do not match template")
            if any(requirement != "BearerAuth" for requirement in item.get("security", [{}])[0]):
                errors.append(f"{path} {method}: references an unknown security scheme")
    if errors:
        raise ValueError("\n".join(errors))


def check_breaking_changes(current, baseline_path):
    baseline = json.loads(Path(baseline_path).read_text())
    removed = []
    for path, methods in baseline.items():
        for method in methods:
            if method not in current.get(path, {}):
                removed.append(f"{method.upper()} {path}")
    if removed:
        raise ValueError("breaking API operations removed: " + ", ".join(sorted(removed)))


def main():
    generated = render()
    current = json.loads(generated)
    try:
        validate(current)
        if "--check-breaking" in sys.argv:
            index = sys.argv.index("--check-breaking")
            check_breaking_changes(current, sys.argv[index + 1])
    except (ValueError, IndexError, json.JSONDecodeError) as error:
        print(f"OpenAPI validation failed: {error}", file=sys.stderr)
        return 1
    if "--check" in sys.argv:
        if not OUTPUT.exists() or OUTPUT.read_text() != generated:
            print("OpenAPI route catalog is stale; run python3 scripts/openapi_contract.py", file=sys.stderr)
            return 1
        print(f"OpenAPI route catalog matches {len(extract_routes())} registered method/path pairs")
        return 0
    OUTPUT.write_text(generated)
    print(f"wrote {OUTPUT.relative_to(ROOT)} with {len(extract_routes())} method/path pairs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

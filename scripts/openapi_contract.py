#!/usr/bin/env python3
"""Generate and validate the control API's route and DTO OpenAPI contract."""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "crates/control_api/src"
OUTPUT = ROOT / "crates/control_api/openapi-paths.json"
ROUTE = re.compile(
    r"\.route\(\s*\"([^\"]+)\"\s*,\s*web::(get|post|put|patch|delete)\s*"
    r"\(\s*\)\s*\.to\(\s*([\w:]+)\s*\)\s*,?\s*\)",
    re.IGNORECASE | re.DOTALL,
)
METHODS = {"get", "post", "put", "patch", "delete"}
PUBLIC_OPERATIONS = {
    ("/api/v1/auth/login", "post"),
    ("/api/v1/auth/refresh", "post"),
}


def production_source(path):
    text = path.read_text()
    # Inline test modules can sit between production declarations, so remove
    # their balanced blocks instead of truncating the remainder of that file.
    marker = re.compile(r"(?m)^#\[cfg\(test\)\]\s*\n(?:pub\s+)?mod\s+\w+\s*\{")
    while match := marker.search(text):
        opening = text.find("{", match.start())
        depth = 0
        end = opening
        for end in range(opening, len(text)):
            if text[end] == "{":
                depth += 1
            elif text[end] == "}":
                depth -= 1
                if depth == 0:
                    end += 1
                    break
        text = text[: match.start()] + "\n" + text[end:]
    return text


def sources():
    return {path: production_source(path) for path in SOURCE.glob("*.rs") if not path.name.endswith("_tests.rs")}


def extract_operations():
    operations = {}
    for path, text in sources().items():
        for route, method, handler in ROUTE.findall(text):
            # CORS-only test helper routes are excluded with the test module;
            # keep the guard in case a test route is moved into another file.
            if route == "/test":
                continue
            key = (route, method.lower())
            if key in operations:
                raise ValueError(f"duplicate route registration: {method.upper()} {route}")
            operations[key] = (handler, path)
    return operations


def extract_routes():
    return sorted(extract_operations())


def function_arguments(text, function_name):
    match = re.search(rf"\b(?:async\s+)?fn\s+{re.escape(function_name)}\s*\(", text)
    if not match:
        return ""
    start = text.find("(", match.start())
    depth = 0
    for end in range(start, len(text)):
        if text[end] == "(":
            depth += 1
        elif text[end] == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1 : end]
    return ""


def request_type(handler, source_path):
    function_name = handler.split("::")[-1]
    module = handler.split("::")[-2] if "::" in handler else None
    target_path = SOURCE / f"{module}.rs" if module and (SOURCE / f"{module}.rs").exists() else source_path
    text = sources()[target_path]
    arguments = function_arguments(text, function_name)
    match = re.search(r"web::Json\s*<\s*([\w:<> ,]+?)\s*>", arguments)
    return match.group(1).strip().split("::")[-1] if match else None


def balanced_block(text, opening):
    depth = 0
    for end in range(opening, len(text)):
        if text[end] == "{":
            depth += 1
        elif text[end] == "}":
            depth -= 1
            if depth == 0:
                return text[opening + 1 : end]
    return ""


def rust_struct(type_name):
    for text in sources().values():
        match = re.search(rf"\bstruct\s+{re.escape(type_name)}\s*\{{", text)
        if match:
            opening = text.find("{", match.start())
            return balanced_block(text, opening)
    return None


def rust_type_schema(type_name, components, active=None):
    active = active or set()
    value = type_name.strip().rstrip(",")
    if value.startswith("Option<") and value.endswith(">"):
        schema = rust_type_schema(value[7:-1], components, active)
        return {**schema, "nullable": True}
    if value.startswith("Vec<") and value.endswith(">"):
        return {"type": "array", "items": rust_type_schema(value[4:-1], components, active)}
    if value.startswith(("HashMap<", "BTreeMap<")) and value.endswith(">"):
        inner = value[value.find("<") + 1 : -1]
        mapped = inner.split(",", 1)[-1].strip()
        return {"type": "object", "additionalProperties": rust_type_schema(mapped, components, active)}
    primitives = {
        "String": {"type": "string"},
        "str": {"type": "string"},
        "bool": {"type": "boolean"},
        "i8": {"type": "integer", "format": "int32"},
        "i16": {"type": "integer", "format": "int32"},
        "i32": {"type": "integer", "format": "int32"},
        "i64": {"type": "integer", "format": "int64"},
        "u8": {"type": "integer", "format": "int32", "minimum": 0},
        "u16": {"type": "integer", "format": "int32", "minimum": 0},
        "u32": {"type": "integer", "format": "int64", "minimum": 0},
        "u64": {"type": "integer", "format": "int64", "minimum": 0},
        "f32": {"type": "number", "format": "float"},
        "f64": {"type": "number", "format": "double"},
    }
    if value in primitives:
        return dict(primitives[value])
    if value in {"Value", "serde_json::Value"}:
        return {}
    if value.startswith("Uuid"):
        return {"type": "string", "format": "uuid"}
    if value.startswith("DateTime"):
        return {"type": "string", "format": "date-time"}
    if value in active:
        return {"$ref": f"#/components/schemas/{value}"}
    body = rust_struct(value)
    if body is None:
        return {"type": "string"}
    active.add(value)
    properties = {}
    required = []
    attrs = []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#["):
            attrs.append(stripped)
            continue
        if stripped.startswith("//"):
            continue
        field = re.match(r"(?:pub(?:\([^)]*\))?\s+)?([A-Za-z_]\w*)\s*:\s*(.+?)\s*,?$", stripped)
        if not field:
            attrs = []
            continue
        name, field_type = field.groups()
        rename = next((re.search(r'rename\s*=\s*"([^"]+)"', attr) for attr in attrs if "serde" in attr), None)
        json_name = rename.group(1) if rename else name
        properties[json_name] = rust_type_schema(field_type, components, active)
        optional = field_type.strip().startswith("Option<")
        defaulted = any("default" in attr for attr in attrs if "serde" in attr)
        if not optional and not defaulted:
            required.append(json_name)
        attrs = []
    components[value] = {"type": "object", "properties": properties}
    if required:
        components[value]["required"] = required
    active.remove(value)
    return {"$ref": f"#/components/schemas/{value}"}


def operation(path, method, handler, source_path, components):
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
    result = {"operationId": operation_id, "tags": [tag.replace("-", " ").title()], "responses": responses}
    path_parameters = re.findall(r"\{([^}]+)\}", path)
    if path_parameters:
        result["parameters"] = [
            {"name": name, "in": "path", "required": True, "schema": {"type": "string"}}
            for name in path_parameters
        ]
    if path.startswith("/api/") and (path, method) not in PUBLIC_OPERATIONS:
        result["security"] = [{"BearerAuth": []}]
    body_type = request_type(handler, source_path)
    if body_type:
        schema = rust_type_schema(body_type, components)
        result["requestBody"] = {
            "required": True,
            "content": {"application/json": {"schema": schema}},
        }
    return result


def render():
    components = {}
    paths = {}
    operations = extract_operations()
    for (path, method), (handler, source_path) in sorted(operations.items()):
        paths.setdefault(path, {})[method] = operation(path, method, handler, source_path, components)
    return json.dumps({"paths": paths, "components": {"schemas": components}}, indent=2, sort_keys=True) + "\n"


def check_breaking_changes(current, baseline_path):
    baseline = json.loads(Path(baseline_path).read_text())
    old_paths = baseline.get("paths", baseline)
    new_paths = current["paths"]
    removed = []
    for path, methods in old_paths.items():
        if not path.startswith("/"):
            continue
        if path == "/test":
            continue
        for method, old_operation in methods.items():
            new_operation = new_paths.get(path, {}).get(method)
            if new_operation is None:
                removed.append(f"{method.upper()} {path}")
                continue
            old_body = old_operation.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema")
            new_body = new_operation.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema")
            # The first generated catalog used an unconstrained object for all
            # requests. Replacing that placeholder with DTO schemas improves
            # precision without changing the runtime contract.
            if old_body and old_body.get("additionalProperties") is True:
                continue
            if old_body and old_body != new_body:
                removed.append(f"request schema changed: {method.upper()} {path}")
    old_schemas = baseline.get("components", {}).get("schemas", {})
    new_schemas = current.get("components", {}).get("schemas", {})
    for name, old_schema in old_schemas.items():
        new_schema = new_schemas.get(name)
        if new_schema is None:
            removed.append(f"schema removed: {name}")
            continue
        old_properties = old_schema.get("properties", {})
        new_properties = new_schema.get("properties", {})
        for field, old_property in old_properties.items():
            if field not in new_properties or old_property != new_properties[field]:
                removed.append(f"schema property changed: {name}.{field}")
        newly_required = set(new_schema.get("required", [])) - set(old_schema.get("required", []))
        if newly_required:
            removed.append(f"new required properties in {name}: {', '.join(sorted(newly_required))}")
    if removed:
        raise ValueError("breaking API operations/schemas changed: " + ", ".join(sorted(removed)))


def validate(document):
    operation_ids = set()
    errors = []
    paths = document.get("paths", {})
    schemas = document.get("components", {}).get("schemas", {})
    def validate_schema(schema, context):
        if "$ref" in schema:
            name = schema["$ref"].split("/")[-1]
            if name not in schemas:
                errors.append(f"{context}: request schema reference {name} is missing")
        if schema.get("type") == "array" and "items" not in schema:
            errors.append(f"{context}: array schema has no items")
        if schema.get("type") == "object":
            properties = schema.get("properties", {})
            for field in schema.get("required", []):
                if field not in properties:
                    errors.append(f"{context}: required property {field} is not defined")
            for field, child in properties.items():
                validate_schema(child, f"{context}.{field}")
            if "additionalProperties" in schema and isinstance(schema["additionalProperties"], dict):
                validate_schema(schema["additionalProperties"], f"{context}.*")
        if schema.get("type") == "array":
            validate_schema(schema["items"], f"{context}[]")

    for name, schema in schemas.items():
        validate_schema(schema, f"schema {name}")
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
            schema = item.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema")
            if schema is not None and schema.get("additionalProperties") is True:
                errors.append(f"{path} {method}: generic request body schema is not allowed")
            if schema:
                validate_schema(schema, f"{path} {method}")
    if errors:
        raise ValueError("\n".join(errors))


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
    if "--check" in sys.argv or "--check-breaking" in sys.argv:
        if "--check" in sys.argv and (not OUTPUT.exists() or OUTPUT.read_text() != generated):
            print("OpenAPI route/schema catalog is stale; run python3 scripts/openapi_contract.py", file=sys.stderr)
            return 1
        print(f"OpenAPI route/schema catalog validated for {len(extract_routes())} registered method/path pairs")
        return 0
    OUTPUT.write_text(generated)
    print(f"wrote {OUTPUT.relative_to(ROOT)} with {len(extract_routes())} method/path pairs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Regression tests for generated OpenAPI DTO and compatibility contracts."""

import importlib.util
import json
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("openapi_contract.py")
SPEC = importlib.util.spec_from_file_location("openapi_contract", MODULE_PATH)
contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(contract)


class OpenApiContractTests(unittest.TestCase):
    def test_routes_exclude_test_only_operations_and_use_typed_request_dtos(self):
        document = json.loads(contract.render())
        create_zone = document["paths"]["/api/v1/zones"]["post"]
        schema_ref = create_zone["requestBody"]["content"]["application/json"]["schema"]["$ref"]
        self.assertEqual(schema_ref, "#/components/schemas/CreateZoneReq")
        schema = document["components"]["schemas"]["CreateZoneReq"]
        self.assertIn("domain", schema["required"])
        self.assertEqual(schema["properties"]["template_variables"]["type"], "object")
        self.assertNotIn("/test", document["paths"])
        contract.validate(document)

    def test_compatibility_rejects_new_required_request_fields(self):
        current = {
            "paths": {
                "/zones": {
                    "post": {
                        "requestBody": {
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ZoneReq"}}}
                        }
                    }
                }
            },
            "components": {
                "schemas": {
                    "ZoneReq": {
                        "type": "object",
                        "properties": {"name": {"type": "string"}, "tenant": {"type": "string"}},
                        "required": ["name", "tenant"],
                    }
                }
            },
        }
        baseline = {
            "paths": {
                "/zones": {
                    "post": {
                        "requestBody": {
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ZoneReq"}}}
                        }
                    }
                }
            },
            "components": {
                "schemas": {"ZoneReq": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}}
            },
        }
        baseline_path = Path(__file__).with_suffix(".baseline.tmp.json")
        try:
            baseline_path.write_text(json.dumps(baseline))
            with self.assertRaisesRegex(ValueError, "new required properties in ZoneReq: tenant"):
                contract.check_breaking_changes(current, baseline_path)
        finally:
            baseline_path.unlink(missing_ok=True)

    def test_generic_legacy_request_placeholder_is_tolerated_during_schema_upgrade(self):
        current = {"paths": {"/zones": {"post": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/ZoneReq"}}}}}}}, "components": {"schemas": {"ZoneReq": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}}}}
        baseline = {"/zones": {"post": {"requestBody": {"content": {"application/json": {"schema": {"type": "object", "additionalProperties": True}}}}}}, "/test": {"get": {}}}
        baseline_path = Path(__file__).with_suffix(".baseline.tmp.json")
        try:
            baseline_path.write_text(json.dumps(baseline))
            contract.check_breaking_changes(current, baseline_path)
        finally:
            baseline_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()

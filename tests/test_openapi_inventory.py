import hashlib
import json
import socket

import pytest

import permitprobe.openapi_inventory as inventory_module
from permitprobe.cli import main
from permitprobe.openapi_inventory import inventory_openapi
from permitprobe.policy import Policy, PolicyError
from permitprobe.report import Report


def inventory_policy():
    denial = {
        "type": "object",
        "required": ["error"],
        "properties": {"error": {"type": "string"}},
        "additionalProperties": False,
    }
    return {
        "version": 1,
        "api": {
            "base_url": "https://staging.example.invalid",
            "subjects": [
                {"name": "anon", "role": "anonymous"},
                {
                    "name": "alice",
                    "role": "user",
                    "token_env": "PP_ALICE_TOKEN",
                    "attributes": {"document_id": "alice"},
                },
                {
                    "name": "bob",
                    "role": "user",
                    "token_env": "PP_BOB_TOKEN",
                    "attributes": {"document_id": "bob"},
                },
            ],
            "resources": [
                {
                    "name": "documents",
                    "path": "/documents/{id}",
                    "kind": "object",
                    "owner_param": "id",
                    "owner_attr": "document_id",
                    "identity_pointer": "/id",
                    "allow": [{"role": "user", "scope": "own"}],
                    "response_schema": {
                        "type": "object",
                        "required": ["id"],
                        "properties": {"id": {"type": "string"}},
                        "additionalProperties": False,
                    },
                    "denial_schema": denial,
                }
            ],
            "public_resources": [
                {
                    "name": "search",
                    "path": "/search",
                    "query": [{"name": "q", "value": "synthetic"}],
                    "expected_statuses": [200],
                    "max_elapsed_ms": 1000,
                }
            ],
        },
    }


def openapi_document():
    return {
        "openapi": "3.1.0",
        "info": {"title": "Synthetic API", "version": "1"},
        "security": [{"bearerAuth": []}],
        "paths": {
            "/documents/{documentId}": {
                "get": {
                    "operationId": "getDocument",
                    "responses": {"200": {"description": "ok"}},
                }
            },
            "/search": {
                "parameters": [
                    {"$ref": "#/components/parameters/SearchQuery"},
                ],
                "get": {
                    "operationId": "search",
                    "security": [],
                    "responses": {"200": {"description": "DO-NOT-REPORT"}},
                },
                "post": {
                    "operationId": "unsupportedWrite",
                    "security": [],
                    "responses": {"204": {"description": "created"}},
                },
            },
        },
        "components": {
            "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}},
            "parameters": {
                "SearchQuery": {
                    "name": "q",
                    "in": "query",
                    "required": True,
                    "schema": {"type": "string"},
                    "example": "DO-NOT-REPORT",
                }
            },
        },
    }


def write_inputs(tmp_path, policy=None, document=None):
    policy_path = tmp_path / "policy.json"
    openapi_path = tmp_path / "openapi.json"
    policy_path.write_text(json.dumps(policy or inventory_policy()))
    openapi_path.write_text(json.dumps(document or openapi_document()))
    return policy_path, openapi_path


def test_inventory_covers_public_and_protected_gets_without_credentials(tmp_path, monkeypatch):
    def reject_network(*_):
        raise AssertionError("inventory attempted network access")

    monkeypatch.delenv("PP_ALICE_TOKEN", raising=False)
    monkeypatch.delenv("PP_BOB_TOKEN", raising=False)
    monkeypatch.setattr(socket.socket, "connect", reject_network)
    _, openapi_path = write_inputs(tmp_path)
    report = Report()
    inventory_openapi(Policy.model_validate(inventory_policy()).api, openapi_path, report)
    assert report.exit_code == 0, report.to_dict()
    assert report.inventory == {
        "format": "openapi",
        "version": "3.1.0",
        "document_sha256": hashlib.sha256(openapi_path.read_bytes()).hexdigest(),
        "operations": 3,
        "get_operations": 2,
        "covered_get_operations": 2,
        "uncovered_get_operations": 0,
        "unsupported_non_get_operations": 1,
        "declared_check_resources": 2,
        "stale_check_resources": 0,
    }
    assert all(check.outcome == "pass" for check in report.checks)
    assert len(report.policy_digest) == 64
    assert len(report.inventory["document_sha256"]) == 64
    assert "DO-NOT-REPORT" not in json.dumps(report.to_dict())
    assert not report.evidence


def test_inventory_reports_uncovered_get_and_stale_policy(tmp_path):
    document = openapi_document()
    document["paths"].pop("/documents/{documentId}")
    document["paths"]["/health"] = {"get": {"security": [], "responses": {}}}
    _, openapi_path = write_inputs(tmp_path, document=document)
    report = Report()
    inventory_openapi(Policy.model_validate(inventory_policy()).api, openapi_path, report)
    assert report.exit_code == 1
    assert report.inventory["uncovered_get_operations"] == 1
    assert report.inventory["stale_check_resources"] == 1
    assert {check.code for check in report.checks if check.outcome == "fail"} == {
        "inventory.coverage",
        "inventory.stale_policy",
    }


def test_inventory_detects_security_and_required_query_mismatches(tmp_path):
    document = openapi_document()
    document["paths"]["/search"]["get"].pop("security")
    policy = inventory_policy()
    policy["api"]["public_resources"][0]["query"] = []
    _, openapi_path = write_inputs(tmp_path, policy, document)
    report = Report()
    inventory_openapi(Policy.model_validate(policy).api, openapi_path, report)
    assert report.exit_code == 1
    failures = {check.code for check in report.checks if check.outcome == "fail"}
    assert failures == {"inventory.security"}

    document["paths"]["/search"]["get"]["security"] = []
    openapi_path.write_text(json.dumps(document))
    report = Report()
    inventory_openapi(Policy.model_validate(policy).api, openapi_path, report)
    assert report.exit_code == 1
    assert any(check.code == "inventory.query" for check in report.checks)


def test_operation_parameter_overrides_path_parameter(tmp_path):
    document = openapi_document()
    document["paths"]["/search"]["get"]["parameters"] = [
        {"name": "q", "in": "query", "required": False}
    ]
    policy = inventory_policy()
    policy["api"]["public_resources"][0]["query"] = []
    _, openapi_path = write_inputs(tmp_path, policy, document)
    report = Report()
    inventory_openapi(Policy.model_validate(policy).api, openapi_path, report)
    assert report.exit_code == 0, report.to_dict()


@pytest.mark.parametrize(
    "mutate",
    [
        lambda document: document.update(openapi="2.0"),
        lambda document: document.update(paths=[]),
        lambda document: document["paths"]["/search"].update(get=[]),
        lambda document: document["paths"]["/search"]["get"].update(security="public"),
        lambda document: document.update(security=[{"unknownScheme": []}]),
        lambda document: document["components"]["parameters"]["SearchQuery"].update(required="yes"),
        lambda document: document["paths"]["/search"].update(
            parameters=[{"$ref": "https://example.invalid/parameter.json"}]
        ),
    ],
)
def test_invalid_or_ambiguous_openapi_is_rejected(tmp_path, mutate):
    document = openapi_document()
    mutate(document)
    _, openapi_path = write_inputs(tmp_path, document=document)
    with pytest.raises(PolicyError):
        inventory_openapi(Policy.model_validate(inventory_policy()).api, openapi_path, Report())


def test_duplicate_keys_and_size_limit_are_rejected(tmp_path, monkeypatch):
    path = tmp_path / "openapi.json"
    path.write_text('{"openapi":"3.1.0","paths":{},"paths":{}}')
    with pytest.raises(PolicyError):
        inventory_openapi(Policy.model_validate(inventory_policy()).api, path, Report())

    monkeypatch.setattr(inventory_module, "MAX_OPENAPI_BYTES", 10)
    path.write_text("{}" * 6)
    with pytest.raises(PolicyError):
        inventory_openapi(Policy.model_validate(inventory_policy()).api, path, Report())


def test_duplicate_structural_operations_and_parameters_are_rejected(tmp_path):
    document = openapi_document()
    document["paths"]["/documents/{other}"] = document["paths"]["/documents/{documentId}"]
    _, openapi_path = write_inputs(tmp_path, document=document)
    with pytest.raises(PolicyError):
        inventory_openapi(Policy.model_validate(inventory_policy()).api, openapi_path, Report())

    document = openapi_document()
    reference = {"$ref": "#/components/parameters/SearchQuery"}
    document["paths"]["/search"]["parameters"] = [reference, reference]
    openapi_path.write_text(json.dumps(document))
    with pytest.raises(PolicyError):
        inventory_openapi(Policy.model_validate(inventory_policy()).api, openapi_path, Report())


def test_inventory_cli_writes_exclusive_report(tmp_path, capsys):
    policy_path, openapi_path = write_inputs(tmp_path)
    output = tmp_path / "inventory-report.json"
    args = [
        "inventory-openapi",
        str(policy_path),
        "--openapi",
        str(openapi_path),
        "--format",
        "json",
        "--report",
        str(output),
    ]
    assert main(args) == 0
    payload = json.loads(output.read_text())
    assert payload["inventory"]["covered_get_operations"] == 2
    assert json.loads(capsys.readouterr().out) == payload
    assert main(args) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "inconclusive"

    text_args = [
        "inventory-openapi",
        str(policy_path),
        "--openapi",
        str(openapi_path),
    ]
    assert main(text_args) == 0
    assert "OpenAPI GET coverage: 2/2; non-GET not executed: 1" in capsys.readouterr().out


def test_public_only_inventory_is_supported(tmp_path):
    policy = inventory_policy()
    policy["api"].pop("subjects")
    policy["api"].pop("resources")
    document = openapi_document()
    document["paths"].pop("/documents/{documentId}")
    _, openapi_path = write_inputs(tmp_path, policy, document)
    report = Report()
    inventory_openapi(Policy.model_validate(policy).api, openapi_path, report)
    assert report.exit_code == 0, report.to_dict()


def test_published_openapi_example_matches_the_starter_policy():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    policy = Policy.model_validate_json((root / "examples/permitprobe.json").read_text())
    report = Report()
    inventory_openapi(policy.api, root / "examples/openapi.json", report)
    assert report.exit_code == 0, report.to_dict()
    assert report.inventory["unsupported_non_get_operations"] == 1

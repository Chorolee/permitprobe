import json
import time
from decimal import Decimal

import pytest

import permitprobe.api as api_module
from permitprobe.api import check_api
from permitprobe.demo import demo_environment, example_policy
from permitprobe.policy import Policy
from permitprobe.report import Report
from permitprobe.validation import exact_json_loads, exact_validator


def test_response_numbers_keep_json_decimal_precision():
    data = exact_json_loads('{"sequence":9007199254740993.0}')
    errors = list(
        exact_validator(
            {
                "type": "object",
                "properties": {"sequence": {"const": 9007199254740992}},
            }
        ).iter_errors(data)
    )
    assert errors


def test_exact_numbers_preserve_json_schema_integer_and_multiple_semantics():
    validator = exact_validator({"type": "integer", "multipleOf": 0.1})
    assert not list(validator.iter_errors(Decimal("1.0")))
    assert list(validator.iter_errors(Decimal("1.01")))
    assert not list(validator.iter_errors(Decimal("1e100")))


def test_extreme_json_number_is_rejected_without_decimal_arithmetic_failure():
    with pytest.raises(ValueError, match="too large"):
        exact_json_loads("1e999999999")


def test_authorization_response_validation_is_stopped_by_total_budget(monkeypatch):
    data = example_policy()
    resource = data["api"]["resources"][0]
    resource.update(
        kind="function",
        path="/expensive",
        owner_param=None,
        owner_attr=None,
        identity_pointer=None,
        allow=[{"role": "user", "scope": "any"}],
        response_schema={"type": "string", "pattern": "^(a+)+$"},
    )
    config = Policy.model_validate(data).api
    config.validation_timeout_ms = 50

    async def immediate_response(_url, headers, *_args, **_kwargs):
        if headers.get("Authorization"):
            return 200, json.dumps("a" * 34 + "!"), {}
        return 403, '{"error":"denied"}', {}

    monkeypatch.setattr(api_module, "fetch", immediate_response)
    started = time.monotonic()
    report = Report()
    with demo_environment():
        check_api(config, report)
    assert time.monotonic() - started < 1
    assert report.exit_code == 2
    assert any(check.code == "data.validation_budget" for check in report.checks)

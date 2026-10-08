import json
import time

import permitprobe.api as api_module
from permitprobe.api import check_api
from permitprobe.demo import demo_environment, example_policy
from permitprobe.policy import Policy
from permitprobe.report import Report


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

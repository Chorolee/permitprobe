"""Fail-closed parsing and wall-clock budgets for response validation."""

import json
import signal
import threading
from contextlib import contextmanager
from decimal import Decimal, DecimalException, localcontext
from math import isfinite
from time import monotonic

from jsonschema import Draft202012Validator, validators
from jsonschema.exceptions import ValidationError

MAX_SCHEMA_ERRORS = 16
MAX_JSON_NUMBER_DIGITS = 4_096
MAX_JSON_NUMBER_EXPONENT = 4_096


class ValidationBudgetExceeded(RuntimeError):
    pass


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def bounded_json_int(raw: str) -> int:
    if len(raw.removeprefix("-")) > MAX_JSON_NUMBER_DIGITS:
        raise ValueError("JSON integer is too large")
    return int(raw)


def bounded_json_decimal(raw: str) -> Decimal:
    try:
        value = Decimal(raw)
        if (
            not value.is_finite()
            or len(value.as_tuple().digits) > MAX_JSON_NUMBER_DIGITS
            or abs(value.adjusted()) > MAX_JSON_NUMBER_EXPONENT
            or abs(value.as_tuple().exponent) > MAX_JSON_NUMBER_EXPONENT
        ):
            raise ValueError("JSON decimal is too large")
        return value
    except DecimalException:
        raise ValueError("invalid JSON decimal") from None


def exact_json_loads(text: str):
    """Parse response JSON without rounding finite decimal numbers."""

    return json.loads(
        text,
        object_pairs_hook=_unique_pairs,
        parse_float=bounded_json_decimal,
        parse_int=bounded_json_int,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
    )


def _exact_schema_numbers(value):
    if type(value) is float:
        if not isfinite(value):
            raise ValueError("non-finite schema number")
        return Decimal(str(value))
    if isinstance(value, dict):
        return {key: _exact_schema_numbers(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_exact_schema_numbers(item) for item in value]
    return value


def _is_exact_integer(checker, instance):
    if isinstance(instance, bool):
        return False
    if isinstance(instance, int):
        return True
    return isinstance(instance, Decimal) and instance == instance.to_integral_value()


def _exact_multiple_of(validator, divisor, instance, schema):
    if not validator.is_type(instance, "number"):
        return
    try:
        left = Decimal(instance) if isinstance(instance, int) else instance
        right = Decimal(divisor) if isinstance(divisor, int) else divisor
        precision = (
            max(len(left.as_tuple().digits), len(right.as_tuple().digits))
            + abs(left.adjusted() - right.adjusted())
            + 2
        )
        if precision > MAX_JSON_NUMBER_DIGITS * 2 + 2:
            raise ValueError("numeric validation budget exceeded")
        with localcontext() as context:
            context.prec = max(precision, 28)
            failed = left % right != 0
    except (AttributeError, DecimalException, TypeError, ValueError):
        yield ValidationError("number cannot be evaluated safely against multipleOf")
        return
    if failed:
        yield ValidationError(f"{instance!r} is not a multiple of {divisor}")


_EXACT_TYPE_CHECKER = Draft202012Validator.TYPE_CHECKER.redefine(
    "integer", _is_exact_integer
)
ExactDraft202012Validator = validators.extend(
    Draft202012Validator,
    {"multipleOf": _exact_multiple_of},
    type_checker=_EXACT_TYPE_CHECKER,
)


def exact_validator(schema: dict):
    """Build a validator whose instance and schema arithmetic stays decimal-exact."""

    return ExactDraft202012Validator(_exact_schema_numbers(schema))


class ValidationLimiter:
    """Track only time spent parsing and validating across one execution batch."""

    def __init__(self, seconds: float):
        self.remaining = seconds

    @contextmanager
    def run(self, *, max_seconds: float | None = None):
        allowed = self.remaining
        if max_seconds is not None:
            allowed = min(allowed, max_seconds)
        if allowed <= 0:
            raise ValidationBudgetExceeded
        started = monotonic()
        try:
            with validation_budget(allowed):
                yield
        finally:
            self.remaining = max(0.0, self.remaining - (monotonic() - started))


@contextmanager
def validation_budget(seconds: float):
    """Interrupt validation on POSIX without leaving an alarm behind."""

    if (
        seconds <= 0
        or threading.current_thread() is not threading.main_thread()
        or not hasattr(signal, "setitimer")
    ):
        raise ValidationBudgetExceeded
    previous_delay, _ = signal.getitimer(signal.ITIMER_REAL)
    if previous_delay > 0:
        # Do not replace a caller's deadline with a more permissive timer.
        raise ValidationBudgetExceeded
    previous_handler = signal.getsignal(signal.SIGALRM)

    def expired(_signum, _frame):
        raise ValidationBudgetExceeded

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


def schema_errors(validator, data) -> list:
    """Collect only the bounded error metadata used by normalized reports."""

    errors = []
    for error in validator.iter_errors(data):
        errors.append(error)
        if len(errors) >= MAX_SCHEMA_ERRORS:
            break
    return errors

"""Fail-closed wall-clock budgets for local response validation."""

import signal
import threading
from contextlib import contextmanager
from time import monotonic

MAX_SCHEMA_ERRORS = 16


class ValidationBudgetExceeded(RuntimeError):
    pass


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

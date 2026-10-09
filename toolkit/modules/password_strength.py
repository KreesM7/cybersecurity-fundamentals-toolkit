from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QWidget

    from frontend.viewmodels.tools_vm import ToolsViewModel

import math
from dataclasses import dataclass
from functools import lru_cache
from importlib import import_module

from toolkit.core import ModuleSpec, resource_text


@dataclass
class PasswordReport:
    score: int
    guesses: float
    bits: float
    common: bool
    times: dict[str, float]
    warning: str
    suggestions: list[str]


@lru_cache(maxsize=1)
def common_passwords() -> frozenset[str]:
    return frozenset(
        line.casefold() for line in resource_text("common_passwords.txt").splitlines() if line
    )


def analyze_password(password: str) -> PasswordReport:
    if not password:
        raise ValueError("Enter a password to analyze.")
    if len(password) > 72:
        raise ValueError(
            "The estimator supports up to 72 characters. Input is never silently truncated."
        )
    from zxcvbn import zxcvbn  # type: ignore[import-untyped]

    estimate = zxcvbn(password)
    guesses = max(1.0, float(estimate["guesses"]))
    rates = {
        "Online (10/s)": 10,
        "Offline (10,000/s)": 10000,
        "GPU-style fast hash (10 billion/s)": 10000000000,
    }
    # zxcvbn also returns the plaintext and matched tokens. Neither belongs in the report.
    return PasswordReport(
        estimate["score"],
        guesses,
        math.log2(guesses),
        password.casefold() in common_passwords(),
        {label: guesses / rate for label, rate in rates.items()},
        estimate["feedback"]["warning"],
        estimate["feedback"]["suggestions"],
    )


def format_time(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds:.3g} seconds"
    for divisor, unit in ((31557600, "years"), (86400, "days"), (3600, "hours"), (60, "minutes")):
        if seconds >= divisor:
            return f"{seconds / divisor:.3g} {unit}"
    return f"{seconds:.3g} seconds"


def readiness() -> str:
    try:
        import_module("zxcvbn")

        common_passwords()
    except (ImportError, OSError) as exc:
        return "Setup needed: install requirements.txt and restore bundled resources. " + str(exc)
    return ""


def create_panel(context: ToolsViewModel) -> QWidget:
    from frontend.views.tools import create_panel as factory

    return factory(MODULE.id, context)


MODULE = ModuleSpec("password-strength", "Password Strength", 20, create_panel)

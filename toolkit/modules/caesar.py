from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QWidget

    from frontend.viewmodels.tools_vm import ToolsViewModel

from toolkit.core import ModuleSpec


def transform(text: str, shift: int, decrypt: bool = False) -> str:
    if type(shift) is not int or not 1 <= shift <= 25:
        raise ValueError("Shift must be an integer between 1 and 25.")
    amount = -shift if decrypt else shift
    output = []
    for character in text:
        if "a" <= character <= "z":
            output.append(chr((ord(character) - ord("a") + amount) % 26 + ord("a")))
        elif "A" <= character <= "Z":
            output.append(chr((ord(character) - ord("A") + amount) % 26 + ord("A")))
        else:
            output.append(character)
    return "".join(output)


def brute_force(text: str) -> list[tuple[int, str]]:
    return [(shift, transform(text, shift, decrypt=True)) for shift in range(1, 26)]


def create_panel(context: ToolsViewModel) -> QWidget:
    from frontend.views.tools import create_panel as factory

    return factory(MODULE.id, context)


MODULE = ModuleSpec("caesar", "Caesar Cipher", 10, create_panel)

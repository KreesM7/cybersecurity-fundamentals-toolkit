"""Compatibility import for pure analysis contexts. Desktop tasks use REST jobs."""

from toolkit.task_context import Cancelled, TaskContext

__all__ = ["Cancelled", "TaskContext"]

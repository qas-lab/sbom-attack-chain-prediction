"""
Utilities for CLI including mock Click implementation for graceful fallback.
"""

import sys
from pathlib import Path
from typing import Any

from .output import CLIOutputManager, create_output_manager

try:
    import click

    CLICK_AVAILABLE = True
except ImportError:
    CLICK_AVAILABLE = False

    # Create a mock click object with necessary attributes
    class MockContext:
        def __init__(self):
            self.obj = {}

        def ensure_object(self, obj_type):
            if not self.obj:
                self.obj = obj_type()

    class MockClick:
        @staticmethod
        def command(*args, **kwargs):
            def decorator(func):
                # For CLI commands, we need to handle the fallback case
                def wrapper(*args, **kwargs):
                    print("Click is not available. CLI functionality disabled.")
                    return None

                return wrapper

            return decorator

        @staticmethod
        def option(*args, **kwargs):
            def decorator(func):
                return func

            return decorator

        @staticmethod
        def argument(*args, **kwargs):
            def decorator(func):
                return func

            return decorator

        @staticmethod
        def group(*args, **kwargs):
            def decorator(func):
                # For group commands, create a simple wrapper
                def wrapper(*args, **kwargs):
                    print("Click is not available. CLI functionality disabled.")
                    return None

                return wrapper

            return decorator

        @staticmethod
        def pass_context(*args, **kwargs):
            def decorator(func):
                return func

            return decorator

        @staticmethod
        def echo(message, err=False):
            if err:
                print(message, file=sys.stderr)
            else:
                print(message)

        @staticmethod
        def Choice(choices):
            return str

        @staticmethod
        def Path(**kwargs):
            return Path

        @staticmethod
        def confirm(text, default=False):
            """Mock confirm that defaults to False"""
            print(f"{text} [y/N]: ", end="")
            try:
                response = input().strip().lower()
                return response in ("y", "yes")
            except (EOFError, KeyboardInterrupt):
                return False

        @staticmethod
        def prompt(text, default=None, hide_input=False):
            """Mock prompt for user input"""
            import getpass

            prompt_text = f"{text}: "
            if default:
                prompt_text = f"{text} [{default}]: "

            try:
                if hide_input:
                    return getpass.getpass(prompt_text)
                else:
                    return input(prompt_text) or default
            except (EOFError, KeyboardInterrupt):
                return default

    click = MockClick()  # type: ignore[misc,assignment]


def get_click():
    """Get click module (real or mock)."""
    return click, CLICK_AVAILABLE


def get_cli_flags(ctx) -> dict[str, Any]:
    """Extract CLI flags from Click context, traversing parent contexts."""
    flags = {}

    # Traverse up the context chain to find global flags
    current_ctx = ctx
    while current_ctx:
        if hasattr(current_ctx, "params") and current_ctx.params:
            # Update with current context params (child overrides parent)
            flags.update(current_ctx.params)
        current_ctx = getattr(current_ctx, "parent", None)

    return flags


def get_output_manager_from_context(ctx) -> CLIOutputManager:
    """Create output manager from Click context flags."""
    flags = get_cli_flags(ctx)

    quiet = flags.get("quiet", False)
    verbose = flags.get("verbose", False)

    return create_output_manager(quiet=quiet, verbose=verbose)


def get_cli_verbosity(ctx) -> tuple[bool, bool]:
    """Get quiet and verbose flags from context."""
    flags = get_cli_flags(ctx)
    return flags.get("quiet", False), flags.get("verbose", False)


def pass_cli_config(func):
    """Decorator to inject CLI configuration into command functions."""

    def wrapper(*args, **kwargs):
        # Look for Click context in args
        ctx = None
        for arg in args:
            if hasattr(arg, "obj") and hasattr(arg, "params"):
                ctx = arg
                break

        if ctx:
            # Inject output manager and flags
            kwargs["output_manager"] = get_output_manager_from_context(ctx)
            kwargs["cli_flags"] = get_cli_flags(ctx)

        return func(*args, **kwargs)

    return wrapper

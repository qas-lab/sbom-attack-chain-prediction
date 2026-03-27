"""
Centralized CLI output management system.

Provides consistent output handling across all CLI commands with respect for
global --quiet and --verbose flags.
"""

import sys
from enum import Enum
from typing import Optional

try:
    from rich.console import Console
    from rich.progress import Progress

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class OutputLevel(Enum):
    """Output verbosity levels."""

    QUIET = "quiet"  # Only errors and critical information
    NORMAL = "normal"  # Standard output
    VERBOSE = "verbose"  # Detailed output including debug information


class CLIOutputManager:
    """Centralized output manager for CLI commands."""

    def __init__(
        self,
        level: OutputLevel = OutputLevel.NORMAL,
        use_colors: bool = True,
        stderr_for_errors: bool = True,
    ):
        self.level = level
        self.use_colors = use_colors
        self.stderr_for_errors = stderr_for_errors

        # Initialize Rich console if available
        if RICH_AVAILABLE:
            self.console = Console(
                stderr=False, force_terminal=use_colors, quiet=(level == OutputLevel.QUIET)
            )
            self.error_console = Console(
                stderr=True,
                force_terminal=use_colors,
                quiet=False,  # Never quiet for errors
            )
        else:
            self.console = None
            self.error_console = None

    def info(self, message: str, **kwargs) -> None:
        """Print informational message."""
        if self.level == OutputLevel.QUIET:
            return

        if self.console:
            self.console.print(message, **kwargs)
        else:
            print(message)

    def success(self, message: str, **kwargs) -> None:
        """Print success message."""
        if self.level == OutputLevel.QUIET:
            return

        if self.console:
            self.console.print(f"✓ {message}", style="green", **kwargs)
        else:
            print(f"✓ {message}")

    def warning(self, message: str, **kwargs) -> None:
        """Print warning message."""
        if self.console:
            self.console.print(f"⚠️  {message}", style="yellow", **kwargs)
        else:
            print(f"⚠️  {message}", file=sys.stderr if self.stderr_for_errors else sys.stdout)

    def error(self, message: str, **kwargs) -> None:
        """Print error message (always shown regardless of quiet mode)."""
        if self.error_console:
            self.error_console.print(f"❌ {message}", style="red bold", **kwargs)
        elif self.console:
            self.console.print(f"❌ {message}", style="red bold", **kwargs)
        else:
            print(f"❌ {message}", file=sys.stderr)

    def debug(self, message: str, **kwargs) -> None:
        """Print debug message (only in verbose mode)."""
        if self.level != OutputLevel.VERBOSE:
            return

        if self.console:
            self.console.print(f"🔍 {message}", style="dim", **kwargs)
        else:
            print(f"🔍 {message}")

    def status(self, message: str, **kwargs) -> None:
        """Print status message."""
        if self.level == OutputLevel.QUIET:
            return

        if self.console:
            self.console.print(f"📋 {message}", **kwargs)
        else:
            print(f"📋 {message}")

    def progress_info(self, message: str, **kwargs) -> None:
        """Print progress-related information."""
        if self.level == OutputLevel.QUIET:
            return

        if self.console:
            self.console.print(f"⏳ {message}", **kwargs)
        else:
            print(f"⏳ {message}")

    def test_info(self, message: str, **kwargs) -> None:
        """Print test-related information."""
        if self.level == OutputLevel.QUIET:
            return

        if self.console:
            self.console.print(f"🧪 {message}", **kwargs)
        else:
            print(f"🧪 {message}")

    def interrupt_info(self, message: str, **kwargs) -> None:
        """Print interruption information (always shown)."""
        if self.console:
            self.console.print(f"⚠️  {message}", style="yellow bold", **kwargs)
        else:
            print(f"⚠️  {message}", file=sys.stderr)

    def system_info(self, message: str, **kwargs) -> None:
        """Print system-level information."""
        if self.level == OutputLevel.QUIET:
            return

        if self.console:
            self.console.print(f"🔄 {message}", **kwargs)
        else:
            print(f"🔄 {message}")

    def final_results(self, message: str, **kwargs) -> None:
        """Print final results (always shown)."""
        if self.console:
            self.console.print(f"📊 {message}", style="bold", **kwargs)
        else:
            print(f"📊 {message}")

    def print_raw(self, message: str, end: str = "\n", flush: bool = False) -> None:
        """Print raw message without formatting (for streaming output)."""
        if self.level == OutputLevel.QUIET:
            return

        # Use consistent output method regardless of mode
        try:
            sys.stdout.write(message)
            if end:
                sys.stdout.write(end)
            if flush or self.level == OutputLevel.VERBOSE:
                sys.stdout.flush()
        except (OSError, UnicodeEncodeError):
            # Fallback - should rarely be needed
            print(message, end=end, flush=flush)

    def create_progress(self, *args, **kwargs) -> Optional["Progress"]:
        """Create a Rich progress bar if available and not in quiet mode."""
        if self.level == OutputLevel.QUIET:
            return None

        if RICH_AVAILABLE:
            # Ensure transient=True to prevent hanging on exit
            kwargs.setdefault("transient", True)
            return Progress(*args, **kwargs)
        return None

    @property
    def is_quiet(self) -> bool:
        """Check if output manager is in quiet mode."""
        return self.level == OutputLevel.QUIET

    @property
    def is_verbose(self) -> bool:
        """Check if output manager is in verbose mode."""
        return self.level == OutputLevel.VERBOSE

    @property
    def rich_console(self) -> Optional["Console"]:
        """Get the Rich console instance if available."""
        return self.console if RICH_AVAILABLE else None


def create_output_manager(
    quiet: bool = False, verbose: bool = False, use_colors: bool = True
) -> CLIOutputManager:
    """Factory function to create output manager from CLI flags."""
    if quiet:
        level = OutputLevel.QUIET
    elif verbose:
        level = OutputLevel.VERBOSE
    else:
        level = OutputLevel.NORMAL

    return CLIOutputManager(level=level, use_colors=use_colors)

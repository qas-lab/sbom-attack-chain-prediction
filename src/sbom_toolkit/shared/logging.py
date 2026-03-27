"""
Logging utilities for SBOM toolkit.
"""

import logging
import sys
from pathlib import Path

try:
    from rich.console import Console
    from rich.logging import RichHandler

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


def setup_logging(
    level: str = "INFO", log_file: Path | None = None, use_rich: bool = True
) -> logging.Logger:
    """Set up logging configuration.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file
        use_rich: Whether to use Rich formatting for console output

    Returns:
        Configured logger instance
    """
    # Create logger
    logger = logging.getLogger("sbom_toolkit")
    logger.setLevel(getattr(logging, level.upper()))

    # Remove existing handlers to avoid duplicates
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Console handler
    if use_rich and RICH_AVAILABLE:
        console = Console(stderr=True)
        console_handler = RichHandler(console=console, show_time=True, show_path=False, markup=True)
        formatter = logging.Formatter(fmt="%(message)s", datefmt="[%X]")
    else:
        console_handler = logging.StreamHandler(sys.stderr)
        formatter = logging.Formatter(
            fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler (if specified)
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_formatter = logging.Formatter(
            fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str = "sbom_toolkit") -> logging.Logger:
    """Get a logger instance.

    Args:
        name: Logger name

    Returns:
        Logger instance
    """
    return logging.getLogger(name)


class ProgressLogger:
    """Logger for tracking progress of long-running operations."""

    def __init__(self, logger: logging.Logger | None = None, use_rich: bool = True):
        """Initialize progress logger.

        Args:
            logger: Logger instance to use
            use_rich: Whether to use Rich console for output
        """
        self.logger = logger or get_logger()
        self.use_rich = use_rich and RICH_AVAILABLE
        if self.use_rich:
            self.console = Console()

    def start_operation(self, operation_name: str, total_items: int | None = None):
        """Start tracking an operation.

        Args:
            operation_name: Name of the operation
            total_items: Total number of items to process (if known)
        """
        if total_items:
            message = f"Starting {operation_name} ({total_items} items)..."
        else:
            message = f"Starting {operation_name}..."

        if self.use_rich:
            self.console.print(message, style="blue bold")
        else:
            self.logger.info(message)

    def log_progress(self, current: int, total: int, item_name: str = "items"):
        """Log progress of an operation.

        Args:
            current: Current number of processed items
            total: Total number of items
            item_name: Name for the items being processed
        """
        percentage = (current / total) * 100 if total > 0 else 0
        message = f"Progress: {current}/{total} {item_name} ({percentage:.1f}%)"

        if self.use_rich:
            self.console.print(message, style="cyan")
        else:
            self.logger.info(message)

    def log_item_processed(self, item_name: str, success: bool = True):
        """Log processing of an individual item.

        Args:
            item_name: Name of the processed item
            success: Whether processing was successful
        """
        if success:
            symbol = "✓" if self.use_rich else "SUCCESS"
            style = "green"
        else:
            symbol = "✗" if self.use_rich else "FAILED"
            style = "red"

        message = f"{symbol} {item_name}"

        if self.use_rich:
            self.console.print(f"  {message}", style=style)
        else:
            level = logging.INFO if success else logging.ERROR
            self.logger.log(level, message)

    def finish_operation(
        self,
        operation_name: str,
        success_count: int,
        total_count: int,
        duration: float | None = None,
    ):
        """Finish tracking an operation.

        Args:
            operation_name: Name of the operation
            success_count: Number of successful items
            total_count: Total number of items processed
            duration: Duration in seconds (if measured)
        """
        failure_count = total_count - success_count

        if duration:
            duration_str = f" in {duration:.2f}s"
        else:
            duration_str = ""

        if failure_count == 0:
            message = f"✅ {operation_name} completed successfully: {success_count}/{total_count} items{duration_str}"
            style = "green bold"
        else:
            message = f"⚠️  {operation_name} completed with errors: {success_count}/{total_count} items successful{duration_str}"
            style = "yellow bold"

        if self.use_rich:
            self.console.print(message, style=style)
        else:
            self.logger.info(message)

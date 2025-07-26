import logging
from typing import Dict

class DispatchingFormatter(logging.Formatter):
    """
    DispatchingFormatter class allows for the creation of
    different formatters to be created and then called upon
    with the __name__ of the module or a specified name
    """

    def __init__(
        self,
        formatters: Dict[str, logging.Formatter],
        default_formatter: logging.Formatter,
    ):
        """
        Initialize DispatchingFormatter.

        Args:
            formatters: Dictionary mapping logger names to formatters
            default_formatter: Default formatter to use when no specific formatter found
        """
        super().__init__()
        self._formatters = formatters
        self._default_formatter = default_formatter

    def format(self, record: logging.LogRecord) -> str:
        """
        Format a log record using the appropriate formatter.

        Args:
            record: The log record to format

        Returns:
            Formatted log message
        """
        formatter = self._formatters.get(record.name, self._default_formatter)
        return formatter.format(record)


class CustomGeneralLogFormatter(logging.Formatter):
    """
    Custom formatter with colored output. The formatter
    is used for all normal logging messages.
    """

    green = "\033[92m"
    grey = "\033[92m"
    yellow = "\033[93m"
    red = "\033[91m"
    bold_red = f"\033[1m{red}"
    reset = "\033[0m"
    fmt = (
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"
    )
    FORMATS = {
        logging.DEBUG: f"{grey}{fmt}{reset}",
        logging.INFO: f"{green}{fmt}{reset}",
        logging.WARNING: f"{yellow}{fmt}{reset}",
        logging.ERROR: f"{red}{fmt}{reset}",
        logging.CRITICAL: f"{bold_red}{fmt}{reset}",
    }

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with appropriate color and style."""
        return logging.Formatter(self.FORMATS.get(record.levelno)).format(record)


class CustomMessageFormatter(logging.Formatter):
    """
    Custom formatter with colored output. The formatter
    is used for all print styled messages that isn't
    normal logging.
    """

    bg_green = "\033[102m"
    bg_yellow = "\033[43m"
    green = "\033[92m"
    grey = "\033[90m"
    yellow = "\033[93m"
    red = "\033[101m"
    black = "\033[30m"
    reset = "\033[0m"
    fmt = "%(message)s"
    FORMATS = {
        logging.DEBUG: f"{grey}{fmt}{reset}",
        logging.INFO: f"{bg_green}{black}{fmt}{reset}",
        logging.WARNING: f"{bg_yellow}{black}{fmt}{reset}",
        logging.ERROR: f"{red}{fmt}{reset}",
        logging.CRITICAL: f"{red}{fmt}{reset}",
    }

    def format(self, record: logging.LogRecord) -> str:
        """Format message-style log record with appropriate color and style."""
        return logging.Formatter(self.FORMATS.get(record.levelno)).format(record)


def setup_logging(verbose: bool = False) -> None:
    """
    Set up logging with custom formatter.

    Args:
        verbose: Enable debug level logging if True
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    # Remove all handlers first to avoid duplicate logs
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    handler = logging.StreamHandler()
    handler.setFormatter(
        DispatchingFormatter(
            {"default": CustomMessageFormatter()}, CustomGeneralLogFormatter()
        )
    )
    root_logger.addHandler(handler)
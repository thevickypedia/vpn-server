class NotImplementedWarning(Warning):
    """Custom implementation warning."""


class AWSResourceError(Exception):
    """Custom resource error for AWS resources."""

    def __init__(self, status_code: int, error_msg: str):
        self.status_code = status_code
        self.error_msg = error_msg

    def __str__(self):
        """Returns string formatted text."""
        return f"\n\t[{self.status_code}] - {self.error_msg}"

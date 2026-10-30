class ApiError(Exception):
    """An error with a stable code the web app can switch on; main.py turns it into JSON."""

    def __init__(self, status: int, code: str, message: str, headers: dict[str, str] | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.headers = headers or {}

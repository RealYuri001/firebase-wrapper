from typing import Optional

__all__ = (
    'APIError',
    'HTTPExceptionError',
    'UnauthorizedError',
    'NotFoundError',
)

class APIError(Exception):
    """Common base class for API exceptions."""
    pass

class HTTPExceptionError(APIError):
    def __init__(self, message: Optional[str] = None):
        self.message = message
        super().__init__(message)
        
class UnauthorizedError(HTTPExceptionError):
    def __init__(self, message: Optional[str] = None):
        self.message = message
        super().__init__(message)
        
class NotFoundError(HTTPExceptionError):
    def __init__(self, message: Optional[str] = None):
        self.message = message
        super().__init__(message)
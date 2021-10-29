from cdiserrors import APIError


class NoKeyError(APIError):
    def __init__(self, message):
        self.message = message
        self.code = 500

class KeyPathInvalidError(APIError):
    def __init__(self, message):
        self.message = message
        self.code = 500

class Unauthorized(APIError):
    """
    Used for AuthN-related errors in most cases.
    """
    def __init__(self, message):
        super(Unauthorized, self).__init__(message)
        self.message = str(message)
        self.code = 401
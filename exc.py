class BadResponse(Exception):
    def __init__(self, message):
        super().__init__(message)


class RequestFailure(Exception):
    def __init__(self, message, reason):
        super().__init__(message)
        self.reason = reason


class BadRequest(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message

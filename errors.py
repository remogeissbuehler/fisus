class BadInfraStateException(ValueError):
    pass

class UnavailableInfraException(ImportError):
    pass

class MissingKeyException(BadInfraStateException):
    pass
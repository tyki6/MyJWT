class InvalidJWT(Exception):
    def __init__(self, message):
        self.message = message


class InvalidJwtJson(Exception):
    def __init__(self, message):
        self.message = message


class InvalidParam(Exception):
    def __init__(self, message):
        self.message = message


class UnknownAlg(Exception):
    def __init__(self, message):
        self.message = message

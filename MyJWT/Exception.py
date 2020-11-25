"""
Exception package
"""


class InvalidJWT(Exception):
    """
    Invalid JWT
    """
    def __init__(self, message):
        self.message = message


class InvalidJwtJson(Exception):
    """
    Invalid InvalidJwtJson
    """
    def __init__(self, message):
        self.message = message


class InvalidParam(Exception):
    """
    Invalid Param
    """
    def __init__(self, message):
        self.message = message


class UnknownAlg(Exception):
    """
    UnknownAlg
    """
    def __init__(self, message):
        self.message = message

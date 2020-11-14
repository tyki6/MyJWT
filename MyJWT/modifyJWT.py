import base64
import hashlib
import hmac

from MyJWT.Exception import InvalidJwtJson, InvalidParam, UnknownAlg
from MyJWT.utils import encodeJwt, isValidJwtJson, PAYLOAD, HEADER


def addpayload(jwtJson, payload):
    """
    Add new key:value to jwt payload.

    :param dict jwtJson: your jwt json (use encodeToJson.Check Doc)
    :param dict payload: add value to your payload
    :return: dict JWT
    :rtype: dict

    :raise: InvalidJwtJson if your jwtJson is not a dict.
    :raise: InvalidParam if your payload is not a dict.
    """
    if not isValidJwtJson(jwtJson):
        raise InvalidJwtJson("Invalid JWT json format")

    if type(payload) is not dict:
        raise InvalidParam("Invalid Payload")

    for payloadKey in payload.keys():
        jwtJson[PAYLOAD][payloadKey] = payload[payloadKey]
    return jwtJson


def addheader(jwtJson, header):
    """
    Add new key:value to jwt header.

    :param dict jwtJson: your jwt json (use encodeToJson.Check Doc)
    :param dict header: add value to your header
    :return: dict JWT
    :rtype: dict

    :raise: InvalidJwtJson if your jwtJson is not a dict.
    :raise: InvalidParam if your header is not a dict.
    """
    if not isValidJwtJson(jwtJson):
        raise InvalidJwtJson("Invalid JWT json format")

    if type(header) is not dict:
        raise InvalidParam("Invalid Header")

    for headerKey in header.keys():
        jwtJson[HEADER][headerKey] = header[headerKey]
    return jwtJson


def changeAlg(jwtJson, algo):
    """
    Change alg of your jwt

    :param dict jwtJson: your jwt json (use encodeToJson.Check Doc)
    :param str algo: new algo
    :return: dict JWT
    :rtype: dict

    :raise: InvalidJwtJson if your jwtJson is not a dict.
    """
    if not isValidJwtJson(jwtJson):
        raise InvalidJwtJson("Invalid JWT json format")

    jwtJson[HEADER]["alg"] = algo
    return jwtJson


def changePayload(jwtJson, payload):
    """
    Change payload to your jwtJson

    :param dict jwtJson: your jwt json (use encodeToJson.Check Doc)
    :param dict payload: new payload
    :return: dict JWT
    :rtype: dict

    :raise: InvalidJwtJson if your jwtJson is not a dict.
    """
    if not isValidJwtJson(jwtJson):
        raise InvalidJwtJson("Invalid JWT json format")
    jwtJson[PAYLOAD] = payload
    return jwtJson


def signature(jwtJson, key):
    """
    Sign your jwt.

    :param dict jwtJson: your jwt json (use encodeToJson.Check Doc)
    :param str key: new payload
    :return: jwt encoded
    :rtype: str

    :raise: InvalidJwtJson if your jwtJson is not a dict.
    :raise: UnknownAlg if your algo is not know.
    """
    if not isValidJwtJson(jwtJson):
        raise InvalidJwtJson("Invalid JWT json format")

    if jwtJson[HEADER]["alg"] == "none":
        return encodeJwt(jwtJson) + "."
    elif jwtJson[HEADER]["alg"] == "HS256":
        jwt = encodeJwt(jwtJson)
        signature = hmac.new(key.encode(), jwt.encode(), hashlib.sha256).digest()
        newSig = base64.urlsafe_b64encode(signature).decode("UTF-8").strip("=")
        return jwt + "." + newSig
    elif jwtJson[HEADER]["alg"] == "HS384":
        jwt = encodeJwt(jwtJson)
        signature = hmac.new(key.encode(), jwt.encode(), hashlib.sha384).digest()
        newSig = base64.urlsafe_b64encode(signature).decode("UTF-8").strip("=")
        return jwt + "." + newSig
    elif jwtJson[HEADER]["alg"] == "HS512":
        jwt = encodeJwt(jwtJson)
        signature = hmac.new(key.encode(), jwt.encode(), hashlib.sha512).digest()
        newSig = base64.urlsafe_b64encode(signature).decode("UTF-8").strip("=")
        return jwt + "." + newSig

    raise UnknownAlg("Unknown alg " + jwtJson[HEADER]["alg"] + "send an issue please.")

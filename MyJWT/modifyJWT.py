import base64
import hashlib
import hmac

from MyJWT.utils import encodeJwt


def addpayload(jwtJson, payload):
    for payloadKey in payload.keys():
        jwtJson["payload"][payloadKey] = payload[payloadKey]
    return jwtJson


def addheader(jwtJson, header):
    for headerKey in header.keys():
        jwtJson["header"][headerKey] = header[headerKey]
    return jwtJson


def changeAlg(jwtJson, algo):
    jwtJson["header"]["alg"] = algo
    return jwtJson


def changePayload(jwtJson, payload):
    jwtJson["payload"] = payload
    return jwtJson


def signature(jwtJson, key):
    if jwtJson["header"]["alg"] == "HS256":
        jwt = encodeJwt(jwtJson)
        signature = hmac.new(key.encode(), jwt.encode(), hashlib.sha256).digest()
        newSig = base64.urlsafe_b64encode(signature).decode('UTF-8').strip("=")
        return jwt + "." + newSig

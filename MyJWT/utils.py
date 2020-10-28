import base64
import json


def jwtToJson(jwt):
    jwtSplit = jwt.split('.')
    header = jwtSplit[0]
    payload = jwtSplit[1]
    signature = jwtSplit[2]
    headerJson = encodedToJson(header)
    payloadJson = encodedToJson(payload)
    return {"header": headerJson, "payload": payloadJson, "signature": signature}


def encodedToJson(encodedString):
    decode = base64.b64decode(encodedString + '=' * (-len(encodedString) % 4))
    return json.loads(decode)


def encodeJwt(jwtJson):
    headerEncoded = base64.urlsafe_b64encode(
        json.dumps(jwtJson["header"], separators=(',', ':')).encode('UTF-8')).decode('UTF-8').strip('=')
    payloadEncoded = base64.urlsafe_b64encode(
        json.dumps(jwtJson["payload"], separators=(',', ':')).encode('UTF-8')).decode('UTF-8').strip('=')
    return headerEncoded + "." + payloadEncoded

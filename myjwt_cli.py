import json
import sys
from json import JSONDecodeError

import click
from os import path

from click import pass_context, Path, File

from MyJWT.modifyJWT import changePayload, addheader, changeAlg, signature, addpayload
from MyJWT.utils import jwtToJson, encodeJwt, HEADER, isValidJwt, SIGNATURE
from MyJWT.variables import NOT_VALID_JWT, CHECK_DOCS, NOT_CRAKED, CRACKED, VALID_PAYLOAD, VALID_HEADER, \
    VALID_PAYLOAD_JSON, NEW_JWT, INVALID_SIGNATURE, VALID_SIGNATURE
from MyJWT.vulnerabilities import injectSqlKid, bruteforceDict, printDecoded, confusionRsaHmac

VERSION = "1.0.0"


@click.command()
@click.version_option(VERSION)
@click.argument('jwt')
# modify your jwt
@click.option("--full-payload", help="New payload for your jwt.Json format Required")
@click.option("--add-header", "-h",
              help="Add a new key, value to your jwt header, if key is present old value will be replaced.Format: key=value",
              multiple=True)
@click.option("--add-payload", "-p",
              help="Add a new key, value to your jwt payload, if key is present old value will be replaced.Format: key=value",
              multiple=True)
# signature
@click.option("--sign", help="Sign Your jwt with key given")
@click.option("--verify", help="verify your key")
# vulnerabilities
@click.option("--none-vulnerability", '-none', is_flag=True, help="Check None Alg vulnerability")
@click.option("--hmac", type=click.Path(exists=True), help="Check RS/HMAC Alg vulnerability")
@click.option("--bruteforce", type=click.Path(exists=True), help="Bruteforce to guess th secret used to sign the token")
@click.option("--kid", help="Kid Injection sql")
# print
@click.option("--print", is_flag=True, help="Print Decoded JWT")
def myjwt_cli(jwt, full_payload, add_header, add_payload, sign, verify, none_vulnerability, hmac, bruteforce, kid,
              print):
    if not isValidJwt(jwt):
        sys.exit(NOT_VALID_JWT)
    if bruteforce:
        jwtJson = jwtToJson(jwt)
        if "HS" not in jwtJson[HEADER]["alg"]:
            sys.exit(CHECK_DOCS)
        key = bruteforceDict(jwt, bruteforce)
        if key == "":
            sys.exit(NOT_CRAKED)
        else:
            click.echo(CRACKED + key)
            if not add_header and not add_payload and not full_payload:
                sys.exit()

    if add_payload:
        payloadDict = dict()
        for payload in add_payload:
            newStr = payload.split("=")
            if len(newStr) != 2:
                sys.exit(VALID_PAYLOAD)
            payloadDict[newStr[0]] = newStr[1]
        jwtJson = addpayload(jwtToJson(jwt), payloadDict)
        jwt = encodeJwt(jwtJson) + "." + jwtJson[SIGNATURE]

    if add_header:
        headerDict = dict()
        for header in add_header:
            newStr = header.split("=")
            if len(newStr) != 2:
                sys.exit(VALID_HEADER)
            headerDict[newStr[0]] = newStr[1]
        jwtJson = addheader(jwtToJson(jwt), headerDict)
        jwt = encodeJwt(jwtJson) + "." + jwtJson[SIGNATURE]

    if full_payload:
        click.echo(full_payload)
        try:
            jwtJson = changePayload(jwtToJson(jwt), json.loads(full_payload))
            jwt = encodeJwt(jwtJson) + "." + jwtJson[SIGNATURE]
        except JSONDecodeError:
            sys.exit(VALID_PAYLOAD_JSON)

    if kid:
        jwt = injectSqlKid(jwt, kid)
        if not sign:
            click.echo(NEW_JWT + jwt)
            sys.exit()
    if hmac:
        jwt = confusionRsaHmac(jwt, hmac)
        click.echo(NEW_JWT + jwt)
        sys.exit()

    if none_vulnerability:
        jwtJson = changeAlg(jwtToJson(jwt), "none")
        jwt = encodeJwt(jwtJson) + "."
        click.echo(NEW_JWT + jwt)
        sys.exit()
    if sign:
        jwtJson = jwtToJson(jwt)
        if "HS" not in jwtJson[HEADER]["alg"]:
            sys.exit(CHECK_DOCS)
        jwt = signature(jwtJson, sign)
        click.echo(NEW_JWT + jwt)
        sys.exit()
    if verify:
        jwtJson = jwtToJson(jwt)
        if "HS" not in jwtJson[HEADER]["alg"]:
            sys.exit(CHECK_DOCS)
        newJwt = signature(jwtJson, verify)
        click.echo(VALID_SIGNATURE if newJwt.split('.')[2] == jwt.split('.')[2] else INVALID_SIGNATURE)
        sys.exit()
    if print:
        printDecoded(jwt)
        sys.exit()
    click.echo(NEW_JWT + jwt)
    sys.exit()


if __name__ == '__main__':
    myjwt_cli()

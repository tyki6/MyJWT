# type: ignore
"""User interface file"""

import re
from typing import Dict

import click
import questionary

from myjwt.modify_jwt import signature
from myjwt.utils import HEADER, PAYLOAD, SIGNATURE, copy_to_clipboard, encode_jwt, jwt_to_json
from myjwt.variables import (
    CHECK_DOCS,
    CRACKED,
    INVALID_SIGNATURE,
    MAIN_SUMMARY_CHOICES,
    MAIN_SUMMARY_CHOICES_BRUTE_FORCE,
    MAIN_SUMMARY_CHOICES_JKU,
    MAIN_SUMMARY_CHOICES_KID,
    MAIN_SUMMARY_CHOICES_MODIFY,
    MAIN_SUMMARY_CHOICES_NONE_ALG,
    MAIN_SUMMARY_CHOICES_QUIT,
    MAIN_SUMMARY_CHOICES_RSA_CONFUSION,
    MAIN_SUMMARY_CHOICES_SIGN,
    MAIN_SUMMARY_CHOICES_VERIFY,
    MAIN_SUMMARY_CHOICES_X5U,
    MAIN_SUMMARY_PROMPT_INJECTION,
    MAIN_SUMMARY_PROMPT_JWKS,
    MAIN_SUMMARY_PROMPT_KEY,
    MAIN_SUMMARY_PROMPT_PEM,
    MAIN_SUMMARY_PROMPT_WORDLIST,
    MAIN_SUMMARY_QUESTION,
    MODIFY_SUMMARY_CHOICES_ADD_HEADER,
    MODIFY_SUMMARY_CHOICES_ADD_PAYLOAD,
    MODIFY_SUMMARY_CHOICES_RETURN,
    MODIFY_SUMMARY_PROMPT_KEY,
    MODIFY_SUMMARY_PROMPT_VALUE,
    MODIFY_SUMMARY_QUESTION,
    NEW_JWT,
    NOT_CRAKED,
    SEPARATOR_HEADER,
    SEPARATOR_PAYLOAD,
    VALID_SIGNATURE,
    custom_style_fancy,
)
from myjwt.vulnerabilities import (
    bruteforce_wordlist,
    confusion_rsa_hmac,
    inject_sql_kid,
    jku_vulnerability,
    none_vulnerability,
    print_decoded,
)


def user_interface(jwt: str) -> None:
    """
    User interface for myjwt.
    Print decoded jwt then list choices of vulnerabilities.

    Parameters
    ----------
    jwt: Your jwt
    """
    click.echo("")
    click.echo("Your jwt is: \n" + jwt)
    click.echo("")
    click.echo("Your jwt decoded is:")
    click.echo("")
    print_decoded(jwt)
    click.echo("")
    jwt_json = jwt_to_json(jwt)
    summary = ""
    while summary != MAIN_SUMMARY_CHOICES_QUIT and summary is not None:
        summary = questionary.select(
            MAIN_SUMMARY_QUESTION,
            choices=MAIN_SUMMARY_CHOICES,
            style=custom_style_fancy,
        ).ask()
        if summary == MAIN_SUMMARY_CHOICES_MODIFY:
            jwt_json = user_modify_jwt(jwt_json)
        elif summary == MAIN_SUMMARY_CHOICES_NONE_ALG:
            user_none_vulnerability(jwt_json)
            summary = MAIN_SUMMARY_CHOICES_QUIT
        elif summary == MAIN_SUMMARY_CHOICES_RSA_CONFUSION:
            hmac = click.prompt(
                MAIN_SUMMARY_PROMPT_PEM,
                type=click.Path(exists=True),
            )
            user_confusion_rsa_hmac(jwt_json, hmac)
            summary = MAIN_SUMMARY_CHOICES_QUIT
        elif summary == MAIN_SUMMARY_CHOICES_BRUTE_FORCE:
            wordlist = click.prompt(
                MAIN_SUMMARY_PROMPT_WORDLIST,
                type=click.Path(exists=True),
            )
            user_bruteforce_wordlist(jwt_json, wordlist)
            summary = MAIN_SUMMARY_CHOICES_QUIT
        elif summary == MAIN_SUMMARY_CHOICES_SIGN:
            key = click.prompt(MAIN_SUMMARY_PROMPT_KEY, type=str)
            user_sign_jwt(jwt_json, key)
            summary = ""
        elif summary == MAIN_SUMMARY_CHOICES_VERIFY:
            key = click.prompt(MAIN_SUMMARY_PROMPT_KEY, type=str)
            user_verify_key(jwt_json, key)
            summary = MAIN_SUMMARY_CHOICES_QUIT
        elif summary == MAIN_SUMMARY_CHOICES_KID:
            injection = click.prompt(MAIN_SUMMARY_PROMPT_INJECTION, type=str)
            new_jwt = user_kid_injection(jwt_json, injection)
            jwt_json = jwt_to_json(new_jwt)
            click.echo(NEW_JWT + new_jwt)
            copy_to_clipboard(new_jwt)
            summary = MAIN_SUMMARY_CHOICES_QUIT
        elif summary == MAIN_SUMMARY_CHOICES_JKU:
            url = click.prompt(MAIN_SUMMARY_PROMPT_JWKS, type=str)
            user_jku_by_pass(jwt_json, url)
            summary = MAIN_SUMMARY_CHOICES_QUIT
        elif summary == MAIN_SUMMARY_CHOICES_X5U:
            url = click.prompt(MAIN_SUMMARY_PROMPT_JWKS, type=str)
            user_x5u_by_pass(jwt_json, url)
            summary = MAIN_SUMMARY_CHOICES_QUIT


def user_modify_jwt(jwt_json: Dict) -> Dict:
    """
    Print for modify interface

    Parameters
    ----------
    jwt_json: Dict
        your jwt json (use encode_to_json.Check Doc).

    Returns
    -------
    Dict
        jwt Dict
    """
    item = ""
    while item != MODIFY_SUMMARY_CHOICES_RETURN and item is not None:
        header_list = []
        for key in jwt_json[HEADER].keys():
            header_list.append(
                str(key) + " = " + (str(jwt_json[HEADER][key]) if jwt_json[HEADER][key] is not None else "null"),
            )

        payload_list = []
        for key in jwt_json[PAYLOAD].keys():
            payload_list.append(
                str(key) + " = " + (str(jwt_json[PAYLOAD][key]) if jwt_json[PAYLOAD][key] is not None else "null"),
            )
        item = questionary.select(
            MODIFY_SUMMARY_QUESTION,
            choices=[SEPARATOR_HEADER]
            + header_list
            + [MODIFY_SUMMARY_CHOICES_ADD_HEADER]
            + [SEPARATOR_PAYLOAD]
            + payload_list
            + [
                MODIFY_SUMMARY_CHOICES_ADD_PAYLOAD,
                MODIFY_SUMMARY_CHOICES_RETURN,
            ],
            style=custom_style_fancy,
        ).ask()
        if item in header_list:
            m = re.match("(.*) = .*", item)
            key = m.groups()[0]  # type: ignore
            value = click.prompt(MODIFY_SUMMARY_PROMPT_VALUE, type=str)
            jwt_json[HEADER][key] = value
        elif item in payload_list:
            m = re.match("(.*) = .*", item)
            key = m.groups()[0]  # type: ignore
            value = click.prompt(MODIFY_SUMMARY_PROMPT_VALUE, type=str)
            jwt_json[PAYLOAD][key] = value
        elif item == MODIFY_SUMMARY_CHOICES_ADD_HEADER:
            key = click.prompt(MODIFY_SUMMARY_PROMPT_KEY, type=str)
            value = click.prompt(MODIFY_SUMMARY_PROMPT_VALUE, type=str)
            jwt_json[HEADER][key] = value
        elif item == MODIFY_SUMMARY_CHOICES_ADD_PAYLOAD:
            key = click.prompt(MODIFY_SUMMARY_PROMPT_KEY, type=str)
            value = click.prompt(MODIFY_SUMMARY_PROMPT_VALUE, type=str)
            jwt_json[PAYLOAD][key] = value
    return jwt_json


def user_none_vulnerability(jwt_json: Dict) -> None:
    """
    Print for none vulnerability.

    Parameters
    ----------
    jwt_json: Dict
        your jwt json (use encode_to_json.Check Doc).
    """
    jwt = none_vulnerability(encode_jwt(jwt_json) + "." + jwt_json[SIGNATURE])
    copy_to_clipboard(jwt)
    click.echo(NEW_JWT + jwt)


def user_confusion_rsa_hmac(jwt_json: Dict, hmac: str) -> None:
    """
    Print for rsa/hmac confusion.

    Parameters
    ----------
    jwt_json: Dict
        your jwt json (use encode_to_json.Check Doc).
    hmac: str
        path of your public key.
    """
    jwt = confusion_rsa_hmac(
        encode_jwt(jwt_json) + "." + jwt_json[SIGNATURE],
        hmac,
    )
    copy_to_clipboard(jwt)
    click.echo(NEW_JWT + jwt)


def user_bruteforce_wordlist(jwt_json: Dict, wordlist: str) -> None:
    """
    Print For bruteforce method.

    Parameters
    ----------
    jwt_json: Dict
        your jwt json (use encode_to_json.Check Doc).
    wordlist: str
        path of your wordlist
    """
    if "HS" not in jwt_json[HEADER]["alg"]:
        click.echo(CHECK_DOCS)
    key = bruteforce_wordlist(
        encode_jwt(jwt_json) + "." + jwt_json[SIGNATURE],
        wordlist,
    )
    if key == "":
        click.echo(NOT_CRAKED)
    else:
        copy_to_clipboard(key)
        click.echo(CRACKED + key)


def user_verify_key(jwt_json: Dict, key: str) -> None:
    """
     Print For verify method.

    Parameters
    ----------
    jwt_json: Dict
        your jwt json (use encode_to_json.Check Doc).
    key: str
        your key
    """
    if "HS" not in jwt_json[HEADER]["alg"]:
        click.echo(CHECK_DOCS)
    new_jwt = signature(jwt_json, key)
    click.echo(
        VALID_SIGNATURE if new_jwt.split(".")[2] == jwt_json[SIGNATURE] else INVALID_SIGNATURE,
    )


def user_sign_jwt(jwt_json: Dict, key: str) -> None:
    """
     Print For sign method.

    Parameters
    ----------
    jwt_json: Dict
        your jwt json (use encode_to_json.Check Doc).
    key: str
        your key
    """
    if "HS" not in jwt_json[HEADER]["alg"]:
        click.echo(CHECK_DOCS)
    jwt = signature(jwt_json, key)
    copy_to_clipboard(jwt)
    click.echo(NEW_JWT + jwt)


def user_kid_injection(jwt_json: Dict, injection: str) -> str:
    """
    Print for kid injection method.

    Parameters
    ----------
    jwt_json: Dict
        your jwt json (use encode_to_json.Check Doc).
    injection: str
        your injection

    Returns
    ----------
    str
        Your jwt.
    """
    return inject_sql_kid(
        jwt=encode_jwt(jwt_json) + "." + jwt_json[SIGNATURE],
        injection=injection,
    )


def user_jku_by_pass(jwt_json: Dict, url: str) -> None:
    """
    Print for jku bypass method.

    Parameters
    ----------
    jwt_json: Dict
        your jwt json (use encode_to_json.Check Doc).
    url: str
        your url
    """
    new_jwt = jku_vulnerability(
        jwt=encode_jwt(jwt_json) + "." + jwt_json[SIGNATURE],
        url=url,
    )
    click.echo(NEW_JWT + new_jwt)
    copy_to_clipboard(new_jwt)
    click.echo(
        f"Please run python -m http.server --bind {url} .Before send your jwt",
    )


def user_x5u_by_pass(jwt_json: Dict, url: str) -> None:
    """
    Print for x5u bypass method.

    Parameters
    ----------
    jwt_json: Dict
        your jwt json (use encode_to_json.Check Doc).
    url: str
        your url
    """
    new_jwt = jku_vulnerability(
        jwt=encode_jwt(jwt_json) + "." + jwt_json[SIGNATURE],
        url=url,
    )
    click.echo(NEW_JWT + new_jwt)
    copy_to_clipboard(new_jwt)
    click.echo(
        f"Please run python -m http.server --bind {url} .Before send your jwt",
    )

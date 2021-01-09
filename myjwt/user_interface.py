"""User interface file"""
import re
from typing import Dict

import click
import questionary

from myjwt.modify_jwt import signature
from myjwt.utils import copy_to_clipboard
from myjwt.utils import encode_jwt
from myjwt.utils import HEADER
from myjwt.utils import jwt_to_json
from myjwt.utils import PAYLOAD
from myjwt.utils import SIGNATURE
from myjwt.variables import CHECK_DOCS
from myjwt.variables import CRACKED
from myjwt.variables import custom_style_fancy
from myjwt.variables import INVALID_SIGNATURE
from myjwt.variables import MAIN_SUMMARY_CHOICES
from myjwt.variables import MAIN_SUMMARY_CHOICES_BRUTE_FORCE
from myjwt.variables import MAIN_SUMMARY_CHOICES_JKU
from myjwt.variables import MAIN_SUMMARY_CHOICES_KID
from myjwt.variables import MAIN_SUMMARY_CHOICES_MODIFY
from myjwt.variables import MAIN_SUMMARY_CHOICES_NONE_ALG
from myjwt.variables import MAIN_SUMMARY_CHOICES_QUIT
from myjwt.variables import MAIN_SUMMARY_CHOICES_RSA_CONFUSION
from myjwt.variables import MAIN_SUMMARY_CHOICES_SIGN
from myjwt.variables import MAIN_SUMMARY_CHOICES_VERIFY
from myjwt.variables import MAIN_SUMMARY_CHOICES_X5U
from myjwt.variables import MAIN_SUMMARY_PROMPT_INJECTION
from myjwt.variables import MAIN_SUMMARY_PROMPT_JWKS
from myjwt.variables import MAIN_SUMMARY_PROMPT_KEY
from myjwt.variables import MAIN_SUMMARY_PROMPT_PEM
from myjwt.variables import MAIN_SUMMARY_PROMPT_WORDLIST
from myjwt.variables import MAIN_SUMMARY_QUESTION
from myjwt.variables import MODIFY_SUMMARY_CHOICES_ADD_HEADER
from myjwt.variables import MODIFY_SUMMARY_CHOICES_ADD_PAYLOAD
from myjwt.variables import MODIFY_SUMMARY_CHOICES_RETURN
from myjwt.variables import MODIFY_SUMMARY_PROMPT_KEY
from myjwt.variables import MODIFY_SUMMARY_PROMPT_VALUE
from myjwt.variables import MODIFY_SUMMARY_QUESTION
from myjwt.variables import NEW_JWT
from myjwt.variables import NOT_CRAKED
from myjwt.variables import SEPARATOR_HEADER
from myjwt.variables import SEPARATOR_PAYLOAD
from myjwt.variables import VALID_SIGNATURE
from myjwt.vulnerabilities import bruteforce_wordlist
from myjwt.vulnerabilities import confusion_rsa_hmac
from myjwt.vulnerabilities import inject_sql_kid
from myjwt.vulnerabilities import jku_vulnerability
from myjwt.vulnerabilities import none_vulnerability
from myjwt.vulnerabilities import print_decoded


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
        header_list = list()
        for key in jwt_json[HEADER].keys():
            header_list.append(
                str(key)
                + " = "
                + (
                    str(jwt_json[HEADER][key])
                    if jwt_json[HEADER][key] is not None
                    else "null"
                ),
            )

        payload_list = list()
        for key in jwt_json[PAYLOAD].keys():
            payload_list.append(
                str(key)
                + " = "
                + (
                    str(jwt_json[PAYLOAD][key])
                    if jwt_json[PAYLOAD][key] is not None
                    else "null"
                ),
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
        VALID_SIGNATURE
        if new_jwt.split(".")[2] == jwt_json[SIGNATURE]
        else INVALID_SIGNATURE,
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

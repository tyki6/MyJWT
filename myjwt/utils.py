"""
Utils package
"""

import base64
import json
from typing import Any, cast

import click
import pyperclip
from OpenSSL import crypto

from myjwt.Exception import InvalidJWT, InvalidJwtJson
from myjwt.variables import CLIPBOARD

HEADER = "header"
PAYLOAD = "payload"
SIGNATURE = "signature"


def jwt_to_json(jwt: str) -> dict[str, Any]:
    """
    Transform your jwt's string to a dict.

    Parameters
    ----------
    jwt: str
        your jwt.

    Returns
    -------
    Dict
        a dict with key: header with value base64_decode(header), payload with value base64_decode(payload), and signature with value signature.
    """
    if not is_valid_jwt(jwt):
        raise InvalidJWT("Invalid JWT format")

    jwt_split = jwt.split(".")
    header = jwt_split[0]
    payload = jwt_split[1]
    signature = jwt_split[2]
    header_json = encoded_to_json(header)
    payload_json = encoded_to_json(payload)
    return {HEADER: header_json, PAYLOAD: payload_json, SIGNATURE: signature}


def encoded_to_json(encoded_string: str) -> dict[str, Any]:
    """
    Transform your encoded string to dict.

    Parameters
    ----------
    encoded_string: str
        your string base64 encoded.

    Returns
    -------
    Dict
        your string cast to a dict.
    """
    decode = base64.b64decode(
        encoded_string + "=" * (-len(encoded_string) % 4),
    )
    return cast(dict[str, Any], json.loads(decode))


def encode_jwt(jwt_json: dict[str, Any]) -> str:
    """
    Transform your jwt dict to a jwt string without "." + signature.

    Parameters
    ----------
    jwt_json: Dict
        dict with key header and payload.

    Returns
    -------
    str
        jwt string encoded
    """
    if not is_valid_jwt_json(jwt_json):
        raise InvalidJwtJson("Invalid JWT json format")
    header_encoded = (
        base64.urlsafe_b64encode(
            json.dumps(jwt_json[HEADER], separators=(",", ":")).encode(
                "UTF-8",
            ),
        )
        .decode("UTF-8")
        .strip("=")
    )
    payload_encoded = (
        base64.urlsafe_b64encode(
            json.dumps(jwt_json[PAYLOAD], separators=(",", ":")).encode(
                "UTF-8",
            ),
        )
        .decode("UTF-8")
        .strip("=")
    )
    return header_encoded + "." + payload_encoded


def is_valid_jwt(jwt: str) -> bool:
    """
    Check your jwt.

    Parameters
    ----------
    jwt: str
        jwt string.

    Returns
    -------
    bool
        True if jwt is valid , False else
    """
    return len(jwt.split(".")) == 3


def is_valid_jwt_json(jwt_json: dict[str, Any]) -> bool:
    """
    Check your jwt dict.

    Parameters
    ----------
    jwt_json: Dict
        your jwt dict.

    Returns
    -------
    bool
        True if jwt_json is valid , False else
    """
    return (
        HEADER in jwt_json
        and PAYLOAD in jwt_json
        and SIGNATURE in jwt_json
        and type(jwt_json[HEADER]) is dict
        and type(jwt_json[PAYLOAD]) is dict
        and type(jwt_json[SIGNATURE]) is str
    )


def create_crt() -> tuple[str, str]:
    """
    Create crt + pem

    Returns
    -------
    str, str
        crt + pem
    """
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "AU"
    cert.get_subject().ST = "Victoria"
    cert.get_subject().L = "Melbourne"
    cert.get_subject().O = "myjwt"
    cert.get_subject().CN = "hacker"
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, "sha256")
    crt = "selfsigned.crt"
    pem = "private.pem"
    with open("selfsigned.crt", "w") as f:
        f.write(
            crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"),
        )
        f.close()
    with open("private.pem", "w") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))
        f.close()
    return crt, pem


def copy_to_clipboard(jwt: str) -> None:
    """
    Copy txt to clipboard.

    Parameters
    ----------
    jwt: str
        your jwt.
    """
    try:
        pyperclip.copy(jwt)
        click.echo(CLIPBOARD)
    except pyperclip.PyperclipException:
        click.echo(
            """Pyperclip could not find a copy/paste mechanism for your system.
        For more information, please visit https://pyperclip.readthedocs.io/en/latest/index.html#not-implemented-error""",
        )

